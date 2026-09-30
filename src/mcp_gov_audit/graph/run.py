"""Run the audit graph, including review resume (§13.5, §13.6)."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.errors import GraphInterrupt
from langgraph.types import Command
from mcp import ClientSession

from mcp_gov_audit.classification.cache import ClassificationCache
from mcp_gov_audit.config import AuditConfig, LoadedConfig, load_policy, load_probe_fixtures
from mcp_gov_audit.context import AuditContext
from mcp_gov_audit.graph.builder import build_graph
from mcp_gov_audit.graph.state import AuditState
from mcp_gov_audit.mcp_client.session import open_session
from mcp_gov_audit.models import FieldClassifier, Finding, ProbePlanner, ReviewDecision
from mcp_gov_audit.reporting.json_report import run_exit_code


@dataclass(frozen=True)
class ProbeRun:
    run_dir: Path
    state: AuditState
    findings: list[Finding]
    exit_code: int
    paused: bool = False


class ReviewNotPaused(Exception):
    """`mcpaudit review` was pointed at a run that is not waiting for decisions."""


async def run_until_normalize(
    loaded: LoadedConfig,
    *,
    output_root: Path | None = None,
    run_dir: Path | None = None,
    static_only: bool = False,
    no_llm: bool = False,
    no_cache: bool = False,
    classifier: FieldClassifier | None = None,
    planner: ProbePlanner | None = None,
) -> ProbeRun:
    """Execute the audit graph. `--no-llm` forces deterministic classification."""
    if no_llm:
        loaded = loaded.model_copy(
            update={
                "audit": loaded.audit.model_copy(
                    update={
                        "llm": loaded.audit.llm.model_copy(update={"enabled": False}),
                    }
                )
            }
        )
        classifier = None
        planner = None
    clock = make_clock(loaded.audit.run.clock_override)
    directory = run_dir or (output_root or Path(loaded.audit.output.dir)) / _run_id(clock)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "run_config.json").write_text(
        loaded.audit.without_secrets().model_dump_json(indent=2),
        encoding="utf-8",
    )
    from mcp_gov_audit.cli import configure_logging

    configure_logging(directory / "run.log")
    state, paused = await _execute(
        loaded,
        directory,
        clock,
        {"run_id": directory.name, "started_at": _iso(clock())},
        static_only=static_only,
        no_cache=no_cache,
        classifier=classifier,
        planner=planner,
    )
    return _finish(loaded, directory, state, paused=paused)


async def load_pending_findings(run_dir: Path) -> list[dict[str, Any]]:
    """Return the interrupt payload for a paused run."""
    if not (run_dir / "run_config.json").is_file():
        raise ReviewNotPaused(f"no run config in {run_dir}")
    async with AsyncSqliteSaver.from_conn_string(str(_checkpoint(run_dir))) as saver:
        graph = build_graph(checkpointer=saver, review_enabled=True)
        snapshot = await graph.aget_state(_thread(run_dir.name))
    if not snapshot.interrupts:
        raise ReviewNotPaused(f"{run_dir.name} is not waiting for review")
    value = snapshot.interrupts[0].value
    if not isinstance(value, dict):
        raise ReviewNotPaused(f"{run_dir.name} has no pending findings")
    findings = value.get("findings", [])
    if not isinstance(findings, list):
        raise ReviewNotPaused(f"{run_dir.name} has no pending findings")
    return [item for item in findings if isinstance(item, dict)]


async def resume_review(run_dir: Path, decisions: list[ReviewDecision]) -> ProbeRun:
    """Resume a paused run and render its report."""
    loaded = _loaded_from_run(run_dir)
    clock = make_clock(loaded.audit.run.clock_override)
    payload = [item.model_dump(mode="json") for item in decisions]
    async with AsyncSqliteSaver.from_conn_string(str(_checkpoint(run_dir))) as saver:
        graph = build_graph(
            scan_after_rules=loaded.audit.static_scan.enabled,
            review_enabled=True,
            checkpointer=saver,
        )
        context = _context(
            loaded,
            run_dir,
            clock,
            session=None,
            classifier=None,
            planner=None,
            no_cache=False,
        )
        state, paused = await _invoke(
            graph,
            Command(resume=payload),
            context,
            _thread(run_dir.name),
        )
    return _finish(loaded, run_dir, state, paused=paused)


async def _execute(
    loaded: LoadedConfig,
    directory: Path,
    clock: Callable[[], datetime],
    payload: dict[str, str],
    *,
    static_only: bool,
    no_cache: bool,
    classifier: FieldClassifier | None,
    planner: ProbePlanner | None,
) -> tuple[AuditState, bool]:
    async with AsyncSqliteSaver.from_conn_string(str(_checkpoint(directory))) as saver:
        graph = build_graph(
            static_only=static_only,
            scan_after_rules=loaded.audit.static_scan.enabled and not static_only,
            review_enabled=loaded.audit.review.enabled,
            checkpointer=saver,
        )
        if static_only:
            context = _context(
                loaded,
                directory,
                clock,
                session=None,
                classifier=classifier,
                planner=planner,
                no_cache=no_cache,
            )
            return await _invoke(graph, payload, context, _thread(directory.name))
        async with open_session(loaded.audit.target) as session:
            context = _context(
                loaded,
                directory,
                clock,
                session=session,
                classifier=classifier,
                planner=planner,
                no_cache=no_cache,
            )
            return await _invoke(graph, payload, context, _thread(directory.name))


async def _invoke(
    graph: Any,
    payload: dict[str, str] | Command[Any],
    context: AuditContext,
    config: RunnableConfig,
) -> tuple[AuditState, bool]:
    with contextlib.suppress(GraphInterrupt):
        await graph.ainvoke(payload, config, context=context, durability="sync")
    snapshot = await graph.aget_state(config)
    return cast(AuditState, snapshot.values), bool(snapshot.next)


def _finish(loaded: LoadedConfig, directory: Path, state: AuditState, *, paused: bool) -> ProbeRun:
    findings = [
        item if isinstance(item, Finding) else Finding.model_validate(item)
        for item in state.get("findings", [])
    ]
    if paused:
        return ProbeRun(
            run_dir=directory,
            state=state,
            findings=findings,
            exit_code=4,
            paused=True,
        )
    return ProbeRun(
        run_dir=directory,
        state=state,
        findings=findings,
        exit_code=run_exit_code(
            findings,
            fail_on=loaded.audit.run.fail_on,
            fail_on_llm_assisted=loaded.audit.run.fail_on_llm_assisted,
        ),
    )


def _loaded_from_run(run_dir: Path) -> LoadedConfig:
    raw = (run_dir / "run_config.json").read_text(encoding="utf-8")
    audit = AuditConfig.model_validate_json(raw)
    return LoadedConfig(
        audit=audit,
        policy=load_policy(Path(audit.policy_file)),
        probe_fixtures=load_probe_fixtures(Path(audit.probing.fixtures_file)),
    )


def _checkpoint(run_dir: Path) -> Path:
    return run_dir.parent / ".checkpoints.sqlite"


def _thread(run_id: str) -> RunnableConfig:
    return {"configurable": {"thread_id": run_id}}


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_clock(clock_override: str | None) -> Callable[[], datetime]:
    if clock_override is None:
        return lambda: datetime.now(UTC)
    fixed = datetime.fromisoformat(clock_override.replace("Z", "+00:00"))
    return lambda: fixed


def _run_id(clock: Callable[[], datetime]) -> str:
    stamp = clock().astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{secrets.token_hex(3)}"


def _context(
    loaded: LoadedConfig,
    run_dir: Path,
    clock: Callable[[], datetime],
    *,
    session: ClientSession | None,
    classifier: FieldClassifier | None,
    planner: ProbePlanner | None,
    no_cache: bool,
) -> AuditContext:
    digest = hashlib.sha256(loaded.policy.model_dump_json().encode()).hexdigest()
    return AuditContext(
        config=loaded.audit,
        policy=loaded.policy,
        policy_sha256=digest,
        session=session,
        classifier=classifier,
        planner=planner,
        cache=ClassificationCache(Path(loaded.audit.llm.cache_dir), read=not no_cache),
        semaphore=asyncio.Semaphore(loaded.audit.run.max_concurrency),
        clock=clock,
        run_dir=run_dir,
        fixtures=loaded.probe_fixtures,
    )
