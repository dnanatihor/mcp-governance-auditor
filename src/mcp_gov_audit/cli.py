"""Typer CLI (§14)."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Annotated, Any, Literal, cast

import structlog
from rich.console import Console
from rich.table import Table
from typer import Argument, Exit, Option, Typer, echo, prompt

from mcp_gov_audit.config import ConfigError, LoadedConfig, load_config
from mcp_gov_audit.mcp_client.session import TargetUnreachable
from mcp_gov_audit.models import ReviewDecision, Severity
from mcp_gov_audit.rules import REGISTRY

app = Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Audit an MCP server for epistemic-layer governance.",
)


def configure_logging(run_log: Path | None = None) -> None:
    """Write JSON logs to stderr and, when a run directory exists, to `run.log`."""
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]
    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
    )

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.INFO)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    root.addHandler(stderr_handler)

    if run_log is not None:
        run_log.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(run_log, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)


@app.callback()
def _callback() -> None:
    """Audit an MCP server for epistemic-layer governance."""
    configure_logging()


@app.command()
def introspect(
    config: Annotated[Path, Option("--config", "-c", help="Path to audit.yaml")],
    output_dir: Annotated[
        Path | None,
        Option("--output-dir", help="Directory for manifest.json"),
    ] = None,
) -> None:
    """Connect, list tools, triage, evaluate MAN-* rules, write manifest.json, print a table."""
    loaded = _load_or_exit(config)
    from mcp_gov_audit.introspect import introspect_server

    try:
        tools, findings = asyncio.run(introspect_server(loaded))
    except TargetUnreachable as exc:
        echo(str(exc), err=True)
        raise Exit(code=3) from exc
    except Exit:
        raise
    except Exception as exc:
        echo(str(exc), err=True)
        raise Exit(code=2) from exc
    directory = output_dir or Path(loaded.audit.output.dir)
    directory.mkdir(parents=True, exist_ok=True)
    manifest = directory / "manifest.json"
    manifest.write_text(
        json.dumps(
            [tool.model_dump(mode="json") for tool in tools],
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    table = Table(title="Tools")
    table.add_column("Name")
    table.add_column("Decision")
    table.add_column("Risk")
    table.add_column("Inference risk")
    for tool in tools:
        table.add_row(
            tool.name,
            tool.probe_decision or "probe",
            f"{tool.risk_score:.2f}",
            "yes" if tool.inference_risk else "no",
        )
    Console().print(table)
    for finding in findings:
        echo(f"FINDING {finding.rule_id} {finding.tool_name}")
    echo(str(manifest))


@app.command()
def run(
    config: Annotated[Path, Option("--config", "-c", help="Path to audit.yaml")],
    no_llm: Annotated[
        bool,
        Option("--no-llm", help="Disable the classifier and planner for this run"),
    ] = False,
    no_cache: Annotated[
        bool,
        Option("--no-cache", help="Skip classification-cache reads; still write new verdicts"),
    ] = False,
    static_only: Annotated[
        bool,
        Option("--static-only", help="Run only the static scan"),
    ] = False,
    fail_on: Annotated[
        Severity | None,
        Option("--fail-on", help="Override run.fail_on for the exit code"),
    ] = None,
    output_dir: Annotated[
        Path | None,
        Option("--output-dir", help="Directory for the run output"),
    ] = None,
) -> None:
    """Run the audit graph and write the report, or pause for review."""
    loaded = _load_or_exit(config)
    if fail_on is not None:
        loaded = loaded.model_copy(
            update={
                "audit": loaded.audit.model_copy(
                    update={
                        "run": loaded.audit.run.model_copy(update={"fail_on": fail_on}),
                    }
                )
            }
        )
    structlog.get_logger().info(
        "run_start",
        no_llm=no_llm,
        no_cache=no_cache,
        static_only=static_only,
        fail_on=None if fail_on is None else fail_on.value,
    )
    from mcp_gov_audit.classification.llm import LangChainFieldClassifier, LangChainProbePlanner
    from mcp_gov_audit.graph.run import run_until_normalize

    classifier = None
    planner = None
    if not no_llm and not static_only and loaded.audit.llm.enabled:
        classifier = LangChainFieldClassifier(
            loaded.audit.llm.classifier_model,
            temperature=loaded.audit.llm.temperature,
        )
        planner = LangChainProbePlanner(
            loaded.audit.llm.planner_model,
            temperature=loaded.audit.llm.temperature,
        )
    try:
        completed = asyncio.run(
            run_until_normalize(
                loaded,
                output_root=output_dir,
                static_only=static_only,
                no_llm=no_llm,
                no_cache=no_cache,
                classifier=classifier,
                planner=planner,
            )
        )
    except TargetUnreachable as exc:
        echo(str(exc), err=True)
        raise Exit(code=3) from exc
    except Exit:
        raise
    except Exception as exc:
        echo(str(exc), err=True)
        raise Exit(code=2) from exc
    if completed.paused:
        echo(f"Run {completed.run_dir.name} is paused for human review.")
        echo(f"mcpaudit review {completed.run_dir.name} --output-dir {completed.run_dir.parent}")
        raise Exit(code=4)
    verdict = "fail" if completed.exit_code == 1 else "pass"
    echo(f"{completed.run_dir}")
    echo(f"verdict={verdict}")
    raise Exit(code=completed.exit_code)


@app.command()
def review(
    run_id: Annotated[str, Argument(help="Run id to resume")],
    output_dir: Annotated[
        Path | None,
        Option("--output-dir", help="Directory that contains the paused run"),
    ] = None,
) -> None:
    """Resume a run paused for human review."""
    parent = output_dir or Path("reports")
    run_dir = parent / run_id
    from mcp_gov_audit.graph.run import ReviewNotPaused, load_pending_findings, resume_review

    try:
        pending = asyncio.run(load_pending_findings(run_dir))
    except (ReviewNotPaused, OSError, ValueError) as exc:
        echo(str(exc), err=True)
        raise Exit(code=2) from exc
    decisions = _collect_decisions(pending)
    try:
        completed = asyncio.run(resume_review(run_dir, decisions))
    except Exception as exc:
        echo(str(exc), err=True)
        raise Exit(code=2) from exc
    if completed.paused:
        echo(f"{run_id} is still paused", err=True)
        raise Exit(code=2)
    echo(str(completed.run_dir))
    raise Exit(code=completed.exit_code)


@app.command()
def diff(
    old_run_dir: Annotated[Path, Argument(help="Earlier run directory")],
    new_run_dir: Annotated[Path, Argument(help="Later run directory")],
    json_output: Annotated[bool, Option("--json", help="Emit JSON")] = False,
    fail_on: Annotated[
        Severity | None,
        Option("--fail-on", help="Fail when a new active finding is at or above this level"),
    ] = None,
) -> None:
    """Compare finding ids from two run directories."""
    from mcp_gov_audit.reporting.diff import (
        diff_exit_code,
        fail_on_llm_assisted,
        format_diff,
        load_run_diff,
    )

    try:
        result, new_report = load_run_diff(old_run_dir, new_run_dir)
    except (OSError, ValueError) as exc:
        echo(str(exc), err=True)
        raise Exit(code=2) from exc
    level = fail_on if fail_on is not None else Severity(new_report.run.fail_on)
    code = diff_exit_code(
        result,
        fail_on=level,
        fail_on_llm_assisted=fail_on_llm_assisted(new_run_dir),
    )
    if json_output:
        echo(json.dumps(result.model_dump(mode="json"), indent=2))
    else:
        echo(format_diff(result), nl=False)
    raise Exit(code=code)


@app.command()
def rules(
    json_output: Annotated[bool, Option("--json", help="Emit JSON")] = False,
) -> None:
    """List registered rules with id, name, scope, and default severity."""
    rows = [
        {
            "id": rule.id,
            "name": rule.name,
            "scope": rule.scope,
            "default_severity": rule.default_severity.value,
        }
        for rule in REGISTRY.values()
    ]
    rows.sort(key=lambda row: row["id"])
    if json_output:
        echo(json.dumps(rows))
        return

    table = Table(title="Rules")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Scope")
    table.add_column("Default severity")
    for row in rows:
        table.add_row(row["id"], row["name"], row["scope"], row["default_severity"])
    Console().print(table)


def main() -> None:
    app()


def _collect_decisions(pending: list[dict[str, Any]]) -> list[ReviewDecision]:
    console = Console()
    decisions: list[ReviewDecision] = []
    for item in pending:
        console.print(f"[bold]{item.get('rule_id')}[/bold] {item.get('finding_id')}")
        console.print(
            f"{item.get('severity')} {item.get('tool_name')} {item.get('normalized_path')}"
        )
        console.print(str(item.get("evidence", "")))
        choice = ""
        while choice not in {"confirm", "dismiss", "downgrade"}:
            choice = prompt("Decision (confirm/dismiss/downgrade)").strip().lower()
        severity = None
        if choice == "downgrade":
            raw = ""
            while raw not in {"critical", "high", "medium", "low", "info"}:
                raw = prompt("Severity (critical/high/medium/low/info)").strip().lower()
            severity = Severity(raw)
        note = prompt("Note", default="").strip()
        decisions.append(
            ReviewDecision(
                finding_id=str(item["finding_id"]),
                decision=cast(Literal["confirm", "dismiss", "downgrade"], choice),
                severity=severity,
                note=note or None,
            )
        )
    return decisions


def _load_or_exit(path: Path) -> LoadedConfig:
    try:
        return load_config(path)
    except ConfigError as exc:
        echo(str(exc), err=True)
        raise Exit(code=2) from exc
