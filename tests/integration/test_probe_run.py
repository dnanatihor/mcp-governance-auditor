"""Fixture probe run: safety skips, failures, and masked raw capture."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from tests.helpers import ROOT
from tests.llm_stubs import StubClassifier, StubPlanner

from mcp_gov_audit.config import LoadedConfig, load_config
from mcp_gov_audit.graph.run import ProbeRun, run_until_normalize
from mcp_gov_audit.models import Finding, LLMFieldVerdict

_EMAIL = "jane.doe@example.com"


@pytest.mark.asyncio
async def test_fixture_run_skips_unsafe_tools_and_masks_raw_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    log_path = tmp_path / "calls.log"
    loaded = load_config(ROOT / "tests" / "fixtures" / "audit.fixture.yaml")
    audit = loaded.audit.model_copy(
        update={
            "target": loaded.audit.target.model_copy(
                update={
                    "command": sys.executable,
                    "env": {"FIXTURE_CALL_LOG": str(log_path)},
                }
            ),
            "run": loaded.audit.run.model_copy(update={"max_concurrency": 1}),
        }
    )
    loaded = loaded.model_copy(update={"audit": audit})
    completed = await run_until_normalize(loaded, run_dir=tmp_path / "run", no_llm=True)
    again = await run_until_normalize(loaded, run_dir=tmp_path / "run-again", no_llm=True)

    called = log_path.read_text(encoding="utf-8").splitlines()
    assert "delete_asset" not in called
    assert "list_assets" not in called

    by_status = {probe.tool_name: probe.status for probe in completed.state["probes"]}
    assert by_status["slow_lookup"] == "timeout"
    assert by_status["flaky_lookup"] == "tool_error"

    coverage = {
        (finding.rule_id, finding.tool_name)
        for finding in completed.findings
        if finding.rule_id == "COV-002"
    }
    assert coverage == {("COV-002", "slow_lookup"), ("COV-002", "flaky_lookup")}
    decisions = {
        finding.tool_name: finding.evidence
        for finding in completed.findings
        if finding.rule_id == "COV-001"
    }
    assert decisions["delete_asset"] == "skip_destructive"
    assert decisions["list_assets"] == "skip_not_allowlisted"

    raw_root = completed.run_dir / "raw"
    column_path = raw_root / "get_column_quality" / "get_column_quality#0.json"
    column = column_path.read_text(encoding="utf-8")
    assert "«email»" in column
    for path in completed.run_dir.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert _EMAIL not in text

    assert _finding_tuples(completed) == _expected_findings()
    assert _finding_ids(completed) == _finding_ids(again)
    report = json.loads((completed.run_dir / "report.json").read_text(encoding="utf-8"))
    reported = {
        (item["rule_id"], item["tool_name"], item["normalized_path"]) for item in report["findings"]
    }
    assert reported == _expected_findings()


def _finding_tuples(run: ProbeRun) -> set[tuple[str, str | None, str | None]]:
    return {(item.rule_id, item.tool_name, item.normalized_path) for item in run.findings}


def _finding_ids(run: ProbeRun) -> set[tuple[str, str | None, str | None, str]]:
    return {
        (item.rule_id, item.tool_name, item.normalized_path, item.finding_id)
        for item in run.findings
    }


@pytest.mark.asyncio
async def test_stub_classifier_matches_stubllm_and_caches_the_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    loaded = _loaded(tmp_path / "calls.log", tmp_path / "cache")
    verdict = LLMFieldVerdict(
        field_path="$.quality.score",
        layer="inferred",
        confidence=0.85,
        evidence="stub verdict",
    )
    first = StubClassifier(verdicts={"$.quality.score": verdict})
    completed = await run_until_normalize(
        loaded,
        run_dir=tmp_path / "stub",
        classifier=first,
    )
    second = StubClassifier(verdicts={"$.quality.score": verdict})
    await run_until_normalize(
        loaded,
        run_dir=tmp_path / "stub-cached",
        classifier=second,
    )
    assert _finding_tuples(completed) == _expected_file("expected_findings.stubllm.json")
    score = _one(completed, "EPI-003", "$.quality.score")
    assert score.basis == "llm_assisted"
    assert score.needs_human_review is True
    assert score.review_status == "pending"
    assert _one(completed, "EPI-002", "$.quality").basis == "deterministic"
    assert first.calls == 1
    assert second.calls == 0


@pytest.mark.asyncio
async def test_stub_planner_probes_or_skips_without_a_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    good_log = tmp_path / "good.log"
    good = _without_profile_fixture(_loaded(good_log, tmp_path / "cache-good"))
    planner = StubPlanner([{"asset_id": "tbl_orders"}])
    await run_until_normalize(good, run_dir=tmp_path / "planned", planner=planner)
    assert "get_profile_snapshot" in good_log.read_text(encoding="utf-8").splitlines()

    bad_log = tmp_path / "bad.log"
    bad = _without_profile_fixture(_loaded(bad_log, tmp_path / "cache-bad"))
    skipped = await run_until_normalize(
        bad,
        run_dir=tmp_path / "skipped",
        planner=StubPlanner([{"wrong": 1}]),
    )
    assert "get_profile_snapshot" not in bad_log.read_text(encoding="utf-8").splitlines()
    decisions = {
        finding.tool_name: finding.evidence
        for finding in skipped.findings
        if finding.rule_id == "COV-001"
    }
    assert decisions["get_profile_snapshot"] == "skip_no_input"


def _without_profile_fixture(loaded: LoadedConfig) -> LoadedConfig:
    fixtures = dict(loaded.probe_fixtures)
    del fixtures["get_profile_snapshot"]
    return loaded.model_copy(update={"probe_fixtures": fixtures})


def _loaded(log_path: Path, cache_dir: Path) -> LoadedConfig:
    loaded = load_config(ROOT / "tests" / "fixtures" / "audit.fixture.yaml")
    audit = loaded.audit.model_copy(
        update={
            "target": loaded.audit.target.model_copy(
                update={
                    "command": sys.executable,
                    "env": {"FIXTURE_CALL_LOG": str(log_path)},
                }
            ),
            "run": loaded.audit.run.model_copy(update={"max_concurrency": 1}),
            "llm": loaded.audit.llm.model_copy(update={"cache_dir": str(cache_dir)}),
        }
    )
    return loaded.model_copy(update={"audit": audit})


def _one(run: ProbeRun, rule_id: str, path: str | None) -> Finding:
    matches = [
        item for item in run.findings if item.rule_id == rule_id and item.normalized_path == path
    ]
    assert len(matches) == 1
    return matches[0]


def _expected_findings() -> set[tuple[str, str | None, str | None]]:
    return _expected_file("expected_findings.nollm.json")


def _expected_file(name: str) -> set[tuple[str, str | None, str | None]]:
    payload = json.loads((ROOT / "tests" / "fixtures" / name).read_text(encoding="utf-8"))
    return {(item["rule_id"], item["tool_name"], item["normalized_path"]) for item in payload}
