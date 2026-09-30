"""Fixture report, exit codes 1, diff, and human review (§13, §16 Phase 6)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import jsonschema
import pytest
from tests.helpers import ROOT
from tests.llm_stubs import StubClassifier
from typer.testing import CliRunner

from mcp_gov_audit.cli import app
from mcp_gov_audit.config import load_config
from mcp_gov_audit.graph.run import run_until_normalize
from mcp_gov_audit.models import LLMFieldVerdict, Severity
from mcp_gov_audit.reporting.diff import load_run_diff
from mcp_gov_audit.reporting.json_report import is_active, load_report, run_exit_code

runner = CliRunner()
_SCHEMA = json.loads((ROOT / "schemas" / "report.v1.json").read_text(encoding="utf-8"))
_SECTIONS = (
    "## Summary",
    "## Target and run",
    "## Coverage",
    "## Epistemic distribution",
    "## Findings",
    "## Static findings",
    "## Appendix",
)


def test_fixture_exit_codes_schema_and_diff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    nollm = _invoke_fixture(tmp_path / "nollm", "--no-llm")
    assert nollm.exit_code == 1
    critical = _invoke_fixture(tmp_path / "critical", "--no-llm", "--fail-on", "critical")
    assert critical.exit_code == 1

    nollm_dir = _run_dir(nollm.stdout)
    report = json.loads((nollm_dir / "report.json").read_text(encoding="utf-8"))
    jsonschema.validate(report, _SCHEMA)
    markdown = (nollm_dir / "report.md").read_text(encoding="utf-8")
    for heading in _SECTIONS:
        assert heading in markdown
    loaded = load_report(nollm_dir / "report.json")
    assert (
        run_exit_code(
            loaded.findings,
            fail_on=Severity.CRITICAL,
            fail_on_llm_assisted=False,
        )
        == 1
    )

    stub_dir = asyncio.run(_stub_run(tmp_path / "stub-out"))
    diff, _new = load_run_diff(nollm_dir, stub_dir)
    assert [(item.rule_id, item.tool_name, item.normalized_path) for item in diff.new] == [
        ("EPI-003", "get_table_quality_summary", "$.quality.score")
    ]
    assert diff.resolved == []
    again = runner.invoke(
        app,
        ["diff", str(nollm_dir), str(stub_dir), "--json"],
    )
    assert again.exit_code == 0
    payload = json.loads(again.stdout)
    assert len(payload["new"]) == 1
    assert payload["new"][0]["normalized_path"] == "$.quality.score"
    assert payload["new"][0]["rule_id"] == "EPI-003"


def test_stub_review_dismiss_drops_the_pending_finding_from_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    output = tmp_path / "paused"
    completed = asyncio.run(_stub_run_paused(output))
    assert completed.exit_code == 4
    assert completed.paused is True
    assert not (completed.run_dir / "report.json").exists()
    pending = [item for item in completed.findings if item.review_status == "pending"]
    assert [(item.rule_id, item.normalized_path) for item in pending] == [
        ("EPI-003", "$.quality.score")
    ]

    reviewed = runner.invoke(
        app,
        ["review", completed.run_dir.name, "--output-dir", str(output)],
        input="dismiss\n\n",
    )
    assert reviewed.exit_code == 1
    report = load_report(completed.run_dir / "report.json")
    score = next(
        item
        for item in report.findings
        if item.rule_id == "EPI-003" and item.normalized_path == "$.quality.score"
    )
    assert score.review_status == "dismissed"
    assert is_active(score, fail_on_llm_assisted=False) is False
    others = [item for item in report.findings if item.finding_id != score.finding_id]
    assert reviewed.exit_code == run_exit_code(
        report.findings,
        fail_on=Severity.HIGH,
        fail_on_llm_assisted=False,
    )
    assert reviewed.exit_code == run_exit_code(
        others,
        fail_on=Severity.HIGH,
        fail_on_llm_assisted=False,
    )


def _invoke_fixture(output: Path, *args: str) -> object:
    source = (ROOT / "tests" / "fixtures" / "audit.fixture.yaml").read_text(encoding="utf-8")
    source = source.replace("command: python", f'command: "{sys.executable}"', 1)
    config = output.parent / f"{output.name}.yaml"
    config.write_text(source, encoding="utf-8")
    return runner.invoke(
        app,
        ["run", "-c", str(config), *args, "--output-dir", str(output)],
    )


def _run_dir(stdout: str) -> Path:
    for line in stdout.splitlines():
        if line.startswith("verdict="):
            continue
        candidate = Path(line.strip())
        if candidate.is_dir() and (candidate / "report.json").is_file():
            return candidate
    raise AssertionError(stdout)


async def _stub_run(output: Path) -> Path:
    loaded = _fixture_loaded(output / "calls.log", output / "cache")
    verdict = LLMFieldVerdict(
        field_path="$.quality.score",
        layer="inferred",
        confidence=0.85,
        evidence="stub verdict",
    )
    completed = await run_until_normalize(
        loaded,
        output_root=output,
        classifier=StubClassifier(verdicts={"$.quality.score": verdict}),
    )
    assert completed.exit_code == 1
    assert (completed.run_dir / "report.json").is_file()
    return completed.run_dir


async def _stub_run_paused(output: Path) -> object:
    loaded = _fixture_loaded(output / "calls.log", output / "cache")
    audit = loaded.audit.model_copy(
        update={"review": loaded.audit.review.model_copy(update={"enabled": True})}
    )
    loaded = loaded.model_copy(update={"audit": audit})
    verdict = LLMFieldVerdict(
        field_path="$.quality.score",
        layer="inferred",
        confidence=0.85,
        evidence="stub verdict",
    )
    return await run_until_normalize(
        loaded,
        output_root=output,
        classifier=StubClassifier(verdicts={"$.quality.score": verdict}),
    )


def _fixture_loaded(log_path: Path, cache_dir: Path) -> object:
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
