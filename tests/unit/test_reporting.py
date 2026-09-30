"""Schema freshness, metrics, and exit codes that do not need the fixture server."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from tests.helpers import ROOT, write_audit_config
from typer.testing import CliRunner

from mcp_gov_audit.cli import app
from mcp_gov_audit.reporting.json_report import report_json_schema
from mcp_gov_audit.reporting.metrics import compute_metrics

runner = CliRunner()
_SCHEMA = ROOT / "schemas" / "report.v1.json"
_SECTIONS = (
    "## Summary",
    "## Target and run",
    "## Coverage",
    "## Epistemic distribution",
    "## Findings",
    "## Static findings",
    "## Appendix",
)


def test_committed_report_schema_matches_the_model() -> None:
    committed = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    assert committed == report_json_schema()


def test_metrics_are_null_when_the_denominator_is_zero() -> None:
    metrics = compute_metrics(
        tools=[],
        probes=[],
        envelopes=[],
        fields=[],
        classifications=[],
    )
    assert metrics.probe_coverage is None
    assert metrics.explicit_label_coverage is None
    assert metrics.inference_disclosure_rate is None
    assert metrics.governance_notice_rate is None
    assert metrics.unknown_rate is None


def test_static_only_clean_repo_exits_0_and_writes_the_seven_sections(tmp_path: Path) -> None:
    config = _static_config(tmp_path, "instrumented_global", review=False)
    output = tmp_path / "out"
    result = runner.invoke(
        app,
        ["run", "-c", str(config), "--static-only", "--output-dir", str(output)],
    )
    assert result.exit_code == 0
    report_json, report_md = _only_report(output)
    jsonschema.validate(report_json, json.loads(_SCHEMA.read_text(encoding="utf-8")))
    assert report_json["run"]["verdict"] == "pass"
    for heading in _SECTIONS:
        assert heading in report_md
    assert "Rule catalog" in report_md
    assert "Run manifest" in report_md


def test_unreachable_url_exits_3(tmp_path: Path) -> None:
    path = write_audit_config(tmp_path)
    text = path.read_text(encoding="utf-8").replace(
        "url: http://localhost:8000/mcp",
        "url: http://127.0.0.1:9/mcp",
        1,
    )
    path.write_text(text, encoding="utf-8")
    result = runner.invoke(
        app,
        ["run", "-c", str(path), "--no-llm", "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == 3


def test_unreachable_stdio_target_exits_3(tmp_path: Path) -> None:
    path = write_audit_config(tmp_path)
    text = path.read_text(encoding="utf-8").replace(
        "transport: streamable_http",
        "transport: stdio\n  command: /no/such/mcp-auditor-target",
        1,
    )
    path.write_text(text, encoding="utf-8")
    result = runner.invoke(app, ["run", "-c", str(path), "--no-llm", "--output-dir", str(tmp_path)])
    assert result.exit_code == 3


def test_static_review_pause_exits_4(tmp_path: Path) -> None:
    config = _static_config(tmp_path, "flush_per_request", review=True)
    output = tmp_path / "out"
    result = runner.invoke(
        app,
        ["run", "-c", str(config), "--static-only", "--output-dir", str(output)],
    )
    assert result.exit_code == 4
    assert "mcpaudit review" in result.stdout
    assert list(output.rglob("report.json")) == []


def _static_config(tmp_path: Path, case: str, *, review: bool) -> Path:
    path = write_audit_config(tmp_path)
    sample = (ROOT / "tests" / "fixtures" / "static_samples" / case).as_posix()
    text = path.read_text(encoding="utf-8")
    text = text.replace("repo_path: ../oe_mcp", f"repo_path: {sample}", 1)
    if review:
        text = text.replace("review:\n  enabled: false", "review:\n  enabled: true", 1)
    path.write_text(text, encoding="utf-8")
    return path


def _only_report(output: Path) -> tuple[dict[str, object], str]:
    reports = list(output.rglob("report.json"))
    assert len(reports) == 1
    payload = json.loads(reports[0].read_text(encoding="utf-8"))
    markdown = reports[0].with_name("report.md").read_text(encoding="utf-8")
    assert payload["schema_version"] == "1.0"
    return payload, markdown


def test_invalid_config_still_exits_2(tmp_path: Path) -> None:
    path = write_audit_config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8").replace("fail_on: high", "fail_on: banana", 1),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["run", "-c", str(path), "--no-llm"])
    assert result.exit_code == 2
    assert "run.fail_on" in (result.stdout + result.stderr)
