import json
import logging
from pathlib import Path

import pytest
import structlog
from tests.helpers import write_audit_config
from typer.testing import CliRunner

from mcp_gov_audit.cli import app, configure_logging

runner = CliRunner()


def _combined(result: object) -> str:
    stdout = getattr(result, "stdout", "") or ""
    stderr = getattr(result, "stderr", "") or ""
    output = getattr(result, "output", "") or ""
    return "\n".join((stdout, stderr, output))


def test_help_lists_five_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ("introspect", "run", "review", "diff", "rules"):
        assert name in result.stdout

    run_help = runner.invoke(app, ["run", "--help"])
    assert run_help.exit_code == 0
    for flag in ("--no-llm", "--no-cache", "--static-only", "--fail-on", "--output-dir"):
        assert flag in run_help.stdout

    introspect_help = runner.invoke(app, ["introspect", "--help"])
    assert "-c" in introspect_help.stdout
    diff_help = runner.invoke(app, ["diff", "--help"])
    assert "--json" in diff_help.stdout
    assert "--fail-on" in diff_help.stdout


def test_invalid_config_exits_2_and_names_the_key(tmp_path: Path) -> None:
    path = write_audit_config(tmp_path)
    text = path.read_text(encoding="utf-8").replace("fail_on: high", "fail_on: banana", 1)
    path.write_text(text, encoding="utf-8")
    result = runner.invoke(app, ["introspect", "-c", str(path)])
    assert result.exit_code == 2
    assert "run.fail_on" in _combined(result)


def test_missing_env_var_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISSING_MCP_AUDIT_TOKEN", raising=False)
    path = write_audit_config(tmp_path, authorization="Bearer ${MISSING_MCP_AUDIT_TOKEN}")
    result = runner.invoke(app, ["run", "-c", str(path), "--no-llm"])
    assert result.exit_code == 2
    assert "target.headers.Authorization" in _combined(result)
    assert "MISSING_MCP_AUDIT_TOKEN" in _combined(result)


def test_run_help_describes_no_cache_as_skip_reads() -> None:
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    assert "still write" in result.stdout


def test_rules_json_lists_coverage_rules() -> None:
    result = runner.invoke(app, ["rules", "--json"])
    assert result.exit_code == 0
    listed = json.loads(result.stdout)
    assert [row["id"] for row in listed] == [
        "COV-001",
        "COV-002",
        "COV-003",
        "EPI-001",
        "EPI-002",
        "EPI-003",
        "EPI-004",
        "EPI-005",
        "EPI-006",
        "EPI-007",
        "EPI-008",
        "EPI-009",
        "MAN-001",
        "MAN-002",
        "MAN-003",
        "OBS-001",
        "OBS-002",
        "OBS-003",
        "SEC-001",
        "SEC-002",
        "SEC-003",
    ]


def test_logging_writes_json_to_stderr_and_run_log(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_log = tmp_path / "out" / "run.log"
    configure_logging(run_log)
    structlog.get_logger().info("audit_event", run_id="run-1", node="introspect", tool_name=None)
    for handler in logging.getLogger().handlers:
        handler.flush()
    line = run_log.read_text(encoding="utf-8").strip().splitlines()[-1]
    payload = json.loads(line)
    assert payload["event"] == "audit_event"
    assert payload["run_id"] == "run-1"
    assert payload["node"] == "introspect"
    captured = capsys.readouterr()
    assert "audit_event" in captured.err
