"""introspect lists the fixture tools and does not call them."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from tests.helpers import ROOT
from typer.testing import CliRunner

from mcp_gov_audit.cli import app

runner = CliRunner()
_ELIGIBLE = {
    "get_column_quality",
    "get_table_quality_summary",
    "get_asset_description",
    "get_owner_suggestions",
    "get_profile_snapshot",
    "flaky_lookup",
    "slow_lookup",
}
_MAN = {
    ("MAN-001", "get_table_quality_summary"),
    ("MAN-002", "get_owner_suggestions"),
    ("MAN-003", "list_assets"),
}


def test_introspect_lists_fixture_decisions_without_calling_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    log_path = tmp_path / "calls.log"
    config = _fixture_config(tmp_path, log_path)
    output = tmp_path / "out"
    result = runner.invoke(
        app,
        ["introspect", "-c", str(config), "--output-dir", str(output)],
    )
    assert result.exit_code == 0
    assert not log_path.exists() or log_path.read_text(encoding="utf-8") == ""
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    decisions = {item["name"]: item["probe_decision"] for item in manifest}
    assert set(decisions) == _ELIGIBLE | {"list_assets", "delete_asset"}
    assert decisions["delete_asset"] == "skip_destructive"
    assert decisions["list_assets"] == "skip_not_allowlisted"
    assert {name for name, decision in decisions.items() if decision is None} == _ELIGIBLE
    findings = {
        tuple(line.split()[1:])
        for line in result.stdout.splitlines()
        if line.startswith("FINDING ")
    }
    assert findings == _MAN


def _fixture_config(tmp_path: Path, log_path: Path) -> Path:
    text = (ROOT / "tests" / "fixtures" / "audit.fixture.yaml").read_text(encoding="utf-8")
    text = text.replace("command: python", f'command: "{sys.executable}"', 1)
    text = text.replace(
        'args: ["tests/fixtures/fake_catalog_server.py"]',
        "args: [tests/fixtures/fake_catalog_server.py]\n"
        "  env:\n"
        f'    FIXTURE_CALL_LOG: "{log_path}"',
        1,
    )
    path = tmp_path / "audit.yaml"
    path.write_text(text, encoding="utf-8")
    return path
