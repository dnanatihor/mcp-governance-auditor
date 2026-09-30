import json
from pathlib import Path

import pytest
from tests.helpers import ROOT, write_audit_config

from mcp_gov_audit.config import ConfigError, load_audit_config, load_config


def test_interpolation_replaces_variable_inside_a_string(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OE_MCP_TOKEN", "s3cret")
    path = write_audit_config(tmp_path, authorization="Bearer ${OE_MCP_TOKEN}")
    loaded = load_config(path)
    assert loaded.audit.target.headers["Authorization"] == "Bearer s3cret"
    assert loaded.audit.target.env["OE_API_BASE"] == "https://example.test"
    assert loaded.probe_fixtures["get_column_quality"][0]["asset_id"] == "col_email"
    redacted = loaded.audit.without_secrets().model_dump_json()
    assert json.loads(redacted)["target"]["headers"] == {}
    assert json.loads(redacted)["target"]["env"] == {}
    assert "s3cret" not in redacted
    assert "https://example.test" not in redacted


def test_missing_environment_variable_names_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MISSING_MCP_AUDIT_TOKEN", raising=False)
    path = write_audit_config(tmp_path, authorization="Bearer ${MISSING_MCP_AUDIT_TOKEN}")
    with pytest.raises(ConfigError) as caught:
        load_config(path)
    assert caught.value.key == "target.headers.Authorization"
    assert "MISSING_MCP_AUDIT_TOKEN" in str(caught.value)


def test_invalid_fail_on_names_the_key(tmp_path: Path) -> None:
    path = write_audit_config(tmp_path)
    text = path.read_text(encoding="utf-8").replace("fail_on: high", "fail_on: banana", 1)
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError) as caught:
        load_audit_config(path)
    assert caught.value.key == "run.fail_on"
    assert "run.fail_on" in str(caught.value)


def test_unknown_key_is_named(tmp_path: Path) -> None:
    path = write_audit_config(tmp_path)
    text = path.read_text(encoding="utf-8").replace("name: demo", "name: demo\n  nope: 1", 1)
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError) as caught:
        load_audit_config(path)
    assert caught.value.key == "run.nope"


def test_invalid_clock_override_names_the_key(tmp_path: Path) -> None:
    path = write_audit_config(tmp_path)
    text = path.read_text(encoding="utf-8").replace(
        "clock_override: null", 'clock_override: "yesterday"', 1
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError) as caught:
        load_audit_config(path)
    assert caught.value.key == "run.clock_override"


def test_missing_policy_file_names_policy_file(tmp_path: Path) -> None:
    path = write_audit_config(tmp_path)
    text = path.read_text(encoding="utf-8").replace(
        f'policy_file: "{(tmp_path / "policy.yaml").as_posix()}"',
        'policy_file: "./missing-policy.yaml"',
        1,
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError) as caught:
        load_config(path)
    assert caught.value.key == "policy_file"


def test_example_and_fixture_configs_load(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OE_MCP_TOKEN", "s3cret")
    monkeypatch.chdir(ROOT)
    example = load_config(ROOT / "configs" / "audit.example.yaml")
    assert example.audit.target.headers["Authorization"] == "Bearer s3cret"
    assert example.policy.envelope.inference_flag_key == "inference_permitted"
    assert "s3cret" not in example.audit.without_secrets().model_dump_json()

    fixture = load_config(ROOT / "tests" / "fixtures" / "audit.fixture.yaml")
    assert fixture.audit.probing.mode == "safe"
    assert fixture.audit.run.tool_timeout_s == 1
    assert fixture.audit.probing.max_probes_per_tool == 1
    assert fixture.audit.static_scan.enabled is False
    assert set(fixture.probe_fixtures) == {
        "get_column_quality",
        "get_table_quality_summary",
        "get_asset_description",
        "get_owner_suggestions",
        "get_profile_snapshot",
    }
