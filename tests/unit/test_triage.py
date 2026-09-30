from tests.helpers import ROOT

from mcp_gov_audit.config import ProbingConfig, load_policy
from mcp_gov_audit.models import ToolDescriptor
from mcp_gov_audit.triage import probe_decision, risk_score

POLICY = load_policy(ROOT / "configs" / "policy.default.yaml")


def _probing(**overrides: object) -> ProbingConfig:
    values: dict[str, object] = {
        "mode": "safe",
        "allowlist": (),
        "denylist": ("delete_*", "update_*"),
        "max_probes_per_tool": 1,
        "fixtures_file": "fixtures.yaml",
        "llm_generated_inputs": False,
        "seed_values": {},
    }
    values.update(overrides)
    return ProbingConfig.model_validate(values)


def _tool(
    name: str,
    *,
    annotations: dict[str, object] | None = None,
    description: str | None = None,
    output_schema: dict[str, object] | None = None,
) -> ToolDescriptor:
    return ToolDescriptor(
        name=name,
        description=description,
        input_schema={"type": "object", "properties": {}},
        output_schema=output_schema,
        annotations=annotations,
    )


def test_mode_off_skips_before_other_rows() -> None:
    tool = _tool("get_column_quality", annotations={"readOnlyHint": True})
    assert probe_decision(tool, _probing(mode="off")) == "skip_mode_off"


def test_denylist_overrides_allowlist_and_read_only() -> None:
    tool = _tool("delete_asset", annotations={"readOnlyHint": True})
    assert probe_decision(tool, _probing(mode="allowlist", allowlist=("delete_asset",))) == (
        "skip_denylisted"
    )


def test_destructive_hint_overrides_allowlist() -> None:
    tool = _tool("delete_asset", annotations={"readOnlyHint": False, "destructiveHint": True})
    probing = _probing(mode="allowlist", allowlist=("delete_asset",), denylist=())
    assert probe_decision(tool, probing) == "skip_destructive"


def test_allowlist_mode_skips_names_not_listed() -> None:
    tool = _tool("list_assets", annotations={"readOnlyHint": True})
    assert probe_decision(tool, _probing(mode="allowlist", allowlist=(), denylist=())) == (
        "skip_not_allowlisted"
    )


def test_safe_mode_skips_tools_without_read_only_hint() -> None:
    unannotated = _tool("list_assets")
    read_only_false = _tool("list_assets", annotations={"readOnlyHint": False})
    probing = _probing(denylist=())
    assert probe_decision(unannotated, probing) == "skip_not_allowlisted"
    assert probe_decision(read_only_false, probing) == "skip_not_allowlisted"


def test_safe_mode_allows_read_only_or_allowlisted_tools() -> None:
    read_only = _tool("get_column_quality", annotations={"readOnlyHint": True})
    allowlisted = _tool("list_assets", annotations={"readOnlyHint": False})
    assert probe_decision(read_only, _probing()) is None
    assert probe_decision(allowlisted, _probing(allowlist=("list_assets",), denylist=())) is None


def test_risk_score_counts_distinct_keywords_and_inferred_schema_keys() -> None:
    tool = _tool(
        "get_table_quality_summary",
        description="Returns a quality score and recommended actions",
        output_schema={"type": "object", "properties": {"likely_owner": {"type": "string"}}},
    )
    score = risk_score(tool, POLICY)
    assert score == 1.0
    plain = _tool("ping", description="health")
    assert risk_score(plain, POLICY) == 0.0
