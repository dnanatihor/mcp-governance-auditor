from mcp_gov_audit.config import ProbingConfig
from mcp_gov_audit.models import ToolDescriptor
from mcp_gov_audit.probing import plan_probes, resolve_inputs


def _probing(max_probes: int = 2) -> ProbingConfig:
    return ProbingConfig(
        mode="safe",
        allowlist=(),
        denylist=(),
        max_probes_per_tool=max_probes,
        fixtures_file="fixtures.yaml",
        llm_generated_inputs=True,
        seed_values={},
    )


def _tool(name: str, *, required: list[str] | None) -> ToolDescriptor:
    schema: dict[str, object] = {"type": "object", "properties": {"asset_id": {"type": "string"}}}
    if required is not None:
        schema["required"] = required
    return ToolDescriptor(
        name=name,
        input_schema=schema,
        annotations={"readOnlyHint": True},
    )


async def test_fixtures_are_capped_and_validated() -> None:
    tool = _tool("get_column_quality", required=["asset_id"]).model_copy(
        update={"probe_decision": None}
    )
    fixtures = {
        "get_column_quality": (
            {"asset_id": "col_email"},
            {"asset_id": 12},
            {"asset_id": "extra"},
        )
    }
    resolved = await resolve_inputs(tool, fixtures, _probing(max_probes=2))
    assert resolved == [({"asset_id": "col_email"}, "fixture")]


async def test_empty_object_when_schema_has_no_required_properties() -> None:
    tool = _tool("list_assets", required=None)
    assert await resolve_inputs(tool, {}, _probing()) == [({}, "empty")]


async def test_required_tool_without_fixtures_is_skip_no_input_without_planner() -> None:
    tool = _tool("get_owner_suggestions", required=["asset_id"])
    tools, requests = await plan_probes([tool], {}, _probing(), llm_enabled=True)
    assert requests == []
    assert tools[0].probe_decision == "skip_no_input"


async def test_skipped_tools_are_not_planned() -> None:
    tool = _tool("delete_asset", required=["asset_id"]).model_copy(
        update={"probe_decision": "skip_destructive"}
    )
    tools, requests = await plan_probes([tool], {"delete_asset": ({"asset_id": "x"},)}, _probing())
    assert requests == []
    assert tools[0].probe_decision == "skip_destructive"
