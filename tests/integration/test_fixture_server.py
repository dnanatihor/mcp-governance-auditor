"""The fixture server speaks stdio and answers tools/list (§15.1)."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from tests.helpers import ROOT

_SERVER = ROOT / "tests" / "fixtures" / "fake_catalog_server.py"

_READONLY = (
    "get_column_quality",
    "get_table_quality_summary",
    "get_asset_description",
    "get_owner_suggestions",
    "get_profile_snapshot",
    "flaky_lookup",
    "slow_lookup",
)


@pytest.mark.asyncio
async def test_fixture_server_lists_tools_over_stdio(tmp_path: Path) -> None:
    log_path = tmp_path / "calls.log"
    env = dict(os.environ)
    env["FIXTURE_CALL_LOG"] = str(log_path)
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(_SERVER)],
        env=env,
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        listed = await session.list_tools()
        column = await session.call_tool("get_column_quality", {"asset_id": "col_email"})
        table = await session.call_tool("get_table_quality_summary", {"asset_id": "tbl_orders"})
        description = await session.call_tool("get_asset_description", {"asset_id": "col_email"})
        owner = await session.call_tool("get_owner_suggestions", {"asset_id": "tbl_orders"})
        profile = await session.call_tool("get_profile_snapshot", {"asset_id": "tbl_orders"})
        assets = await session.call_tool("list_assets", {})
        flaky = await session.call_tool("flaky_lookup", {})

    by_name = {tool.name: tool for tool in listed.tools}
    assert set(by_name) == {
        "get_column_quality",
        "get_table_quality_summary",
        "get_asset_description",
        "get_owner_suggestions",
        "get_profile_snapshot",
        "list_assets",
        "delete_asset",
        "flaky_lookup",
        "slow_lookup",
    }
    for name in _READONLY:
        annotations = by_name[name].annotations
        assert annotations is not None
        assert annotations.readOnlyHint is True
    assert by_name["list_assets"].annotations is None
    delete_annotations = by_name["delete_asset"].annotations
    assert delete_annotations is not None
    assert delete_annotations.readOnlyHint is False
    assert delete_annotations.destructiveHint is True

    for name in (
        "get_column_quality",
        "get_asset_description",
        "get_profile_snapshot",
    ):
        schema = by_name[name].outputSchema
        assert schema is not None
        assert "inference_permitted" in schema["properties"]
        assert schema.get("additionalProperties") is not False
    assert by_name["get_table_quality_summary"].outputSchema is None
    assert by_name["list_assets"].outputSchema is None
    owner_schema = by_name["get_owner_suggestions"].outputSchema
    assert owner_schema is not None
    assert set(owner_schema["properties"]) == {"ai_inferences"}
    assert owner_schema.get("additionalProperties") is not False

    assert column.isError is False
    assert column.structuredContent is not None
    text = column.content[0]
    assert text.type == "text"
    assert json.loads(text.text) == column.structuredContent
    assert column.structuredContent["inference_permitted"] is True
    certified_at = datetime.strptime(
        column.structuredContent["certified_findings"][0]["certified_at"],
        "%Y-%m-%dT%H:%M:%SZ",
    ).replace(tzinfo=UTC)
    assert abs(certified_at - (datetime.now(UTC) - timedelta(days=1))) < timedelta(seconds=5)

    assert table.structuredContent == {
        "table": "orders",
        "quality": {
            "score": 0.87,
            "dq_rule_pass_rate": 0.91,
            "recommended_action": "Deduplicate customer_id before joins",
        },
    }
    assert description.structuredContent is not None
    certified = description.structuredContent["certified_findings"][0]
    assert certified["model"] == "gen-model-x"
    assert certified["description"] == "Stores customer emails for marketing campaigns."
    assert owner.structuredContent is not None
    assert owner.structuredContent["inference_permitted"] is False
    assert owner.structuredContent["ai_inferences"]["suggested_owner"] == "data-eng"
    assert profile.structuredContent is not None
    observations = profile.structuredContent["profiling_observations"]
    assert observations[0]["observed_at"] == "2025-01-01T00:00:00Z"
    assert "observed_at" not in observations[1]
    assert assets.structuredContent == {"assets": [{"id": "tbl_orders"}]}

    assert flaky.isError is True
    assert flaky.content[0].text == "lookup failed"
    assert log_path.read_text(encoding="utf-8").splitlines() == [
        "get_column_quality",
        "get_table_quality_summary",
        "get_asset_description",
        "get_owner_suggestions",
        "get_profile_snapshot",
        "list_assets",
        "flaky_lookup",
    ]
    assert "delete_asset" not in log_path.read_text(encoding="utf-8")
    assert "slow_lookup" not in log_path.read_text(encoding="utf-8")
