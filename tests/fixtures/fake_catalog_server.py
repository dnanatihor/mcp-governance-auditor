"""Fixture catalog MCP server (§15.1).

Low-level ``Server`` (not FastMCP). Speaks stdio and appends every ``tools/call``
name to the file in ``FIXTURE_CALL_LOG``.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jsonschema
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

STALE_OBSERVED_AT = "2025-01-01T00:00:00Z"
_CALL_LOG_ENV = "FIXTURE_CALL_LOG"

_ASSET_INPUT: dict[str, Any] = {
    "type": "object",
    "properties": {"asset_id": {"type": "string"}},
    "required": ["asset_id"],
}
_EMPTY_INPUT: dict[str, Any] = {"type": "object", "properties": {}}
_INFERENCE_FLAG_OUTPUT: dict[str, Any] = {
    "type": "object",
    "properties": {"inference_permitted": {"type": "boolean"}},
    "additionalProperties": True,
}
_OWNER_OUTPUT: dict[str, Any] = {
    "type": "object",
    "properties": {"ai_inferences": {"type": "object"}},
    "additionalProperties": True,
}

_Handler = Callable[[dict[str, Any]], Awaitable[types.CallToolResult]]

server = Server("fake-catalog", version="0.1.0")


def _now_minus_one_day() -> str:
    moment = datetime.now(UTC) - timedelta(days=1)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _tool(
    name: str,
    description: str,
    input_schema: dict[str, Any],
    *,
    output_schema: dict[str, Any] | None = None,
    read_only: bool | None = None,
    destructive: bool | None = None,
) -> types.Tool:
    annotations = None
    if read_only is not None or destructive is not None:
        annotations = types.ToolAnnotations(
            readOnlyHint=read_only,
            destructiveHint=destructive,
        )
    return types.Tool(
        name=name,
        description=description,
        inputSchema=input_schema,
        outputSchema=output_schema,
        annotations=annotations,
    )


def _tools() -> tuple[types.Tool, ...]:
    return (
        _tool(
            "get_column_quality",
            "Returns data quality results, profiling statistics and AI inferences for a column.",
            _ASSET_INPUT,
            output_schema=_INFERENCE_FLAG_OUTPUT,
            read_only=True,
        ),
        _tool(
            "get_table_quality_summary",
            "Returns a quality score and recommended actions for a table.",
            _ASSET_INPUT,
            read_only=True,
        ),
        _tool(
            "get_asset_description",
            "Returns the description of a catalog asset.",
            _ASSET_INPUT,
            output_schema=_INFERENCE_FLAG_OUTPUT,
            read_only=True,
        ),
        _tool(
            "get_owner_suggestions",
            "Suggests likely owners for an asset.",
            _ASSET_INPUT,
            output_schema=_OWNER_OUTPUT,
            read_only=True,
        ),
        _tool(
            "get_profile_snapshot",
            "Returns the latest profiling statistics for an asset.",
            _ASSET_INPUT,
            output_schema=_INFERENCE_FLAG_OUTPUT,
            read_only=True,
        ),
        _tool("list_assets", "Lists catalog assets.", _EMPTY_INPUT),
        _tool(
            "delete_asset",
            "Deletes a catalog asset.",
            _ASSET_INPUT,
            read_only=False,
            destructive=True,
        ),
        _tool(
            "flaky_lookup",
            "Looks up an asset (always fails).",
            _EMPTY_INPUT,
            read_only=True,
        ),
        _tool(
            "slow_lookup",
            "Looks up an asset slowly.",
            _EMPTY_INPUT,
            read_only=True,
        ),
    )


_TOOL_LIST = _tools()
_TOOLS_BY_NAME = {tool.name: tool for tool in _TOOL_LIST}


def _ok(payload: dict[str, Any], output_schema: dict[str, Any] | None) -> types.CallToolResult:
    if output_schema is not None:
        jsonschema.validate(instance=payload, schema=output_schema)
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload))],
        structuredContent=payload,
    )


def _error(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        isError=True,
    )


def _column_quality(now: str) -> dict[str, Any]:
    return {
        "asset": {"id": "col_email", "name": "email"},
        "inference_permitted": True,
        "governance_notice": "AI-generated content is advisory and not certified.",
        "certified_findings": [
            {
                "rule_id": "DQ-17",
                "result": "pass",
                "certified_at": now,
                "certified_by": "steward_a",
            }
        ],
        "profiling_observations": {
            "null_pct": 0.02,
            "distinct_count": 9812,
            "top_value": "jane.doe@example.com",
            "observed_at": now,
            "profile_run_id": "pr_9",
        },
        "ai_inferences": {
            "likely_pii": True,
            "model": "gen-model-x",
            "generated_at": now,
        },
    }


def _table_quality() -> dict[str, Any]:
    return {
        "table": "orders",
        "quality": {
            "score": 0.87,
            "dq_rule_pass_rate": 0.91,
            "recommended_action": "Deduplicate customer_id before joins",
        },
    }


def _asset_description(now: str) -> dict[str, Any]:
    return {
        "inference_permitted": True,
        "governance_notice": "AI-generated content is advisory and not certified.",
        "certified_findings": [
            {
                "description": "Stores customer emails for marketing campaigns.",
                "model": "gen-model-x",
                "generated_at": now,
            }
        ],
    }


def _owner_suggestions(now: str) -> dict[str, Any]:
    return {
        "inference_permitted": False,
        "ai_inferences": {
            "suggested_owner": "data-eng",
            "model": "gen-model-x",
            "generated_at": now,
        },
    }


def _profile_snapshot() -> dict[str, Any]:
    return {
        "inference_permitted": False,
        "profiling_observations": [
            {
                "null_pct": 0.10,
                "observed_at": STALE_OBSERVED_AT,
                "profile_run_id": "pr_1",
            },
            {"distinct_count": 40, "profile_run_id": "pr_2"},
        ],
    }


async def _handle_column_quality(_arguments: dict[str, Any]) -> types.CallToolResult:
    tool = _TOOLS_BY_NAME["get_column_quality"]
    return _ok(_column_quality(_now_minus_one_day()), tool.outputSchema)


async def _handle_table_quality(_arguments: dict[str, Any]) -> types.CallToolResult:
    return _ok(_table_quality(), None)


async def _handle_asset_description(_arguments: dict[str, Any]) -> types.CallToolResult:
    tool = _TOOLS_BY_NAME["get_asset_description"]
    return _ok(_asset_description(_now_minus_one_day()), tool.outputSchema)


async def _handle_owner_suggestions(_arguments: dict[str, Any]) -> types.CallToolResult:
    tool = _TOOLS_BY_NAME["get_owner_suggestions"]
    return _ok(_owner_suggestions(_now_minus_one_day()), tool.outputSchema)


async def _handle_profile_snapshot(_arguments: dict[str, Any]) -> types.CallToolResult:
    tool = _TOOLS_BY_NAME["get_profile_snapshot"]
    return _ok(_profile_snapshot(), tool.outputSchema)


async def _handle_list_assets(_arguments: dict[str, Any]) -> types.CallToolResult:
    return _ok({"assets": [{"id": "tbl_orders"}]}, None)


async def _handle_delete_asset(_arguments: dict[str, Any]) -> types.CallToolResult:
    return _ok({"deleted": True}, None)


async def _handle_flaky_lookup(_arguments: dict[str, Any]) -> types.CallToolResult:
    return _error("lookup failed")


async def _handle_slow_lookup(_arguments: dict[str, Any]) -> types.CallToolResult:
    await asyncio.sleep(5)
    return _ok({"ok": True}, None)


_HANDLERS: dict[str, _Handler] = {
    "get_column_quality": _handle_column_quality,
    "get_table_quality_summary": _handle_table_quality,
    "get_asset_description": _handle_asset_description,
    "get_owner_suggestions": _handle_owner_suggestions,
    "get_profile_snapshot": _handle_profile_snapshot,
    "list_assets": _handle_list_assets,
    "delete_asset": _handle_delete_asset,
    "flaky_lookup": _handle_flaky_lookup,
    "slow_lookup": _handle_slow_lookup,
}


def _append_call_log(tool_name: str) -> None:
    raw = os.environ.get(_CALL_LOG_ENV, "")
    if raw == "":
        return
    with Path(raw).open("a", encoding="utf-8") as handle:
        handle.write(f"{tool_name}\n")


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    return list(_TOOL_LIST)


@server.call_tool(validate_input=False)
async def _call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
    _append_call_log(name)
    tool = _TOOLS_BY_NAME.get(name)
    if tool is None:
        return _error(f"unknown tool: {name}")
    try:
        jsonschema.validate(instance=arguments, schema=tool.inputSchema)
    except jsonschema.ValidationError as exc:
        return _error(exc.message)
    return await _HANDLERS[name](arguments)


async def serve() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    asyncio.run(serve())


if __name__ == "__main__":
    main()
