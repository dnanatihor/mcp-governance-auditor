"""list_all_tools pagination (§8)."""

from __future__ import annotations

from typing import cast

import mcp.types as types
from mcp import ClientSession

from mcp_gov_audit.mcp_client.operations import list_all_tools


class _PagedSession:
    def __init__(self) -> None:
        self.cursors: list[str | None] = []

    async def list_tools(
        self,
        cursor: str | None = None,
        *,
        params: types.PaginatedRequestParams | None = None,
    ) -> types.ListToolsResult:
        requested = None if params is None else params.cursor
        if cursor is not None:
            requested = cursor
        self.cursors.append(requested)
        if requested is None:
            return types.ListToolsResult(
                tools=[types.Tool(name="one", inputSchema={"type": "object"})],
                nextCursor="page-2",
            )
        return types.ListToolsResult(
            tools=[types.Tool(name="two", inputSchema={"type": "object"})],
        )


async def test_list_all_tools_follows_next_cursor() -> None:
    session = _PagedSession()
    tools = await list_all_tools(cast(ClientSession, session))
    assert [tool.name for tool in tools] == ["one", "two"]
    assert session.cursors == [None, "page-2"]
