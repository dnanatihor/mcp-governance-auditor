"""Tool listing and the single safe call path (§8)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal

import mcp.types as types
import structlog
from mcp import ClientSession

from mcp_gov_audit.models import ProbeRequest, ProbeResult, ToolDescriptor

_LOG = structlog.get_logger()


async def list_all_tools(session: ClientSession) -> list[ToolDescriptor]:
    """Follow `nextCursor` until the tool list is exhausted."""
    collected: list[ToolDescriptor] = []
    cursor: str | None = None
    while True:
        if cursor is None:
            page = await session.list_tools()
        else:
            page = await session.list_tools(params=types.PaginatedRequestParams(cursor=cursor))
        collected.extend(_descriptor(tool) for tool in page.tools)
        cursor = page.nextCursor
        if not cursor:
            return collected


async def call_tool_safely(
    session: ClientSession,
    request: ProbeRequest,
    timeout_s: float,
    *,
    clock: Callable[[], datetime] | None = None,
) -> ProbeResult:
    """Call one tool. Never raises. This is the only `session.call_tool` site."""
    now = clock or (lambda: datetime.now(UTC))
    started = time.perf_counter()
    try:
        result = await asyncio.wait_for(
            session.call_tool(request.tool_name, request.arguments),
            timeout=timeout_s,
        )
    except TimeoutError:
        return _failed(request, "timeout", "timed out", started, now)
    except Exception as exc:
        return _failed(request, "transport_error", str(exc), started, now)
    return _from_result(request, result, started, now)


def _descriptor(tool: types.Tool) -> ToolDescriptor:
    annotations: dict[str, Any] | None = None
    if tool.annotations is not None:
        dumped = tool.annotations.model_dump(exclude_none=True)
        annotations = dumped or None
    return ToolDescriptor(
        name=tool.name,
        description=tool.description,
        input_schema=dict(tool.inputSchema),
        output_schema=None if tool.outputSchema is None else dict(tool.outputSchema),
        annotations=annotations,
    )


def _from_result(
    request: ProbeRequest,
    result: types.CallToolResult,
    started: float,
    clock: Callable[[], datetime],
) -> ProbeResult:
    texts: list[str] = []
    non_text = 0
    for block in result.content:
        if isinstance(block, types.TextContent):
            texts.append(block.text)
        else:
            non_text += 1
    if non_text:
        _LOG.info("non_text_content", tool_name=request.tool_name, count=non_text)
    error_message = None
    if result.isError:
        error_message = texts[0] if texts else "tool error"
    return ProbeResult(
        probe_id=request.probe_id,
        tool_name=request.tool_name,
        arguments=dict(request.arguments),
        input_source=request.input_source,
        status="tool_error" if result.isError else "ok",
        structured_content=result.structuredContent,
        text_content=tuple(texts),
        meta=result.meta,
        error_message=error_message,
        latency_ms=_latency_ms(started),
        captured_at=clock(),
    )


def _failed(
    request: ProbeRequest,
    status: Literal["timeout", "transport_error"],
    message: str,
    started: float,
    clock: Callable[[], datetime],
) -> ProbeResult:
    return ProbeResult(
        probe_id=request.probe_id,
        tool_name=request.tool_name,
        arguments=dict(request.arguments),
        input_source=request.input_source,
        status=status,
        structured_content=None,
        text_content=(),
        meta=None,
        error_message=message,
        latency_ms=_latency_ms(started),
        captured_at=clock(),
    )


def _latency_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
