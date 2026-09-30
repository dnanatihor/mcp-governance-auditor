"""MCP transport setup (§8)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import cast
from weakref import WeakKeyDictionary

from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, get_default_environment, stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.message import SessionMessage

from mcp_gov_audit.config import TargetConfig
from mcp_gov_audit.models import ServerInfo

_SERVER_INFO: WeakKeyDictionary[object, ServerInfo] = WeakKeyDictionary()


class TargetUnreachable(Exception):
    """Connect or initialize failed. The CLI maps this to exit code 3."""


def bind_server_info(session: object, info: ServerInfo) -> None:
    _SERVER_INFO[session] = info


def server_info_for(session: object) -> ServerInfo:
    try:
        return _SERVER_INFO[session]
    except KeyError as exc:
        raise RuntimeError("session has no server info") from exc


_CONNECT_TIMEOUT_S = 30


@asynccontextmanager
async def open_session(target: TargetConfig) -> AsyncIterator[ClientSession]:
    """Open a client session and initialize it. Yields the live session."""
    stack = AsyncExitStack()
    try:
        async with asyncio.timeout(_CONNECT_TIMEOUT_S):
            read, write = await _open_transport(stack, target)
            session = await stack.enter_async_context(ClientSession(read, write))
            await _initialize(session, target)
    except TargetUnreachable:
        await _close_quietly(stack)
        raise
    except (Exception, asyncio.CancelledError) as exc:
        await _close_quietly(stack)
        detail = str(exc).strip() or type(exc).__name__
        raise TargetUnreachable(f"{target.transport} connection failed: {detail}") from exc
    try:
        yield session
    finally:
        await stack.aclose()


async def _close_quietly(stack: AsyncExitStack) -> None:
    try:
        await stack.aclose()
    except BaseException:
        return


_Read = MemoryObjectReceiveStream[SessionMessage | Exception]
_Write = MemoryObjectSendStream[SessionMessage]


async def _open_transport(stack: AsyncExitStack, target: TargetConfig) -> tuple[_Read, _Write]:
    if target.transport == "stdio":
        if not target.command:
            raise TargetUnreachable("stdio target has no command")
        params = StdioServerParameters(
            command=target.command,
            args=list(target.args),
            env=_stdio_env(target.env),
        )
        read, write = await stack.enter_async_context(stdio_client(params))
        return cast(_Read, read), cast(_Write, write)
    if target.transport == "streamable_http":
        if not target.url:
            raise TargetUnreachable("streamable_http target has no url")
        streams = await stack.enter_async_context(
            streamablehttp_client(target.url, headers=dict(target.headers))
        )
        return streams[0], streams[1]
    if not target.url:
        raise TargetUnreachable("sse target has no url")
    read, write = await stack.enter_async_context(
        sse_client(target.url, headers=dict(target.headers))
    )
    return cast(_Read, read), cast(_Write, write)


async def _initialize(session: ClientSession, target: TargetConfig) -> None:
    result = await session.initialize()
    command = target.command or ""
    endpoint = Path(command).name if target.transport == "stdio" else (target.url or "")
    bind_server_info(
        session,
        ServerInfo(
            name=result.serverInfo.name,
            version=result.serverInfo.version,
            protocol_version=str(result.protocolVersion),
            transport=target.transport,
            endpoint=endpoint,
        ),
    )


def _stdio_env(overrides: dict[str, str]) -> dict[str, str] | None:
    """Keep the SDK default environment and overlay configured variables."""
    if not overrides:
        return None
    env = get_default_environment()
    env.update(overrides)
    return env
