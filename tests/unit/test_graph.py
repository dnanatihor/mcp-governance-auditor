"""Graph routing, the call_tool invariant, and concurrency."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import Any, cast

import mcp.types as types
import pytest
from mcp import ClientSession
from tests.helpers import ROOT

from mcp_gov_audit.classification.cache import ClassificationCache
from mcp_gov_audit.config import load_config
from mcp_gov_audit.context import AuditContext
from mcp_gov_audit.graph.builder import build_graph, route_probes
from mcp_gov_audit.graph.nodes import classify, probe_tool
from mcp_gov_audit.mcp_client.session import bind_server_info
from mcp_gov_audit.models import FieldObservation, Layer, ProbeRequest, ServerInfo, ToolDescriptor
from mcp_gov_audit.rules.base import finding_id

_ASSET = {
    "type": "object",
    "properties": {"asset_id": {"type": "string"}},
    "required": ["asset_id"],
}
_EMPTY = {"type": "object", "properties": {}}


def test_empty_plan_routes_to_normalize() -> None:
    assert route_probes({}) == "normalize"
    assert route_probes({"probe_plan": []}) == "normalize"


def test_non_empty_plan_sends_one_payload_per_request() -> None:
    request = ProbeRequest(
        probe_id="list_assets#0",
        tool_name="list_assets",
        arguments={},
        input_source="empty",
    )
    routed = route_probes({"probe_plan": [request]})
    assert isinstance(routed, list)
    assert routed[0].node == "probe_tool"
    assert routed[0].arg == {"request": request}


def test_call_tool_is_only_invoked_from_call_tool_safely() -> None:
    root = ROOT / "src"
    call_sites = [
        path.relative_to(root).as_posix()
        for path in root.rglob("*.py")
        if "session.call_tool(" in path.read_text(encoding="utf-8")
    ]
    safely_sites = [
        path.relative_to(root).as_posix()
        for path in root.rglob("*.py")
        if "call_tool_safely(" in path.read_text(encoding="utf-8")
    ]
    assert sorted(call_sites) == ["mcp_gov_audit/mcp_client/operations.py"]
    assert sorted(safely_sites) == [
        "mcp_gov_audit/graph/nodes.py",
        "mcp_gov_audit/mcp_client/operations.py",
    ]


def test_finding_id_ignores_line_numbers() -> None:
    first = finding_id(rule_id="COV-002", tool_name="slow_lookup")
    second = finding_id(rule_id="COV-002", tool_name="slow_lookup", normalized_path=None)
    assert first == second
    assert len(first) == 16


class _RecordingSession:
    def __init__(self, tools: list[types.Tool]) -> None:
        self.tools = tools
        self.calls: list[tuple[float, float, str]] = []

    async def list_tools(
        self,
        cursor: str | None = None,
        *,
        params: types.PaginatedRequestParams | None = None,
    ) -> types.ListToolsResult:
        del cursor, params
        return types.ListToolsResult(tools=self.tools)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        **_: Any,
    ) -> types.CallToolResult:
        del arguments
        started = time.perf_counter()
        await asyncio.sleep(0.05)
        finished = time.perf_counter()
        self.calls.append((started, finished, name))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text='{"ok": true}')],
            structuredContent={"ok": True},
            isError=False,
        )


def _tool(name: str, schema: dict[str, Any], *, read_only: bool | None) -> types.Tool:
    annotations = None if read_only is None else types.ToolAnnotations(readOnlyHint=read_only)
    return types.Tool(name=name, description=name, inputSchema=schema, annotations=annotations)


def _context(
    tmp_path: Path,
    session: object,
    *,
    mode: str = "safe",
    concurrency: int = 1,
) -> AuditContext:
    loaded = load_config(ROOT / "tests" / "fixtures" / "audit.fixture.yaml")
    audit = loaded.audit.model_copy(
        update={
            "probing": loaded.audit.probing.model_copy(update={"mode": mode}),
            "run": loaded.audit.run.model_copy(update={"max_concurrency": concurrency}),
            "output": loaded.audit.output.model_copy(update={"save_raw": False}),
        }
    )
    bind_server_info(
        session,
        ServerInfo(
            name="fake",
            version="0",
            protocol_version="2025-06-18",
            transport="stdio",
            endpoint="fake",
        ),
    )
    return AuditContext(
        config=audit,
        policy=loaded.policy,
        policy_sha256="abc",
        session=cast(ClientSession, session),
        classifier=None,
        planner=None,
        cache=ClassificationCache(tmp_path),
        semaphore=asyncio.Semaphore(concurrency),
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
        run_dir=tmp_path,
        fixtures=loaded.probe_fixtures,
    )


@pytest.mark.asyncio
async def test_empty_plan_reaches_normalize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    session = _RecordingSession([_tool("get_column_quality", _ASSET, read_only=True)])
    graph = build_graph()
    state = await graph.ainvoke({}, context=_context(tmp_path, session, mode="off"))
    assert state["envelopes"] == []
    assert state["fields"] == []
    assert state["objects"] == []
    assert session.calls == []
    assert state["probe_plan"] == []


@pytest.mark.asyncio
async def test_max_concurrency_one_does_not_overlap_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    session = _RecordingSession(
        [
            _tool("alpha", _EMPTY, read_only=True),
            _tool("beta", _EMPTY, read_only=True),
        ]
    )
    graph = build_graph()
    await graph.ainvoke({}, context=_context(tmp_path, session, concurrency=1))
    assert [name for _, _, name in session.calls] == ["alpha", "beta"]
    ordered = sorted(session.calls)
    for earlier, later in pairwise(ordered):
        assert earlier[1] <= later[0]


@pytest.mark.asyncio
async def test_probe_tool_refuses_a_tool_that_is_not_probe(tmp_path: Path) -> None:
    session = _RecordingSession([])
    context = _context(tmp_path, session)
    context.tools_by_name = {
        "delete_asset": ToolDescriptor(
            name="delete_asset",
            input_schema=_ASSET,
            probe_decision="skip_destructive",
        )
    }
    request = ProbeRequest(
        probe_id="delete_asset#0",
        tool_name="delete_asset",
        arguments={"asset_id": "x"},
        input_source="fixture",
    )
    result = await probe_tool({"request": request}, _runtime(context))
    assert session.calls == []
    assert result["errors"]
    assert "probes" not in result


@pytest.mark.asyncio
async def test_missing_classifier_marks_unmatched_leaves_unknown(tmp_path: Path) -> None:
    session = _RecordingSession([])
    context = _context(tmp_path, session)
    assert context.config.llm.enabled is True
    assert context.classifier is None
    field = FieldObservation(
        probe_id="p",
        tool_name="tool",
        concrete_path="$.zzz",
        normalized_path="$.zzz",
        parent_path="$",
        key="zzz",
        value_type="string",
        value_preview="x",
        value_length=1,
        container_layer=None,
        field_label=None,
        sibling_keys=("zzz",),
        is_structural=False,
    )
    result = await classify({"fields": [field], "tools": []}, _runtime(context))
    [item] = result["classifications"]
    assert item.layer == Layer.UNKNOWN
    assert item.method == "none"
    assert item.evidence == "no deterministic match"


def _runtime(context: AuditContext) -> Any:
    from langgraph.runtime import Runtime

    return Runtime(context=context)
