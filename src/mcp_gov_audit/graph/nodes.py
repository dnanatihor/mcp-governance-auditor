"""Thin graph nodes. Service functions do the work."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict, TypeVar

from langgraph.runtime import Runtime
from pydantic import BaseModel

from mcp_gov_audit.classification.deterministic import classify_deterministic
from mcp_gov_audit.classification.llm import classify_with_model
from mcp_gov_audit.context import AuditContext
from mcp_gov_audit.flatten import normalize_probe
from mcp_gov_audit.graph.state import AuditState
from mcp_gov_audit.mcp_client.operations import call_tool_safely, list_all_tools
from mcp_gov_audit.mcp_client.session import server_info_for
from mcp_gov_audit.models import (
    AuditMetrics,
    FieldClassification,
    FieldObservation,
    Finding,
    ProbeEnvelope,
    ProbeRequest,
    ProbeResult,
    ServerInfo,
    ToolDescriptor,
)
from mcp_gov_audit.probing import plan_probes
from mcp_gov_audit.redaction import mask_probe_result
from mcp_gov_audit.rules.base import RuleContext, evaluate_rules
from mcp_gov_audit.triage import triage_tools


async def introspect(state: AuditState, runtime: Runtime[AuditContext]) -> dict[str, Any]:
    """Reads: —. Writes: server_info, tools. Spec §8."""
    del state
    session = runtime.context.session
    if session is None:
        return {"errors": ["introspect requires an MCP session"]}
    tools = await list_all_tools(session)
    return {"server_info": server_info_for(session), "tools": tools}


async def triage(state: AuditState, runtime: Runtime[AuditContext]) -> dict[str, Any]:
    """Reads: tools. Writes: tools. Spec §9.1-9.2."""
    tools = triage_tools(
        list(state.get("tools", [])),
        runtime.context.config.probing,
        runtime.context.policy,
    )
    return {"tools": tools}


async def plan_probes_node(state: AuditState, runtime: Runtime[AuditContext]) -> dict[str, Any]:
    """Reads: tools. Writes: probe_plan, tools. Spec §9.3."""
    tools, requests = await plan_probes(
        list(state.get("tools", [])),
        runtime.context.fixtures,
        runtime.context.config.probing,
        planner=runtime.context.planner,
        llm_enabled=runtime.context.config.llm.enabled,
    )
    runtime.context.tools_by_name = {tool.name: tool for tool in tools}
    return {"tools": tools, "probe_plan": requests}


class ProbeToolInput(TypedDict):
    request: ProbeRequest


async def probe_tool(state: ProbeToolInput, runtime: Runtime[AuditContext]) -> dict[str, Any]:
    """Reads: Send payload request. Writes: probes, errors. Spec §9.4, §10.5."""
    request = _request(state)
    tool = runtime.context.tools_by_name.get(request.tool_name)
    decision = None if tool is None else tool.probe_decision
    if decision != "probe":
        return {
            "errors": [f"refused to call {request.tool_name}: probe_decision is {decision}"],
        }
    session = runtime.context.session
    if session is None:
        return {"errors": [f"refused to call {request.tool_name}: no MCP session"]}
    async with runtime.context.semaphore:
        captured = await call_tool_safely(
            session,
            request,
            runtime.context.config.run.tool_timeout_s,
            clock=runtime.context.clock,
        )
    masked = mask_probe_result(captured, runtime.context.config.redaction.extra_patterns)
    if runtime.context.config.output.save_raw:
        _write_raw(runtime, masked)
    return {"probes": [masked]}


async def normalize(state: AuditState, runtime: Runtime[AuditContext]) -> dict[str, Any]:
    """Reads: probes, tools. Writes: envelopes, fields, objects. Spec §10.1-10.2."""
    known = {tool.name for tool in state.get("tools", [])}
    config = runtime.context.config
    envelopes: list[Any] = []
    fields: list[Any] = []
    objects: list[Any] = []
    for probe in state.get("probes", []):
        if known and probe.tool_name not in known:
            continue
        normalized = normalize_probe(
            probe,
            runtime.context.policy,
            send_values=config.llm.send_values,
            max_value_chars=config.llm.max_value_chars,
        )
        if normalized is None:
            continue
        envelopes.append(normalized.envelope)
        fields.extend(normalized.fields)
        objects.extend(normalized.objects)
    return {"envelopes": envelopes, "fields": fields, "objects": objects}


async def classify(state: AuditState, runtime: Runtime[AuditContext]) -> dict[str, Any]:
    """Reads: fields, tools. Writes: classifications. Spec §10.3-10.4."""
    tools = list(state.get("tools", []))
    known = {tool.name for tool in tools}
    fields = [field for field in state.get("fields", []) if not known or field.tool_name in known]
    llm_enabled = runtime.context.config.llm.enabled and runtime.context.classifier is not None
    deterministic = classify_deterministic(
        fields,
        runtime.context.policy,
        llm_enabled=llm_enabled,
    )
    if not llm_enabled or runtime.context.classifier is None:
        return {"classifications": deterministic}
    classifications = await classify_with_model(
        fields=fields,
        deterministic=deterministic,
        tools=tools,
        classifier=runtime.context.classifier,
        cache=runtime.context.cache,
        batch_size=runtime.context.config.llm.batch_size,
        min_confidence=runtime.context.config.llm.min_confidence,
        crosscheck=runtime.context.config.llm.crosscheck_labelled_certified,
    )
    return {"classifications": classifications}


async def evaluate_rules_node(state: AuditState, runtime: Runtime[AuditContext]) -> dict[str, Any]:
    """Reads: tools, probes, envelopes, fields, objects, classifications. Writes: findings.

    Spec §11.
    """
    context = RuleContext(
        tools=list(state.get("tools", [])),
        probes=list(state.get("probes", [])),
        envelopes=list(state.get("envelopes", [])),
        fields=list(state.get("fields", [])),
        objects=list(state.get("objects", [])),
        classifications=list(state.get("classifications", [])),
        policy=runtime.context.policy,
        now=runtime.context.clock(),
        remote_auth_configured=_remote_auth(runtime),
    )
    return {"findings": evaluate_rules(context)}


async def static_scan(state: AuditState, runtime: Runtime[AuditContext]) -> dict[str, Any]:
    """Reads: —. Writes: findings. Spec §12."""
    del state
    from mcp_gov_audit.rules import REGISTRY
    from mcp_gov_audit.static.python_ast import analyze_repository

    config = runtime.context.config.static_scan
    analysis = analyze_repository(
        Path(config.repo_path),
        include=config.include,
        exclude=config.exclude,
        telemetry_flush_function_names=config.telemetry_flush_function_names,
        tool_decorator_patterns=config.tool_decorator_patterns,
    )
    context = RuleContext(
        tools=[],
        probes=[],
        envelopes=[],
        fields=[],
        objects=[],
        classifications=[],
        policy=runtime.context.policy,
        now=runtime.context.clock(),
        static_analysis=analysis,
    )
    findings: list[Finding] = []
    for rule_id in ("OBS-001", "OBS-002", "OBS-003"):
        findings.extend(REGISTRY[rule_id].evaluate(context))
    return {"findings": findings}


async def aggregate(state: AuditState, runtime: Runtime[AuditContext]) -> dict[str, Any]:
    """Reads: findings, classifications, tools, probes, envelopes. Writes: metrics.

    Spec §13.4.
    """
    del runtime
    from mcp_gov_audit.reporting.metrics import compute_metrics

    return {
        "metrics": compute_metrics(
            tools=_models(state.get("tools", []), ToolDescriptor),
            probes=_models(state.get("probes", []), ProbeResult),
            envelopes=_models(state.get("envelopes", []), ProbeEnvelope),
            fields=_models(state.get("fields", []), FieldObservation),
            classifications=_models(state.get("classifications", []), FieldClassification),
        )
    }


async def human_review(state: AuditState, runtime: Runtime[AuditContext]) -> dict[str, Any]:
    """Reads: findings. Writes: findings, review_decisions. Spec §13.6."""
    del runtime
    from langgraph.types import interrupt

    from mcp_gov_audit.reporting.review import apply_decisions, coerce_decisions

    findings = _models(state.get("findings", []), Finding)
    pending = [item for item in findings if item.review_status == "pending"]
    resumed = interrupt(
        {
            "run_id": state.get("run_id"),
            "findings": [item.model_dump(mode="json") for item in pending],
        }
    )
    decisions = coerce_decisions(resumed)
    return {
        "findings": apply_decisions(findings, decisions),
        "review_decisions": decisions,
    }


async def render_reports(state: AuditState, runtime: Runtime[AuditContext]) -> dict[str, Any]:
    """Reads: everything. Writes: report_paths. Spec §13."""
    from mcp_gov_audit.reporting.json_report import build_report, write_reports
    from mcp_gov_audit.reporting.metrics import compute_metrics

    tools = _models(state.get("tools", []), ToolDescriptor)
    probes = _models(state.get("probes", []), ProbeResult)
    envelopes = _models(state.get("envelopes", []), ProbeEnvelope)
    fields = _models(state.get("fields", []), FieldObservation)
    classifications = _models(state.get("classifications", []), FieldClassification)
    findings = _models(state.get("findings", []), Finding)
    raw_metrics = state.get("metrics")
    if isinstance(raw_metrics, AuditMetrics):
        metrics = raw_metrics
    else:
        metrics = compute_metrics(
            tools=tools,
            probes=probes,
            envelopes=envelopes,
            fields=fields,
            classifications=classifications,
        )
    finished = runtime.context.clock()
    started = state.get("started_at") or _iso(finished)
    report = build_report(
        run_id=state.get("run_id") or runtime.context.run_dir.name,
        started_at=started,
        finished_at=finished,
        config=runtime.context.config,
        policy=runtime.context.policy,
        policy_sha256=runtime.context.policy_sha256,
        server=_server(state.get("server_info")),
        tools=tools,
        probes=probes,
        findings=findings,
        classifications=classifications,
        metrics=metrics,
    )
    paths = write_reports(
        report,
        run_dir=runtime.context.run_dir,
        tools=tools,
        probes=probes,
    )
    return {"report_paths": paths}


def _request(state: ProbeToolInput) -> ProbeRequest:
    raw = state["request"]
    if isinstance(raw, ProbeRequest):
        return raw
    return ProbeRequest.model_validate(raw)


def _write_raw(runtime: Runtime[AuditContext], result: ProbeResult) -> None:
    directory = runtime.context.run_dir / "raw" / result.tool_name
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{result.probe_id}.json"
    path.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _models(raw: object, model: type[_ModelT]) -> list[_ModelT]:
    if not isinstance(raw, list):
        return []
    parsed: list[_ModelT] = []
    for item in raw:
        if isinstance(item, model):
            parsed.append(item)
        else:
            parsed.append(model.model_validate(item))
    return parsed


def _server(raw: object) -> ServerInfo | None:
    if isinstance(raw, ServerInfo):
        return raw
    if isinstance(raw, dict):
        return ServerInfo.model_validate(raw)
    return None


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _remote_auth(runtime: Runtime[AuditContext]) -> bool | None:
    from mcp_gov_audit.rules.security import remote_auth_configured

    return remote_auth_configured(runtime.context.config.target)
