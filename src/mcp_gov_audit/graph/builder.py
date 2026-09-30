"""Audit graph through reports and optional human review (§7.1, §13)."""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Checkpointer, Send

from mcp_gov_audit.context import AuditContext
from mcp_gov_audit.graph.nodes import (
    aggregate,
    classify,
    evaluate_rules_node,
    human_review,
    introspect,
    normalize,
    plan_probes_node,
    probe_tool,
    render_reports,
    static_scan,
    triage,
)
from mcp_gov_audit.graph.state import AuditState


def route_probes(state: AuditState) -> str | list[Send]:
    """Empty plans go to normalize. An empty Send list would end the run."""
    plan = state.get("probe_plan", [])
    if not plan:
        return "normalize"
    return [Send("probe_tool", {"request": request}) for request in plan]


def build_graph(
    *,
    static_only: bool = False,
    scan_after_rules: bool = False,
    review_enabled: bool = False,
    checkpointer: Checkpointer = None,
) -> CompiledStateGraph[AuditState, AuditContext, AuditState, AuditState]:
    """Compile the graph through rendering. Review pauses when it is enabled."""

    def route_start(state: AuditState) -> str:
        del state
        if static_only:
            return "static_scan"
        return "introspect"

    def route_after_rules(state: AuditState) -> str:
        del state
        if scan_after_rules:
            return "static_scan"
        return "aggregate"

    def route_review(state: AuditState) -> str:
        if review_enabled and _has_pending(state):
            return "human_review"
        return "render_reports"

    builder: StateGraph[AuditState, AuditContext] = StateGraph(
        AuditState, context_schema=AuditContext
    )
    builder.add_node("introspect", introspect)
    builder.add_node("triage", triage)
    builder.add_node("plan_probes", plan_probes_node)
    builder.add_node("probe_tool", probe_tool)
    builder.add_node("normalize", normalize)
    builder.add_node("classify", classify)
    builder.add_node("evaluate_rules", evaluate_rules_node)
    builder.add_node("static_scan", static_scan)
    builder.add_node("aggregate", aggregate)
    builder.add_node("human_review", human_review)
    builder.add_node("render_reports", render_reports)
    builder.add_conditional_edges(START, route_start, ["introspect", "static_scan"])
    builder.add_edge("introspect", "triage")
    builder.add_edge("triage", "plan_probes")
    builder.add_conditional_edges("plan_probes", route_probes, ["probe_tool", "normalize"])
    builder.add_edge("probe_tool", "normalize")
    builder.add_edge("normalize", "classify")
    builder.add_edge("classify", "evaluate_rules")
    builder.add_conditional_edges("evaluate_rules", route_after_rules, ["static_scan", "aggregate"])
    builder.add_edge("static_scan", "aggregate")
    builder.add_conditional_edges("aggregate", route_review, ["human_review", "render_reports"])
    builder.add_edge("human_review", "render_reports")
    builder.add_edge("render_reports", END)
    return builder.compile(checkpointer=checkpointer)


def _has_pending(state: AuditState) -> bool:
    return any(finding.review_status == "pending" for finding in state.get("findings", []))
