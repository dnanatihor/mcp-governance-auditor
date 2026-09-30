"""Graph state (§7.2). Values are serialisable and already masked."""

from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from mcp_gov_audit.models import (
    AuditMetrics,
    FieldClassification,
    FieldObservation,
    Finding,
    ObjectObservation,
    ProbeEnvelope,
    ProbeRequest,
    ProbeResult,
    ReviewDecision,
    ServerInfo,
    ToolDescriptor,
)


def upsert_findings(left: list[Finding], right: list[Finding]) -> list[Finding]:
    merged = {finding.finding_id: finding for finding in left}
    for finding in right:
        merged[finding.finding_id] = finding
    return list(merged.values())


class AuditState(TypedDict, total=False):
    run_id: str
    started_at: str
    server_info: ServerInfo
    tools: list[ToolDescriptor]
    probe_plan: list[ProbeRequest]
    probes: Annotated[list[ProbeResult], operator.add]
    envelopes: list[ProbeEnvelope]
    fields: list[FieldObservation]
    objects: list[ObjectObservation]
    classifications: list[FieldClassification]
    findings: Annotated[list[Finding], upsert_findings]
    metrics: AuditMetrics
    review_decisions: list[ReviewDecision]
    report_paths: dict[str, str]
    errors: Annotated[list[str], operator.add]
