"""Rule protocol, registry, and finding ids (§11.1)."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Literal, Protocol

from pydantic import BaseModel

from mcp_gov_audit.config import Policy
from mcp_gov_audit.models import (
    FieldClassification,
    FieldObservation,
    Finding,
    ObjectObservation,
    Occurrence,
    ProbeEnvelope,
    ProbeResult,
    Severity,
    ToolDescriptor,
)
from mcp_gov_audit.static.python_ast import StaticAnalysis


class RuleContext(BaseModel):
    tools: list[ToolDescriptor]
    probes: list[ProbeResult]
    envelopes: list[ProbeEnvelope]
    fields: list[FieldObservation]
    objects: list[ObjectObservation]
    classifications: list[FieldClassification]
    policy: Policy
    now: datetime
    static_analysis: StaticAnalysis | None = None
    remote_auth_configured: bool | None = None


class Rule(Protocol):
    id: str
    name: str
    default_severity: Severity
    scope: Literal["manifest", "response", "coverage", "static"]

    def evaluate(self, ctx: RuleContext) -> list[Finding]: ...


REGISTRY: dict[str, Rule] = {}


def register_rule(rule_cls: type[Any]) -> type[Any]:
    """Register a rule class. Duplicate ids fail at import time."""
    rule = rule_cls()
    rule_id = str(rule.id)
    if rule_id in REGISTRY:
        raise RuntimeError(f"duplicate rule id {rule_id}")
    REGISTRY[rule_id] = rule
    return rule_cls


def finding_id(
    *,
    rule_id: str,
    tool_name: str | None = None,
    normalized_path: str | None = None,
    file_path: str | None = None,
    symbol: str | None = None,
) -> str:
    """Stable id. Line numbers are not part of the hash."""
    raw = "|".join(
        (
            rule_id,
            tool_name or "",
            normalized_path or "",
            file_path or "",
            symbol or "",
        )
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def evaluate_rules(ctx: RuleContext, *, rule_ids: tuple[str, ...] | None = None) -> list[Finding]:
    """Run rules, apply two-pass basis for response rules, then policy post-processing."""
    if rule_ids is None:
        selected = list(REGISTRY.values())
    else:
        selected = [REGISTRY[rule_id] for rule_id in rule_ids]
    response = [rule for rule in selected if rule.scope == "response"]
    other = [rule for rule in selected if rule.scope != "response"]
    produced: list[Finding] = []
    for rule in other:
        produced.extend(rule.evaluate(ctx))
    pass1 = ctx.model_copy(
        update={
            "classifications": [item for item in ctx.classifications if item.method != "llm"],
        }
    )
    pass1_findings = [finding for rule in response for finding in rule.evaluate(pass1)]
    pass1_ids = {finding.finding_id for finding in pass1_findings}
    pass2_findings = [finding for rule in response for finding in rule.evaluate(ctx)]
    produced.extend(_with_basis(finding, "deterministic") for finding in pass1_findings)
    for finding in pass2_findings:
        if finding.finding_id in pass1_ids:
            continue
        produced.append(_with_basis(finding, "llm_assisted"))
    return [_apply_policy(finding, ctx.policy) for finding in _merge(produced)]


def _with_basis(finding: Finding, basis: Literal["deterministic", "llm_assisted"]) -> Finding:
    if basis == "deterministic":
        return finding.model_copy(update={"basis": "deterministic"})
    severity = finding.severity
    if severity.rank() > Severity.HIGH.rank():
        severity = Severity.HIGH
    return finding.model_copy(
        update={
            "basis": "llm_assisted",
            "severity": severity,
            "needs_human_review": True,
            "review_status": "pending",
        }
    )


def _apply_policy(finding: Finding, policy: Policy) -> Finding:
    severity = policy.severity_overrides.get(finding.rule_id, finding.severity)
    refs = tuple(policy.framework_refs.get(finding.rule_id, ()))
    if severity == finding.severity and refs == finding.framework_refs:
        return finding
    return finding.model_copy(update={"severity": severity, "framework_refs": refs})


def _merge(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for finding in findings:
        current = merged.get(finding.finding_id)
        if current is None:
            merged[finding.finding_id] = finding.model_copy(
                update={"occurrences": finding.occurrences[:10]}
            )
            continue
        seen = {
            (item.probe_id, item.concrete_path, item.line, item.detail)
            for item in current.occurrences
        }
        combined: list[Occurrence] = list(current.occurrences)
        for item in finding.occurrences:
            key = (item.probe_id, item.concrete_path, item.line, item.detail)
            if key in seen:
                continue
            seen.add(key)
            combined.append(item)
        merged[finding.finding_id] = current.model_copy(
            update={"occurrences": tuple(combined[:10])}
        )
    return list(merged.values())
