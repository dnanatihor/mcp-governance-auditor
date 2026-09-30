"""COV-001, COV-002, and COV-003 (§11.3)."""

from __future__ import annotations

from typing import Literal

from mcp_gov_audit.models import Finding, Occurrence, Severity
from mcp_gov_audit.rules.base import RuleContext, finding_id, register_rule


@register_rule
class ToolNotProbed:
    id = "COV-001"
    name = "Tool not probed"
    default_severity = Severity.INFO
    scope: Literal["coverage"] = "coverage"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            if tool.probe_decision == "probe":
                continue
            decision = tool.probe_decision or ""
            findings.append(
                Finding(
                    finding_id=finding_id(rule_id=self.id, tool_name=tool.name),
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    scope=self.scope,
                    tool_name=tool.name,
                    evidence=decision,
                    remediation=(
                        f"Provide a probe input that passes the safety policy for {tool.name}, "
                        f"or accept that it stays unprobed ({decision})."
                    ),
                    basis="deterministic",
                    needs_human_review=False,
                )
            )
        return findings


@register_rule
class ProbeFailed:
    id = "COV-002"
    name = "Probe failed"
    default_severity = Severity.INFO
    scope: Literal["coverage"] = "coverage"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        failed: dict[str, list[Occurrence]] = {}
        for probe in ctx.probes:
            if probe.status == "ok":
                continue
            if probe.error_message:
                detail = f"{probe.status}: {probe.error_message}"
            else:
                detail = probe.status
            failed.setdefault(probe.tool_name, []).append(
                Occurrence(probe_id=probe.probe_id, detail=detail)
            )
        findings: list[Finding] = []
        for tool_name, occurrences in failed.items():
            findings.append(
                Finding(
                    finding_id=finding_id(rule_id=self.id, tool_name=tool_name),
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    scope=self.scope,
                    tool_name=tool_name,
                    evidence="; ".join(item.detail or "" for item in occurrences),
                    remediation=(
                        f"Investigate the failed probe of {tool_name} "
                        "and make it return successfully."
                    ),
                    basis="deterministic",
                    needs_human_review=False,
                    occurrences=tuple(occurrences),
                )
            )
        return findings


@register_rule
class ResponseTruncated:
    id = "COV-003"
    name = "Response truncated"
    default_severity = Severity.INFO
    scope: Literal["coverage"] = "coverage"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for envelope in ctx.envelopes:
            if not envelope.truncated or envelope.tool_name in seen:
                continue
            seen.add(envelope.tool_name)
            findings.append(
                Finding(
                    finding_id=finding_id(rule_id=self.id, tool_name=envelope.tool_name),
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    scope=self.scope,
                    tool_name=envelope.tool_name,
                    evidence="A probe response exceeded the field cap and was truncated.",
                    remediation=(
                        f"Reduce the payload of {envelope.tool_name} or raise the field cap "
                        "so the audit can see every leaf."
                    ),
                    basis="deterministic",
                    needs_human_review=False,
                    occurrences=(Occurrence(probe_id=envelope.probe_id, detail="truncated"),),
                )
            )
        return findings
