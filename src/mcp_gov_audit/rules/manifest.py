"""MAN-001 through MAN-003 (§11.3)."""

from __future__ import annotations

from typing import Literal

from mcp_gov_audit.models import Finding, Severity
from mcp_gov_audit.rules.base import RuleContext, finding_id, register_rule

Scope = Literal["manifest"]


def _finding(
    *,
    rule_id: str,
    rule_name: str,
    severity: Severity,
    tool_name: str,
    evidence: str,
    remediation: str,
) -> Finding:
    return Finding(
        finding_id=finding_id(rule_id=rule_id, tool_name=tool_name),
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        scope="manifest",
        tool_name=tool_name,
        evidence=evidence,
        remediation=remediation,
        basis="deterministic",
        needs_human_review=False,
    )


@register_rule
class MissingOutputSchema:
    id = "MAN-001"
    name = "Missing outputSchema on inference-risk tool"
    default_severity = Severity.MEDIUM
    scope: Scope = "manifest"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        flag = ctx.policy.envelope.inference_flag_key
        findings: list[Finding] = []
        for tool in ctx.tools:
            if not tool.inference_risk or tool.output_schema is not None:
                continue
            findings.append(
                _finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    tool_name=tool.name,
                    evidence="inference_risk is true and outputSchema is absent.",
                    remediation=(
                        f"Declare an outputSchema for `{tool.name}` that models the layer "
                        f"containers and `{flag}`."
                    ),
                )
            )
        return findings


@register_rule
class OutputSchemaOmitsFlag:
    id = "MAN-002"
    name = "outputSchema omits inference flag"
    default_severity = Severity.MEDIUM
    scope: Scope = "manifest"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        flag = ctx.policy.envelope.inference_flag_key
        findings: list[Finding] = []
        for tool in ctx.tools:
            schema = tool.output_schema
            if not tool.inference_risk or schema is None:
                continue
            properties = schema.get("properties")
            if isinstance(properties, dict) and flag in properties:
                continue
            findings.append(
                _finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    tool_name=tool.name,
                    evidence=f"outputSchema root properties omit {flag}.",
                    remediation=(
                        f"Add `{flag}` to the root properties of `{tool.name}`'s outputSchema."
                    ),
                )
            )
        return findings


@register_rule
class MissingSafetyAnnotations:
    id = "MAN-003"
    name = "Missing safety annotations"
    default_severity = Severity.LOW
    scope: Scope = "manifest"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            annotations = tool.annotations
            if annotations is not None and (
                "readOnlyHint" in annotations or "destructiveHint" in annotations
            ):
                continue
            findings.append(
                _finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    tool_name=tool.name,
                    evidence="Tool annotations omit readOnlyHint and destructiveHint.",
                    remediation=(
                        f"Annotate `{tool.name}` with `readOnlyHint` / `destructiveHint` so "
                        "clients and auditors can reason about side effects."
                    ),
                )
            )
        return findings
