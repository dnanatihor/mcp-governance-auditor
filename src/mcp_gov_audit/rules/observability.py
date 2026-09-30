"""OBS-001 and OBS-002 (§12). Decisions are pure; parsing lives in static/."""

from __future__ import annotations

from typing import Literal

from mcp_gov_audit.models import Finding, Occurrence, Severity
from mcp_gov_audit.rules.base import RuleContext, finding_id, register_rule
from mcp_gov_audit.static.python_ast import ClientSite, FlushSite

_OBS001_REMEDIATION = (
    "Instrument httpx globally with `HTTPXClientInstrumentor().instrument()` at startup, "
    "or inject trace context into outbound request headers."
)
_OBS002_REMEDIATION = (
    "For a long-running server, export telemetry through batch processors with scheduled "
    "export and reserve `force_flush()` / `shutdown()` for process shutdown hooks."
)


@register_rule
class UninstrumentedHttpClient:
    id = "OBS-001"
    name = "Uninstrumented downstream HTTP client"
    default_severity = Severity.MEDIUM
    scope: Literal["static"] = "static"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        analysis = ctx.static_analysis
        if analysis is None or analysis.repo_instrumented:
            return []
        findings: list[Finding] = []
        for module in analysis.modules:
            if module.has_propagate_inject:
                continue
            mitigated = set(module.mitigated_variables)
            for site in module.clients:
                if site.variable is not None and site.variable in mitigated:
                    continue
                findings.append(_client_finding(self, site))
        return _collapse(findings)


@register_rule
class FlushDependentExport:
    id = "OBS-002"
    name = "Flush-dependent telemetry export"
    default_severity = Severity.MEDIUM
    scope: Literal["static"] = "static"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        analysis = ctx.static_analysis
        if analysis is None:
            return []
        findings: list[Finding] = []
        for site in analysis.flush_sites:
            if site.context == "other":
                continue
            if site.context == "exit_only" and analysis.has_batch_processor:
                continue
            findings.append(_flush_finding(self, site))
        return _collapse(findings)


def _client_finding(rule: UninstrumentedHttpClient, site: ClientSite) -> Finding:
    return Finding(
        finding_id=finding_id(rule_id=rule.id, file_path=site.file_path, symbol=site.symbol),
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.default_severity,
        scope=rule.scope,
        file_path=site.file_path,
        symbol=site.symbol,
        evidence=site.callee,
        remediation=_OBS001_REMEDIATION,
        basis="deterministic",
        needs_human_review=False,
        occurrences=(Occurrence(line=site.line, detail=site.callee),),
    )


def _flush_finding(rule: FlushDependentExport, site: FlushSite) -> Finding:
    return Finding(
        finding_id=finding_id(rule_id=rule.id, file_path=site.file_path, symbol=site.symbol),
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.default_severity,
        scope=rule.scope,
        file_path=site.file_path,
        symbol=site.symbol,
        evidence=site.context,
        remediation=_OBS002_REMEDIATION,
        basis="heuristic",
        needs_human_review=True,
        review_status="pending",
        occurrences=(Occurrence(line=site.line, detail=site.context),),
    )


def _collapse(findings: list[Finding]) -> list[Finding]:
    """One finding id can cover several sites. Occurrences keep each line."""
    grouped: dict[str, Finding] = {}
    for finding in findings:
        current = grouped.get(finding.finding_id)
        if current is None:
            grouped[finding.finding_id] = finding
            continue
        evidence = _merged_evidence(current.evidence, finding.evidence)
        grouped[finding.finding_id] = current.model_copy(
            update={
                "evidence": evidence,
                "occurrences": (*current.occurrences, *finding.occurrences)[:10],
            }
        )
    return list(grouped.values())


def _merged_evidence(current: str, incoming: str) -> str:
    if incoming == "per_request" or current == "per_request":
        return "per_request"
    parts = list(dict.fromkeys((*current.split(", "), incoming)))
    return ", ".join(parts)


_OBS003_REMEDIATION = (
    "Instrument this HTTP client with OpenTelemetry, or propagate the active trace context "
    "on outbound requests."
)


@register_rule
class UninstrumentedOtherHttpClient:
    id = "OBS-003"
    name = "Uninstrumented HTTP client"
    default_severity = Severity.MEDIUM
    scope: Literal["static"] = "static"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        analysis = ctx.static_analysis
        if analysis is None:
            return []
        findings: list[Finding] = []
        for site in analysis.other_clients:
            findings.append(
                Finding(
                    finding_id=finding_id(
                        rule_id=self.id, file_path=site.file_path, symbol=site.language
                    ),
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    scope=self.scope,
                    file_path=site.file_path,
                    symbol=site.language,
                    evidence=site.callee,
                    remediation=_OBS003_REMEDIATION,
                    basis="deterministic",
                    needs_human_review=False,
                    occurrences=(Occurrence(line=site.line, detail=site.callee),),
                )
            )
        return _collapse(findings)
