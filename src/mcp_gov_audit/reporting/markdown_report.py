"""report.md from templates/report.md.j2 (§13.3)."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, StrictUndefined

from mcp_gov_audit.models import ProbeResult, Severity
from mcp_gov_audit.reporting.json_report import Report
from mcp_gov_audit.rules import REGISTRY

_TEMPLATE = Path(__file__).resolve().parent / "templates" / "report.md.j2"
_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def render_markdown(report: Report, probes: list[ProbeResult]) -> str:
    """Render the seven report sections."""
    environment = Environment(undefined=StrictUndefined, autoescape=False)
    template = environment.from_string(_TEMPLATE.read_text(encoding="utf-8"))
    return template.render(**_context(report, probes))


def _context(report: Report, probes: list[ProbeResult]) -> dict[str, object]:
    response = [item for item in report.findings if item.scope != "static"]
    groups: list[dict[str, object]] = []
    for severity in _SEVERITY_ORDER:
        matched = [item for item in response if item.severity == severity]
        if not matched:
            continue
        rules: list[dict[str, object]] = []
        for rule_id in sorted({item.rule_id for item in matched}):
            members = [item for item in matched if item.rule_id == rule_id]
            rules.append(
                {
                    "rule_id": rule_id,
                    "rule_name": members[0].rule_name,
                    "items": [_finding_item(item) for item in members],
                }
            )
        groups.append({"severity": severity.value, "rules": rules})
    catalog = [
        {
            "id": rule.id,
            "name": rule.name,
            "scope": rule.scope,
            "default_severity": rule.default_severity.value,
        }
        for rule in sorted(REGISTRY.values(), key=lambda item: item.id)
    ]
    return {
        "verdict": report.run.verdict,
        "fail_on": report.run.fail_on,
        "severity": report.summary.by_severity,
        "metrics": _metric_cells(report),
        "server_name": report.target.server_name or "unknown",
        "server_version": report.target.server_version or "",
        "transport": report.target.transport,
        "endpoint": report.target.endpoint,
        "protocol_version": report.target.protocol_version or "",
        "classifier_model": report.run.models.classifier,
        "planner_model": report.run.models.planner,
        "classify_prompt": report.run.prompt_versions.classify_field,
        "planner_prompt": report.run.prompt_versions.generate_probe_input,
        "policy_version": report.run.policy_version,
        "policy_sha256": report.run.policy_sha256,
        "run_id": report.run.run_id,
        "started_at": report.run.started_at,
        "finished_at": report.run.finished_at,
        "auditor_version": report.run.auditor_version,
        "llm_enabled": report.run.llm_enabled,
        "coverage_rows": _coverage_rows(report, probes),
        "distribution_rows": [
            {
                "tool": tool.name,
                "certified": tool.epistemic_distribution.certified,
                "observed": tool.epistemic_distribution.observed,
                "inferred": tool.epistemic_distribution.inferred,
                "unknown": tool.epistemic_distribution.unknown,
            }
            for tool in report.tools
        ],
        "finding_groups": groups,
        "static_findings": _static_rows(report),
        "catalog": catalog,
    }


def _metric_cells(report: Report) -> dict[str, str]:
    values = report.metrics.model_dump()
    return {key: "null" if value is None else str(value) for key, value in values.items()}


def _coverage_rows(report: Report, probes: list[ProbeResult]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for tool in report.tools:
        matched = [probe for probe in probes if probe.tool_name == tool.name]
        rows.append(
            {
                "tool": tool.name,
                "decision": tool.probe_decision or "",
                "ok": sum(1 for probe in matched if probe.status == "ok"),
                "failed": sum(1 for probe in matched if probe.status != "ok"),
                "risk": tool.risk_score,
            }
        )
    return rows


def _finding_item(finding: object) -> dict[str, str]:
    from mcp_gov_audit.models import Finding

    if not isinstance(finding, Finding):
        raise TypeError("expected a finding")
    where = finding.tool_name or finding.file_path or "—"
    if finding.normalized_path:
        where = f"{where} {finding.normalized_path}"
    return {
        "where": where,
        "basis": finding.basis,
        "review_status": finding.review_status,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
    }


def _static_rows(report: Report) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for finding in report.findings:
        if finding.scope != "static":
            continue
        if finding.occurrences:
            for occurrence in finding.occurrences:
                location = finding.file_path or ""
                if occurrence.line is not None:
                    location = f"{location}:{occurrence.line}"
                rows.append(
                    {
                        "location": location,
                        "symbol": finding.symbol or "<module>",
                        "rule_id": finding.rule_id,
                        "evidence": finding.evidence,
                    }
                )
        else:
            rows.append(
                {
                    "location": finding.file_path or "",
                    "symbol": finding.symbol or "<module>",
                    "rule_id": finding.rule_id,
                    "evidence": finding.evidence,
                }
            )
    return rows
