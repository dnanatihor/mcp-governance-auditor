"""report.json and the committed schema (§13.2, §13.5)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from mcp_gov_audit import __version__
from mcp_gov_audit.classification.llm import CLASSIFY_PROMPT_VERSION, PLANNER_PROMPT_VERSION
from mcp_gov_audit.config import AuditConfig, Policy
from mcp_gov_audit.models import (
    AuditMetrics,
    FieldClassification,
    Finding,
    Frozen,
    ProbeResult,
    ServerInfo,
    Severity,
    ToolDescriptor,
)
from mcp_gov_audit.reporting.metrics import distribution_for

SCHEMA_VERSION = "1.0"


class ModelIds(Frozen):
    classifier: str
    planner: str


class PromptVersions(Frozen):
    classify_field: str
    generate_probe_input: str


class ReportRun(Frozen):
    run_id: str
    auditor_version: str
    started_at: str
    finished_at: str
    policy_version: str
    policy_sha256: str
    llm_enabled: bool
    models: ModelIds
    prompt_versions: PromptVersions
    verdict: str
    fail_on: str


class ReportTarget(Frozen):
    transport: str
    endpoint: str
    server_name: str | None = None
    server_version: str | None = None
    protocol_version: str | None = None


class ReportCoverage(Frozen):
    tools_total: int
    tools_probed: int
    tools_skipped: dict[str, int]
    probes_total: int
    probes_failed: int


class SeverityCounts(Frozen):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ReportSummary(Frozen):
    by_severity: SeverityCounts
    by_rule: dict[str, int]


class EpistemicDistribution(Frozen):
    certified: int = 0
    observed: int = 0
    inferred: int = 0
    unknown: int = 0


class ReportTool(Frozen):
    name: str
    risk_score: float
    inference_risk: bool
    probe_decision: str | None
    epistemic_distribution: EpistemicDistribution


class Report(Frozen):
    schema_version: str = SCHEMA_VERSION
    run: ReportRun
    target: ReportTarget
    coverage: ReportCoverage
    metrics: AuditMetrics
    summary: ReportSummary
    tools: list[ReportTool]
    findings: list[Finding]
    classifications: list[FieldClassification]


def report_json_schema() -> dict[str, object]:
    """Schema generated from `Report`. `schemas/report.v1.json` must match it."""
    return Report.model_json_schema()


def is_active(finding: Finding, *, fail_on_llm_assisted: bool) -> bool:
    """Dismissed findings are inactive. Pending llm-assisted findings are too, unless opted in."""
    pending_llm = (
        finding.basis == "llm_assisted"
        and finding.review_status == "pending"
        and not fail_on_llm_assisted
    )
    return finding.review_status != "dismissed" and not pending_llm


def run_exit_code(
    findings: list[Finding],
    *,
    fail_on: Severity,
    fail_on_llm_assisted: bool,
) -> int:
    """1 when an active finding is at or above `fail_on`, otherwise 0."""
    for finding in findings:
        if not is_active(finding, fail_on_llm_assisted=fail_on_llm_assisted):
            continue
        if finding.severity.rank() >= fail_on.rank():
            return 1
    return 0


def build_report(
    *,
    run_id: str,
    started_at: str,
    finished_at: datetime,
    config: AuditConfig,
    policy: Policy,
    policy_sha256: str,
    server: ServerInfo | None,
    tools: list[ToolDescriptor],
    probes: list[ProbeResult],
    findings: list[Finding],
    classifications: list[FieldClassification],
    metrics: AuditMetrics,
) -> Report:
    exit_code = run_exit_code(
        findings,
        fail_on=config.run.fail_on,
        fail_on_llm_assisted=config.run.fail_on_llm_assisted,
    )
    skipped: dict[str, int] = {}
    probed = 0
    for tool in tools:
        if tool.probe_decision == "probe":
            probed += 1
            continue
        key = tool.probe_decision or "undecided"
        skipped[key] = skipped.get(key, 0) + 1
    by_rule: dict[str, int] = {}
    counts = {level.value: 0 for level in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
    included = classifications if config.output.include_classifications else []
    return Report(
        run=ReportRun(
            run_id=run_id,
            auditor_version=__version__,
            started_at=started_at,
            finished_at=_iso(finished_at),
            policy_version=policy.policy_version,
            policy_sha256=policy_sha256,
            llm_enabled=config.llm.enabled,
            models=ModelIds(
                classifier=config.llm.classifier_model,
                planner=config.llm.planner_model,
            ),
            prompt_versions=_prompt_versions(),
            verdict="fail" if exit_code == 1 else "pass",
            fail_on=config.run.fail_on.value,
        ),
        target=_target(config, server),
        coverage=ReportCoverage(
            tools_total=len(tools),
            tools_probed=probed,
            tools_skipped=skipped,
            probes_total=len(probes),
            probes_failed=sum(1 for probe in probes if probe.status != "ok"),
        ),
        metrics=metrics,
        summary=ReportSummary(
            by_severity=SeverityCounts.model_validate(counts),
            by_rule=dict(sorted(by_rule.items())),
        ),
        tools=[
            ReportTool(
                name=tool.name,
                risk_score=tool.risk_score,
                inference_risk=tool.inference_risk,
                probe_decision=tool.probe_decision,
                epistemic_distribution=EpistemicDistribution.model_validate(
                    distribution_for(tool.name, classifications)
                ),
            )
            for tool in tools
        ],
        findings=findings,
        classifications=included,
    )


def write_reports(
    report: Report,
    *,
    run_dir: Path,
    tools: list[ToolDescriptor],
    probes: list[ProbeResult],
) -> dict[str, str]:
    """Write report.json, report.md, and manifest.json."""
    from mcp_gov_audit.reporting.markdown_report import render_markdown

    run_dir.mkdir(parents=True, exist_ok=True)
    json_path = run_dir / "report.json"
    markdown_path = run_dir / "report.md"
    manifest_path = run_dir / "manifest.json"
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(report, probes), encoding="utf-8")
    manifest_path.write_text(
        json.dumps(
            [tool.model_dump(mode="json") for tool in tools],
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "json": str(json_path),
        "markdown": str(markdown_path),
        "manifest": str(manifest_path),
    }


def load_report(path: Path) -> Report:
    return Report.model_validate_json(path.read_text(encoding="utf-8"))


def endpoint_for(config: AuditConfig, server: ServerInfo | None) -> str:
    if server is not None and server.endpoint:
        return server.endpoint
    if config.target.transport == "stdio":
        command = config.target.command or ""
        return Path(command).name
    return config.target.url or ""


def _target(config: AuditConfig, server: ServerInfo | None) -> ReportTarget:
    return ReportTarget(
        transport=server.transport if server is not None else config.target.transport,
        endpoint=endpoint_for(config, server),
        server_name=None if server is None else server.name,
        server_version=None if server is None else server.version,
        protocol_version=None if server is None else server.protocol_version,
    )


def _prompt_versions() -> PromptVersions:
    return PromptVersions(
        classify_field=_revision(CLASSIFY_PROMPT_VERSION),
        generate_probe_input=_revision(PLANNER_PROMPT_VERSION),
    )


def _revision(version: str) -> str:
    _name, separator, revision = version.rpartition(".")
    if separator == "":
        return version
    return revision


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
