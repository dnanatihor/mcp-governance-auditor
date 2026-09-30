from datetime import UTC, datetime

from tests.helpers import ROOT

from mcp_gov_audit.config import load_policy
from mcp_gov_audit.models import Finding, ProbeResult, ToolDescriptor
from mcp_gov_audit.rules.base import RuleContext, evaluate_rules, finding_id

POLICY = load_policy(ROOT / "configs" / "policy.default.yaml")
NOW = datetime(2026, 1, 2, tzinfo=UTC)


def _context(
    tools: list[ToolDescriptor],
    probes: list[ProbeResult] | None = None,
) -> RuleContext:
    return RuleContext(
        tools=tools,
        probes=probes or [],
        envelopes=[],
        fields=[],
        objects=[],
        classifications=[],
        policy=POLICY,
        now=NOW,
    )


def _tool(name: str, decision: str | None) -> ToolDescriptor:
    return ToolDescriptor(
        name=name,
        input_schema={"type": "object"},
        probe_decision=decision,  # type: ignore[arg-type]
    )


def _probe(name: str, status: str, message: str | None = None) -> ProbeResult:
    return ProbeResult(
        probe_id=f"{name}#0",
        tool_name=name,
        arguments={},
        input_source="empty",
        status=status,  # type: ignore[arg-type]
        structured_content=None,
        text_content=(),
        meta=None,
        error_message=message,
        latency_ms=1,
        captured_at=NOW,
    )


def _ids(findings: list[Finding]) -> set[tuple[str, str | None]]:
    return {(finding.rule_id, finding.tool_name) for finding in findings}


def test_cov_001_fires_when_decision_is_not_probe_and_not_when_it_is() -> None:
    findings = evaluate_rules(
        _context(
            [
                _tool("delete_asset", "skip_destructive"),
                _tool("get_column_quality", "probe"),
            ]
        ),
        rule_ids=("COV-001",),
    )
    assert _ids(findings) == {("COV-001", "delete_asset")}
    assert findings[0].evidence == "skip_destructive"
    assert findings[0].normalized_path is None
    assert findings[0].finding_id == finding_id(rule_id="COV-001", tool_name="delete_asset")


def test_cov_002_fires_for_failed_probes_only() -> None:
    findings = evaluate_rules(
        _context(
            [_tool("flaky_lookup", "probe"), _tool("list_assets", "probe")],
            [
                _probe("flaky_lookup", "tool_error", "lookup failed"),
                _probe("slow_lookup", "timeout", "timed out"),
                _probe("list_assets", "ok"),
            ],
        ),
        rule_ids=("COV-002",),
    )
    by_tool = {finding.tool_name: finding for finding in findings}
    assert set(by_tool) == {"flaky_lookup", "slow_lookup"}
    assert by_tool["flaky_lookup"].occurrences[0].detail == "tool_error: lookup failed"
    assert by_tool["slow_lookup"].occurrences[0].detail == "timeout: timed out"
