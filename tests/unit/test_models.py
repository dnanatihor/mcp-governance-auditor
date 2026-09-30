from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from mcp_gov_audit.models import Finding, Occurrence, Severity


def test_severity_rank_orders_critical_above_info() -> None:
    ordered = (
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    )
    assert ordered[0] < ordered[1] < ordered[2] < ordered[3] < ordered[4]
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    ranks = [level.rank() for level in ordered]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ordered)


def test_finding_is_frozen() -> None:
    finding = Finding(
        finding_id="f1",
        rule_id="MAN-001",
        rule_name="Missing output schema",
        severity=Severity.HIGH,
        scope="manifest",
        evidence="outputSchema is absent",
        remediation="Declare an output schema",
        basis="deterministic",
        needs_human_review=False,
        occurrences=(Occurrence(detail="tool list"),),
    )
    with pytest.raises(ValidationError):
        finding.evidence = "changed"
    assert finding.occurrences[0].detail == "tool list"
    assert finding.review_status == "not_required"


def test_llm_verdict_rejects_confidence_above_one() -> None:
    from mcp_gov_audit.models import LLMFieldVerdict

    with pytest.raises(ValidationError):
        LLMFieldVerdict(
            field_path="$.quality.score",
            layer="inferred",
            confidence=1.2,
            evidence="score",
        )


def test_probe_result_uses_tuple_text() -> None:
    from mcp_gov_audit.models import ProbeResult

    result = ProbeResult(
        probe_id="list_assets#0",
        tool_name="list_assets",
        arguments={},
        input_source="empty",
        status="ok",
        structured_content={"assets": []},
        text_content=("[]",),
        meta=None,
        error_message=None,
        latency_ms=3,
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert result.text_content == ("[]",)
