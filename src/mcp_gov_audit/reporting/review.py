"""Apply human review decisions to findings (§13.6)."""

from __future__ import annotations

from mcp_gov_audit.models import Finding, ReviewDecision, ReviewStatus

_STATUS: dict[str, ReviewStatus] = {
    "confirm": "confirmed",
    "dismiss": "dismissed",
    "downgrade": "downgraded",
}


def coerce_decisions(value: object) -> list[ReviewDecision]:
    if isinstance(value, ReviewDecision):
        return [value]
    if isinstance(value, dict):
        return [ReviewDecision.model_validate(value)]
    if isinstance(value, list):
        decisions: list[ReviewDecision] = []
        for item in value:
            if isinstance(item, ReviewDecision):
                decisions.append(item)
            else:
                decisions.append(ReviewDecision.model_validate(item))
        return decisions
    raise TypeError(f"unsupported review resume value: {type(value).__name__}")


def apply_decisions(findings: list[Finding], decisions: list[ReviewDecision]) -> list[Finding]:
    """Update review status, downgraded severity, and the optional note."""
    by_id = {item.finding_id: item for item in decisions}
    updated: list[Finding] = []
    for finding in findings:
        decision = by_id.get(finding.finding_id)
        if decision is None:
            updated.append(finding)
            continue
        changes: dict[str, object] = {
            "review_status": _STATUS[decision.decision],
            "review_note": decision.note,
        }
        if decision.decision == "downgrade" and decision.severity is not None:
            changes["severity"] = decision.severity
        updated.append(finding.model_copy(update=changes))
    return updated
