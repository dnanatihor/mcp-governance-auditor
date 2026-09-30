"""Coverage ratios (§13.4). A zero denominator is null."""

from __future__ import annotations

from mcp_gov_audit.models import (
    AuditMetrics,
    FieldClassification,
    FieldObservation,
    Layer,
    ProbeEnvelope,
    ProbeResult,
    ToolDescriptor,
)

_LAYERS = (Layer.CERTIFIED, Layer.OBSERVED, Layer.INFERRED, Layer.UNKNOWN)


def compute_metrics(
    *,
    tools: list[ToolDescriptor],
    probes: list[ProbeResult],
    envelopes: list[ProbeEnvelope],
    fields: list[FieldObservation],
    classifications: list[FieldClassification],
) -> AuditMetrics:
    """Round every ratio to three decimals."""
    ok_tools = {probe.tool_name for probe in probes if probe.status == "ok"}
    classified = _classified_leaves(fields, classifications)
    labelled = sum(1 for item in classified if item.method in {"field_label", "envelope_label"})
    unknown = sum(1 for item in classified if item.layer == Layer.UNKNOWN)
    inferred_ok = _inferred_ok_probes(probes, envelopes, classifications)
    disclosed = sum(1 for envelope in inferred_ok if envelope.inference_flag_present)
    noticed = sum(1 for envelope in inferred_ok if envelope.governance_notice_present)
    return AuditMetrics(
        probe_coverage=_ratio(len(ok_tools), len(tools)),
        explicit_label_coverage=_ratio(labelled, len(classified)),
        inference_disclosure_rate=_ratio(disclosed, len(inferred_ok)),
        governance_notice_rate=_ratio(noticed, len(inferred_ok)),
        unknown_rate=_ratio(unknown, len(classified)),
    )


def distribution_for(tool_name: str, classifications: list[FieldClassification]) -> dict[str, int]:
    counts = {layer.value: 0 for layer in _LAYERS}
    for item in classifications:
        if item.tool_name != tool_name:
            continue
        key = item.layer.value
        if key in counts:
            counts[key] += 1
    return counts


def _classified_leaves(
    fields: list[FieldObservation],
    classifications: list[FieldClassification],
) -> list[FieldClassification]:
    index = {(item.probe_id, item.normalized_path): item for item in classifications}
    leaves: list[FieldClassification] = []
    for field in fields:
        if field.is_structural:
            continue
        match = index.get((field.probe_id, field.normalized_path))
        if match is not None:
            leaves.append(match)
    return leaves


def _inferred_ok_probes(
    probes: list[ProbeResult],
    envelopes: list[ProbeEnvelope],
    classifications: list[FieldClassification],
) -> list[ProbeEnvelope]:
    by_probe = {envelope.probe_id: envelope for envelope in envelopes}
    inferred_ids = {item.probe_id for item in classifications if item.layer == Layer.INFERRED}
    selected: list[ProbeEnvelope] = []
    for probe in probes:
        if probe.status != "ok":
            continue
        envelope = by_probe.get(probe.probe_id)
        inferred = probe.probe_id in inferred_ids or (
            envelope is not None and envelope.inferred_container_nonempty
        )
        if not inferred:
            continue
        selected.append(
            envelope
            or ProbeEnvelope(
                probe_id=probe.probe_id,
                tool_name=probe.tool_name,
                parse_mode="none",
                inference_flag_present=False,
                inference_flag_value=None,
                governance_notice_present=False,
                inferred_container_nonempty=False,
                truncated=False,
            )
        )
    return selected


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 3)
