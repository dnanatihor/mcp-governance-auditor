"""Deterministic field classification (§10.3)."""

from __future__ import annotations

import fnmatch
from typing import Literal

from mcp_gov_audit.config import Policy
from mcp_gov_audit.models import FieldClassification, FieldObservation, Layer

Method = Literal["field_label", "envelope_label", "policy_pattern", "llm", "none"]

_LAYER_ORDER = (Layer.CERTIFIED, Layer.OBSERVED, Layer.INFERRED)


def classify_deterministic(
    fields: list[FieldObservation],
    policy: Policy,
    *,
    llm_enabled: bool,
) -> list[FieldClassification]:
    """Classify non-structural leaves. Row 4 is unknown when the LLM is off."""
    classified: list[FieldClassification] = []
    for field in fields:
        if field.is_structural:
            continue
        verdict = _classify_one(field, policy, llm_enabled=llm_enabled)
        if verdict is not None:
            classified.append(verdict)
    return classified


def _classify_one(
    field: FieldObservation,
    policy: Policy,
    *,
    llm_enabled: bool,
) -> FieldClassification | None:
    if field.field_label is not None:
        return _classification(
            field,
            field.field_label,
            "field_label",
            1.0,
            f"field label {field.field_label.value}",
        )
    if field.container_layer is not None:
        return _classification(
            field,
            field.container_layer,
            "envelope_label",
            1.0,
            f"container {field.container_layer.value}",
        )
    matched = _matching_layers(field.key, policy)
    if len(matched) == 1:
        layer = matched[0]
        return _classification(field, layer, "policy_pattern", 0.6, f"pattern {layer.value}")
    if llm_enabled:
        return None
    return _classification(field, Layer.UNKNOWN, "none", 0.0, "no deterministic match")


def _matching_layers(key: str, policy: Policy) -> list[Layer]:
    folded = key.casefold()
    matched: list[Layer] = []
    patterns = {
        Layer.CERTIFIED: policy.field_patterns.certified,
        Layer.OBSERVED: policy.field_patterns.observed,
        Layer.INFERRED: policy.field_patterns.inferred,
    }
    for layer in _LAYER_ORDER:
        if any(fnmatch.fnmatch(folded, pattern.casefold()) for pattern in patterns[layer]):
            matched.append(layer)
    return matched


def _classification(
    field: FieldObservation,
    layer: Layer,
    method: Method,
    confidence: float,
    evidence: str,
) -> FieldClassification:
    return FieldClassification(
        probe_id=field.probe_id,
        tool_name=field.tool_name,
        normalized_path=field.normalized_path,
        concrete_path=field.concrete_path,
        parent_path=field.parent_path,
        layer=layer,
        method=method,
        confidence=confidence,
        evidence=evidence,
    )
