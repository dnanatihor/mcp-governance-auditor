from tests.helpers import ROOT

from mcp_gov_audit.classification.deterministic import classify_deterministic
from mcp_gov_audit.config import load_policy
from mcp_gov_audit.models import FieldObservation, Layer

POLICY = load_policy(ROOT / "configs" / "policy.default.yaml")


def _field(**overrides: object) -> FieldObservation:
    values: dict[str, object] = {
        "probe_id": "p",
        "tool_name": "tool",
        "concrete_path": "$.score",
        "normalized_path": "$.score",
        "parent_path": "$",
        "key": "score",
        "value_type": "number",
        "value_preview": "1",
        "value_length": 1,
        "container_layer": None,
        "field_label": None,
        "sibling_keys": ("score",),
        "is_structural": False,
    }
    values.update(overrides)
    return FieldObservation.model_validate(values)


def test_structural_leaves_are_skipped() -> None:
    assert classify_deterministic([_field(is_structural=True)], POLICY, llm_enabled=False) == []


def test_field_label_precedes_container_and_pattern() -> None:
    field = _field(
        key="recommended_action",
        field_label=Layer.OBSERVED,
        container_layer=Layer.CERTIFIED,
    )
    [verdict] = classify_deterministic([field], POLICY, llm_enabled=False)
    assert verdict.layer == Layer.OBSERVED
    assert verdict.method == "field_label"
    assert verdict.confidence == 1.0


def test_container_layer_precedes_pattern() -> None:
    field = _field(key="likely_pii", container_layer=Layer.OBSERVED)
    [verdict] = classify_deterministic([field], POLICY, llm_enabled=False)
    assert verdict.layer == Layer.OBSERVED
    assert verdict.method == "envelope_label"
    assert verdict.confidence == 1.0


def test_single_pattern_match() -> None:
    field = _field(key="recommended_action", normalized_path="$.quality.recommended_action")
    [verdict] = classify_deterministic([field], POLICY, llm_enabled=False)
    assert verdict.layer == Layer.INFERRED
    assert verdict.method == "policy_pattern"
    assert verdict.confidence == 0.6


def test_no_match_is_unknown_when_llm_is_disabled() -> None:
    [verdict] = classify_deterministic([_field(key="score")], POLICY, llm_enabled=False)
    assert verdict.layer == Layer.UNKNOWN
    assert verdict.method == "none"


def test_no_match_is_left_for_the_llm_when_enabled() -> None:
    assert classify_deterministic([_field(key="score")], POLICY, llm_enabled=True) == []


def test_key_matching_two_layers_is_not_a_pattern_match() -> None:
    field = _field(key="certified_recommend")
    [verdict] = classify_deterministic([field], POLICY, llm_enabled=False)
    assert verdict.method == "none"
    assert verdict.layer == Layer.UNKNOWN
