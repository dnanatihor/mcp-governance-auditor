"""Positive and negative cases for EPI-001..009 and COV-003."""

from datetime import UTC, datetime, timedelta

from tests.helpers import ROOT

from mcp_gov_audit.config import load_policy
from mcp_gov_audit.models import (
    FieldClassification,
    Layer,
    ObjectObservation,
    ProbeEnvelope,
)
from mcp_gov_audit.rules import evaluate_rules
from mcp_gov_audit.rules.base import RuleContext

POLICY = load_policy(ROOT / "configs" / "policy.default.yaml")
NOW = datetime(2026, 9, 28, tzinfo=UTC)


def _context(**overrides: object) -> RuleContext:
    values: dict[str, object] = {
        "tools": [],
        "probes": [],
        "envelopes": [],
        "fields": [],
        "objects": [],
        "classifications": [],
        "policy": POLICY,
        "now": NOW,
    }
    values.update(overrides)
    return RuleContext.model_validate(values)


def _envelope(**overrides: object) -> ProbeEnvelope:
    values: dict[str, object] = {
        "probe_id": "p",
        "tool_name": "tool",
        "parse_mode": "structured",
        "inference_flag_present": False,
        "inference_flag_value": None,
        "governance_notice_present": False,
        "inferred_container_nonempty": False,
        "truncated": False,
    }
    values.update(overrides)
    return ProbeEnvelope.model_validate(values)


def _classification(**overrides: object) -> FieldClassification:
    values: dict[str, object] = {
        "probe_id": "p",
        "tool_name": "tool",
        "normalized_path": "$.score",
        "concrete_path": "$.score",
        "parent_path": "$",
        "layer": Layer.INFERRED,
        "method": "policy_pattern",
        "confidence": 0.6,
        "evidence": "pattern",
    }
    values.update(overrides)
    return FieldClassification.model_validate(values)


def _object(**overrides: object) -> ObjectObservation:
    values: dict[str, object] = {
        "probe_id": "p",
        "tool_name": "tool",
        "normalized_path": "$.item",
        "layer": Layer.CERTIFIED,
        "source": "container",
        "keys": (),
        "freshness_value": None,
    }
    values.update(overrides)
    return ObjectObservation.model_validate(values)


def _ids(rule_id: str, **overrides: object) -> set[str | None]:
    findings = evaluate_rules(_context(**overrides), rule_ids=(rule_id,))
    return {finding.normalized_path for finding in findings}


def test_epi_001_requires_inferred_content_without_a_flag() -> None:
    inferred = _classification()
    missing = _envelope()
    present = _envelope(inference_flag_present=True, inference_flag_value=True)
    assert _ids("EPI-001", envelopes=[missing], classifications=[inferred]) == {None}
    assert _ids("EPI-001", envelopes=[present], classifications=[inferred]) == set()


def test_epi_002_requires_mixed_unlabelled_layers() -> None:
    mixed = [
        _classification(layer=Layer.CERTIFIED, method="policy_pattern", normalized_path="$.a"),
        _classification(normalized_path="$.b"),
    ]
    labelled = [
        _classification(layer=Layer.CERTIFIED, method="envelope_label", normalized_path="$.a"),
        _classification(method="envelope_label", normalized_path="$.b"),
    ]
    assert _ids("EPI-002", classifications=mixed) == {"$"}
    assert _ids("EPI-002", classifications=labelled) == set()


def test_epi_003_only_pattern_or_llm_inference() -> None:
    pattern = _classification()
    labelled = _classification(method="envelope_label")
    assert _ids("EPI-003", classifications=[pattern]) == {"$.score"}
    assert _ids("EPI-003", classifications=[labelled]) == set()


def test_epi_004_certified_object_with_inferred_provenance() -> None:
    bad = _object(keys=("model", "rule_id"))
    clean = _object(keys=("rule_id", "certified_at", "certified_by"))
    assert _ids("EPI-004", objects=[bad]) == {"$.item"}
    assert _ids("EPI-004", objects=[clean]) == set()


def test_epi_005_lists_missing_certified_provenance() -> None:
    incomplete = _object(keys=("rule_id",))
    complete = _object(keys=("rule_id", "certified_at", "certified_by"))
    assert _ids("EPI-005", objects=[incomplete]) == {"$.item"}
    assert _ids("EPI-005", objects=[complete]) == set()


def test_epi_006_missing_or_unparsable_timestamp() -> None:
    missing = _object(layer=Layer.OBSERVED, freshness_value=None)
    fresh = _object(layer=Layer.OBSERVED, freshness_value="2026-09-27T00:00:00Z")
    assert _ids("EPI-006", objects=[missing]) == {"$.item"}
    assert _ids("EPI-006", objects=[fresh]) == set()
    findings = evaluate_rules(
        _context(objects=[_object(layer=Layer.OBSERVED, freshness_value="yesterday")]),
        rule_ids=("EPI-006",),
    )
    assert findings[0].evidence == "unparsable timestamp"


def test_epi_007_only_when_the_timestamp_is_older_than_the_limit() -> None:
    stale = _object(layer=Layer.OBSERVED, freshness_value="2025-01-01T00:00:00Z")
    fresh = _object(
        layer=Layer.OBSERVED,
        freshness_value=(NOW - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    assert _ids("EPI-007", objects=[stale]) == {"$.item"}
    assert _ids("EPI-007", objects=[fresh]) == set()


def test_epi_008_requires_a_false_flag_and_inferred_content() -> None:
    prohibited = _envelope(inference_flag_present=True, inference_flag_value=False)
    allowed = _envelope(inference_flag_present=True, inference_flag_value=True)
    inferred = _classification()
    assert _ids("EPI-008", envelopes=[prohibited], classifications=[inferred]) == {None}
    assert _ids("EPI-008", envelopes=[allowed], classifications=[inferred]) == set()


def test_epi_009_requires_inferred_content_without_a_notice() -> None:
    missing = _envelope(inferred_container_nonempty=True)
    noticed = _envelope(inferred_container_nonempty=True, governance_notice_present=True)
    assert _ids("EPI-009", envelopes=[missing]) == {None}
    assert _ids("EPI-009", envelopes=[noticed]) == set()


def test_cov_003_truncated_envelope() -> None:
    truncated = _envelope(truncated=True)
    whole = _envelope()
    assert _ids("COV-003", envelopes=[truncated]) == {None}
    assert _ids("COV-003", envelopes=[whole]) == set()


def test_llm_only_inference_is_llm_assisted_and_capped() -> None:
    findings = evaluate_rules(
        _context(
            classifications=[
                _classification(method="llm", layer=Layer.INFERRED),
                _classification(
                    method="llm",
                    layer=Layer.CERTIFIED,
                    normalized_path="$.certified",
                    crosscheck_disagreement=True,
                ),
            ]
        ),
        rule_ids=("EPI-003", "EPI-004"),
    )
    by_rule = {finding.rule_id: finding for finding in findings}
    assert by_rule["EPI-003"].basis == "llm_assisted"
    assert by_rule["EPI-003"].needs_human_review is True
    assert by_rule["EPI-003"].review_status == "pending"
    assert by_rule["EPI-004"].basis == "llm_assisted"
    assert by_rule["EPI-004"].severity == "high"
