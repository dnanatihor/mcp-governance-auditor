"""Classifier batching, cache, threshold, and planner input resolution."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from jinja2 import UndefinedError
from tests.helpers import ROOT
from tests.llm_stubs import StubClassifier, StubPlanner

from mcp_gov_audit.classification.cache import ClassificationCache
from mcp_gov_audit.classification.llm import (
    LangChainFieldClassifier,
    classify_with_model,
    parse_classification_payload,
    render_prompt,
)
from mcp_gov_audit.config import ProbingConfig, load_policy
from mcp_gov_audit.models import (
    FieldClassification,
    FieldObservation,
    Layer,
    LLMFieldVerdict,
    ToolDescriptor,
)
from mcp_gov_audit.probing import plan_probes
from mcp_gov_audit.rules import evaluate_rules
from mcp_gov_audit.rules.base import RuleContext

POLICY = load_policy(ROOT / "configs" / "policy.default.yaml")
NOW = datetime(2026, 9, 28, tzinfo=UTC)


def _field(path: str, *, preview: str = "0.87") -> FieldObservation:
    return FieldObservation(
        probe_id="get_table_quality_summary#0",
        tool_name="get_table_quality_summary",
        concrete_path=path,
        normalized_path=path,
        parent_path="$.quality",
        key=path.rsplit(".", 1)[-1],
        value_type="number",
        value_preview=preview,
        value_length=len(preview),
        container_layer=None,
        field_label=None,
        sibling_keys=("score", "dq_rule_pass_rate", "recommended_action"),
        is_structural=False,
    )


def _tool() -> ToolDescriptor:
    return ToolDescriptor(
        name="get_table_quality_summary",
        description="Returns a quality score and recommended actions for a table.",
        input_schema={"type": "object", "properties": {"asset_id": {"type": "string"}}},
    )


def _inferred(path: str, confidence: float = 0.85) -> LLMFieldVerdict:
    return LLMFieldVerdict(
        field_path=path,
        layer="inferred",
        confidence=confidence,
        evidence="stub verdict",
    )


@pytest.mark.asyncio
async def test_threshold_keeps_method_and_lowers_layer(tmp_path: Path) -> None:
    field = _field("$.quality.score")
    classifier = StubClassifier(verdicts={"$.quality.score": _inferred("$.quality.score", 0.4)})
    [item] = await classify_with_model(
        fields=[field],
        deterministic=[],
        tools=[_tool()],
        classifier=classifier,
        cache=ClassificationCache(tmp_path),
        batch_size=25,
        min_confidence=0.7,
        crosscheck=False,
    )
    assert item.layer == Layer.UNKNOWN
    assert item.method == "llm"
    assert item.evidence == "stub verdict"
    assert item.confidence == 0.4


@pytest.mark.asyncio
async def test_mismatch_retries_once_then_marks_unknown(tmp_path: Path) -> None:
    field = _field("$.quality.score")
    wrong = LLMFieldVerdict(field_path="$.other", layer="observed", confidence=0.9, evidence="no")
    classifier = StubClassifier(scripted=[[wrong], [wrong]])
    [item] = await classify_with_model(
        fields=[field],
        deterministic=[],
        tools=[_tool()],
        classifier=classifier,
        cache=ClassificationCache(tmp_path),
        batch_size=25,
        min_confidence=0.7,
        crosscheck=False,
    )
    assert classifier.calls == 2
    assert item.evidence == "llm_output_mismatch"
    assert item.method == "llm"
    assert item.layer == Layer.UNKNOWN


@pytest.mark.asyncio
async def test_cache_skips_the_second_classifier_call(tmp_path: Path) -> None:
    field = _field("$.quality.score")
    verdicts = {"$.quality.score": _inferred("$.quality.score")}
    first = StubClassifier(verdicts=verdicts)
    await classify_with_model(
        fields=[field],
        deterministic=[],
        tools=[_tool()],
        classifier=first,
        cache=ClassificationCache(tmp_path),
        batch_size=25,
        min_confidence=0.7,
        crosscheck=False,
    )
    second = StubClassifier(verdicts=verdicts)
    [item] = await classify_with_model(
        fields=[field],
        deterministic=[],
        tools=[_tool()],
        classifier=second,
        cache=ClassificationCache(tmp_path),
        batch_size=25,
        min_confidence=0.7,
        crosscheck=False,
    )
    assert first.calls == 1
    assert second.calls == 0
    assert item.layer == Layer.INFERRED
    assert item.method == "llm"


def test_prompt_render_rejects_a_missing_variable() -> None:
    with pytest.raises(UndefinedError):
        render_prompt("classify_field.v1", {"tool_name": "tool"})


def test_recorded_structured_output_parses_to_verdicts() -> None:
    verdicts = parse_classification_payload(_recorded_batch())
    assert verdicts[0].layer == "inferred"
    assert verdicts[0].confidence == 0.85
    assert verdicts[0].field_path == "$.quality.score"


@pytest.mark.asyncio
async def test_langchain_classifier_parses_a_recorded_payload() -> None:
    class _Recorded:
        async def ainvoke(self, messages: object) -> dict[str, object]:
            del messages
            return _recorded_batch()

    classifier = LangChainFieldClassifier("recorded", runnable=_Recorded())
    verdicts = await classifier.classify(_tool(), [_field("$.quality.score")])
    assert verdicts[0].layer == "inferred"
    assert verdicts[0].field_path == "$.quality.score"
    assert classifier.prompt_version == "classify_field.v1"


def _recorded_batch() -> dict[str, object]:
    return {
        "verdicts": [
            {
                "field_path": "$.quality.score",
                "layer": "inferred",
                "confidence": 0.85,
                "mixed_layers": False,
                "evidence": "score without a rule id",
            }
        ]
    }


@pytest.mark.asyncio
async def test_planner_output_is_validated_before_use() -> None:
    tool = ToolDescriptor(
        name="get_profile_snapshot",
        description="Returns the latest profiling statistics for an asset.",
        input_schema={
            "type": "object",
            "properties": {"asset_id": {"type": "string"}},
            "required": ["asset_id"],
        },
        annotations={"readOnlyHint": True},
    )
    probing = ProbingConfig(
        mode="safe",
        allowlist=(),
        denylist=(),
        max_probes_per_tool=1,
        fixtures_file="fixtures.yaml",
        llm_generated_inputs=True,
        seed_values={"asset_id": ("tbl_orders", "col_email")},
    )
    good, requests = await plan_probes(
        [tool],
        {},
        probing,
        planner=StubPlanner([{"asset_id": "tbl_orders"}]),
        llm_enabled=True,
    )
    assert good[0].probe_decision == "probe"
    assert requests[0].arguments == {"asset_id": "tbl_orders"}
    assert requests[0].input_source == "llm_generated"

    bad, skipped = await plan_probes(
        [tool],
        {},
        probing,
        planner=StubPlanner([{"wrong": 1}]),
        llm_enabled=True,
    )
    assert skipped == []
    assert bad[0].probe_decision == "skip_no_input"
    findings = evaluate_rules(
        RuleContext(
            tools=bad,
            probes=[],
            envelopes=[],
            fields=[],
            objects=[],
            classifications=[],
            policy=POLICY,
            now=NOW,
        ),
        rule_ids=("COV-001",),
    )
    assert [(item.rule_id, item.tool_name) for item in findings] == [
        ("COV-001", "get_profile_snapshot")
    ]


@pytest.mark.asyncio
async def test_crosscheck_marks_disagreement_without_changing_layer(tmp_path: Path) -> None:
    certified = FieldClassification(
        probe_id="p",
        tool_name="get_table_quality_summary",
        normalized_path="$.label",
        concrete_path="$.label",
        parent_path="$",
        layer=Layer.CERTIFIED,
        method="envelope_label",
        confidence=1.0,
        evidence="container",
    )
    field = FieldObservation(
        probe_id="p",
        tool_name="get_table_quality_summary",
        concrete_path="$.label",
        normalized_path="$.label",
        parent_path="$",
        key="label",
        value_type="string",
        value_preview="pass",
        value_length=4,
        container_layer=Layer.CERTIFIED,
        field_label=None,
        sibling_keys=("label",),
        is_structural=False,
    )
    classifier = StubClassifier(verdicts={"$.label": _inferred("$.label")})
    [item] = await classify_with_model(
        fields=[field],
        deterministic=[certified],
        tools=[_tool()],
        classifier=classifier,
        cache=ClassificationCache(tmp_path),
        batch_size=25,
        min_confidence=0.7,
        crosscheck=True,
    )
    assert item.layer == Layer.CERTIFIED
    assert item.crosscheck_disagreement is True
    assert classifier.calls == 1
