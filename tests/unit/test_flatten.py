from datetime import UTC, datetime

from tests.helpers import ROOT

from mcp_gov_audit.config import load_policy
from mcp_gov_audit.flatten import normalize_probe
from mcp_gov_audit.models import ProbeResult

POLICY = load_policy(ROOT / "configs" / "policy.default.yaml")
NOW = datetime(2026, 9, 28, tzinfo=UTC)


def _probe(payload: dict[str, object], *, texts: tuple[str, ...] = ()) -> ProbeResult:
    return ProbeResult(
        probe_id="tool#0",
        tool_name="tool",
        arguments={},
        input_source="fixture",
        status="ok",
        structured_content=payload,
        text_content=texts,
        meta=None,
        error_message=None,
        latency_ms=1,
        captured_at=NOW,
    )


def test_paths_containers_labels_and_structural_keys() -> None:
    normalized = normalize_probe(
        _probe(
            {
                "certified_findings": [
                    {
                        "rule_id": "DQ-1",
                        "score": 1,
                        "epistemic_layer": "observed",
                    }
                ],
                "tags": ["a", "b"],
                "asset": {"id": "col_email", "name": "email"},
            }
        ),
        POLICY,
        send_values="full",
        max_value_chars=20,
    )
    assert normalized is not None
    by_path = {field.normalized_path: field for field in normalized.fields}
    score = by_path["$.certified_findings[*].score"]
    assert score.concrete_path == "$.certified_findings[0].score"
    assert score.parent_path == "$.certified_findings[*]"
    assert score.container_layer == "certified"
    assert score.field_label == "observed"
    assert score.sibling_keys == ("rule_id", "score", "epistemic_layer")
    assert by_path["$.certified_findings[*].rule_id"].is_structural is True
    assert by_path["$.asset.id"].is_structural is True
    assert by_path["$.tags"].value_type == "list"
    assert by_path["$.tags"].value_preview == '["a", "b"]'
    objects = {item.normalized_path: item for item in normalized.objects}
    assert objects["$.certified_findings[*]"].layer == "certified"
    assert objects["$.certified_findings[*]"].source == "container"


def test_truncation_caps_leaves() -> None:
    payload = {f"field_{index}": index for index in range(5)}
    normalized = normalize_probe(
        _probe(payload),
        POLICY,
        send_values="truncated",
        max_value_chars=1,
        max_fields=2,
    )
    assert normalized is not None
    assert normalized.envelope.truncated is True
    assert len(normalized.fields) == 2
    assert all(len(field.value_preview) <= 1 for field in normalized.fields)


def test_text_json_and_free_text_modes() -> None:
    parsed = normalize_probe(
        ProbeResult(
            probe_id="tool#0",
            tool_name="tool",
            arguments={},
            input_source="empty",
            status="ok",
            structured_content=None,
            text_content=('{"score": 1}',),
            meta={"governance_notice": "notice"},
            error_message=None,
            latency_ms=1,
            captured_at=NOW,
        ),
        POLICY,
        send_values="none",
        max_value_chars=10,
    )
    assert parsed is not None
    assert parsed.envelope.parse_mode == "text_json"
    assert parsed.envelope.governance_notice_present is True
    assert parsed.fields[0].value_preview == ""
    assert parsed.fields[0].value_length > 0

    text = normalize_probe(
        ProbeResult(
            probe_id="tool#1",
            tool_name="tool",
            arguments={},
            input_source="empty",
            status="ok",
            structured_content=None,
            text_content=("not json", "also"),
            meta=None,
            error_message=None,
            latency_ms=1,
            captured_at=NOW,
        ),
        POLICY,
        send_values="full",
        max_value_chars=10,
    )
    assert text is not None
    assert text.envelope.parse_mode == "text"
    assert [field.concrete_path for field in text.fields] == ["$text[0]", "$text[1]"]
    assert text.fields[0].value_type == "text"
