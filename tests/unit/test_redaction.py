from mcp_gov_audit.models import ProbeResult
from mcp_gov_audit.redaction import mask_json, mask_probe_result, mask_string


def test_masks_builtin_patterns_and_keeps_structure() -> None:
    payload = {
        "email": "jane.doe@example.com",
        "phone": "415-555-2671",
        "ip": "192.168.0.10",
        "card": "4111111111111111",
        "count": 2,
        "ok": True,
        "missing": None,
        "nested": ["keep", {"note": "call 415-555-0199"}],
    }
    masked = mask_json(payload)
    assert masked["email"] == "«email»"
    assert masked["phone"] == "«phone»"
    assert masked["ip"] == "«ip»"
    assert masked["card"] == "«card»"
    assert masked["count"] == 2
    assert masked["ok"] is True
    assert masked["missing"] is None
    assert masked["nested"][0] == "keep"
    assert masked["nested"][1]["note"] == "call «phone»"
    assert list(payload) == list(masked)


def test_does_not_mask_timestamps_uuids_or_versions() -> None:
    samples = (
        "2025-01-01T00:00:00Z",
        "2026-09-27T10:15:02.123Z",
        "550e8400-e29b-41d4-a716-446655440000",
        "1.2.3",
        "v1.2.0",
    )
    for sample in samples:
        assert mask_string(sample) == sample


def test_extra_pattern_uses_redacted_token() -> None:
    assert mask_string("token secret-value", ("secret-value",)) == "token «redacted»"


def test_mask_probe_result_rewrites_text_and_structured_content() -> None:
    from datetime import UTC, datetime

    result = ProbeResult(
        probe_id="get_column_quality#0",
        tool_name="get_column_quality",
        arguments={"asset_id": "col_email"},
        input_source="fixture",
        status="ok",
        structured_content={"top_value": "jane.doe@example.com"},
        text_content=('{"top_value": "jane.doe@example.com"}',),
        meta={"note": "jane.doe@example.com"},
        error_message=None,
        latency_ms=1,
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    masked = mask_probe_result(result)
    assert masked.structured_content == {"top_value": "«email»"}
    assert "jane.doe@example.com" not in masked.text_content[0]
    assert masked.meta == {"note": "«email»"}
    assert "«email»" in masked.text_content[0]
