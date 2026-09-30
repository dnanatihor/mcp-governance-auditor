"""Response masking at capture (§10.5)."""

from __future__ import annotations

import re
from typing import Any

from mcp_gov_audit.models import ProbeResult

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(
    r"(?<!\d)(?:\+\d{1,3}[\s\-])?(?:\(\d{3}\)[\s\-]?|\d{3}[\s\-])\d{3}[\s\-]\d{4}(?!\d)"
)
_IPV4 = re.compile(
    r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)"
)
_CARD = re.compile(r"(?<!\d)\d{13,19}(?!\d)")

_BUILTIN: tuple[tuple[re.Pattern[str], str], ...] = (
    (_EMAIL, "«email»"),
    (_PHONE, "«phone»"),
    (_IPV4, "«ip»"),
    (_CARD, "«card»"),
)


def mask_string(value: str, extra_patterns: tuple[str, ...] = ()) -> str:
    """Replace sensitive substrings. Non-matching text, including timestamps, is kept."""
    masked = value
    for pattern, token in _BUILTIN:
        masked = pattern.sub(token, masked)
    for raw in extra_patterns:
        masked = re.compile(raw).sub("«redacted»", masked)
    return masked


def mask_json(value: Any, extra_patterns: tuple[str, ...] = ()) -> Any:
    """Walk JSON and rewrite string values only."""
    if isinstance(value, str):
        return mask_string(value, extra_patterns)
    if isinstance(value, dict):
        return {key: mask_json(item, extra_patterns) for key, item in value.items()}
    if isinstance(value, list):
        return [mask_json(item, extra_patterns) for item in value]
    if isinstance(value, tuple):
        return tuple(mask_json(item, extra_patterns) for item in value)
    return value


def mask_probe_result(result: ProbeResult, extra_patterns: tuple[str, ...] = ()) -> ProbeResult:
    """Return a copy whose captured strings are masked."""
    structured = result.structured_content
    meta = result.meta
    error = result.error_message
    return result.model_copy(
        update={
            "arguments": mask_json(result.arguments, extra_patterns),
            "structured_content": None
            if structured is None
            else mask_json(structured, extra_patterns),
            "text_content": tuple(
                mask_string(text, extra_patterns) for text in result.text_content
            ),
            "meta": None if meta is None else mask_json(meta, extra_patterns),
            "error_message": None if error is None else mask_string(error, extra_patterns),
        }
    )
