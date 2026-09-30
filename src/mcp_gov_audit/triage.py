"""Risk scoring and probe eligibility (§9.1-9.2)."""

from __future__ import annotations

import fnmatch
from typing import Any

from mcp_gov_audit.config import Policy, ProbingConfig
from mcp_gov_audit.models import ProbeDecision, ToolDescriptor

ProbeDecisionValue = ProbeDecision | None


def triage_tools(
    tools: list[ToolDescriptor],
    probing: ProbingConfig,
    policy: Policy,
) -> list[ToolDescriptor]:
    """Score every tool and set the first matching eligibility decision."""
    triaged: list[ToolDescriptor] = []
    for tool in tools:
        score = risk_score(tool, policy)
        triaged.append(
            tool.model_copy(
                update={
                    "risk_score": score,
                    "inference_risk": score >= policy.inference_risk.min_score,
                    "probe_decision": probe_decision(tool, probing),
                }
            )
        )
    return triaged


def risk_score(tool: ToolDescriptor, policy: Policy) -> float:
    """§9.1. Keyword hits are distinct and case-insensitive."""
    haystack = f"{tool.name}\n{tool.description or ''}".casefold()
    keywords = {
        word.casefold() for word in policy.inference_risk.keywords if word.casefold() in haystack
    }
    schema_hit = 0
    if tool.output_schema is not None and _schema_has_inferred_key(tool.output_schema, policy):
        schema_hit = 1
    return min(1.0, 0.25 * len(keywords) + 0.25 * schema_hit)


def probe_decision(tool: ToolDescriptor, probing: ProbingConfig) -> ProbeDecisionValue:
    """First matching §9.2 row. Eligible tools stay None for plan_probes."""
    if probing.mode == "off":
        return "skip_mode_off"
    if any(fnmatch.fnmatch(tool.name, pattern) for pattern in probing.denylist):
        return "skip_denylisted"
    if _hint_is_true(tool, "destructiveHint"):
        return "skip_destructive"
    allowlisted = tool.name in probing.allowlist
    if probing.mode == "allowlist" and not allowlisted:
        return "skip_not_allowlisted"
    if probing.mode == "safe" and not (_hint_is_true(tool, "readOnlyHint") or allowlisted):
        return "skip_not_allowlisted"
    # open: denylist and an explicit destructiveHint still skip; missing annotations do not.
    return None


def _hint_is_true(tool: ToolDescriptor, key: str) -> bool:
    if tool.annotations is None:
        return False
    return tool.annotations.get(key) is True


def _schema_has_inferred_key(schema: dict[str, Any], policy: Policy) -> bool:
    patterns = tuple(pattern.casefold() for pattern in policy.field_patterns.inferred)
    return any(
        fnmatch.fnmatch(key.casefold(), pattern)
        for key in _property_names(schema)
        for pattern in patterns
    )


def _property_names(schema: object) -> set[str]:
    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            properties = node.get("properties")
            if isinstance(properties, dict):
                found.update(str(key) for key in properties)
                for child in properties.values():
                    walk(child)
            for key in ("items", "additionalProperties", "not", "if", "then", "else"):
                if key in node:
                    walk(node[key])
            for key in ("anyOf", "allOf", "oneOf", "prefixItems"):
                group = node.get(key)
                if isinstance(group, list):
                    for child in group:
                        walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(schema)
    return found
