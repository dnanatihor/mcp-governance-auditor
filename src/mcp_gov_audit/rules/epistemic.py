"""EPI-001 through EPI-009 (§11.3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from mcp_gov_audit.models import (
    FieldClassification,
    Finding,
    Layer,
    Occurrence,
    ProbeEnvelope,
    Severity,
)
from mcp_gov_audit.rules.base import RuleContext, finding_id, register_rule

Scope = Literal["response"]


def _finding(
    *,
    rule_id: str,
    rule_name: str,
    severity: Severity,
    tool_name: str,
    normalized_path: str | None,
    evidence: str,
    remediation: str,
    occurrences: tuple[Occurrence, ...] = (),
) -> Finding:
    return Finding(
        finding_id=finding_id(
            rule_id=rule_id, tool_name=tool_name, normalized_path=normalized_path
        ),
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        scope="response",
        tool_name=tool_name,
        normalized_path=normalized_path,
        evidence=evidence,
        remediation=remediation,
        basis="deterministic",
        needs_human_review=False,
        occurrences=occurrences,
    )


def _inferred_paths(ctx: RuleContext, probe_id: str) -> list[str]:
    return [
        item.concrete_path
        for item in ctx.classifications
        if item.probe_id == probe_id and item.layer == Layer.INFERRED
    ]


def _has_inferred(ctx: RuleContext, probe_id: str, envelope: ProbeEnvelope | None) -> bool:
    if envelope is not None and envelope.inferred_container_nonempty:
        return True
    return any(path for path in _inferred_paths(ctx, probe_id))


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


@register_rule
class InferenceFlagMissing:
    id = "EPI-001"
    name = "Inference disclosure flag missing"
    default_severity = Severity.HIGH
    scope: Scope = "response"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        by_tool: dict[str, list[Occurrence]] = {}
        for envelope in ctx.envelopes:
            inferred = _has_inferred(ctx, envelope.probe_id, envelope)
            if envelope.inference_flag_present or not inferred:
                continue
            paths = _inferred_paths(ctx, envelope.probe_id)[:5]
            if paths:
                for path in paths:
                    by_tool.setdefault(envelope.tool_name, []).append(
                        Occurrence(probe_id=envelope.probe_id, concrete_path=path)
                    )
            else:
                by_tool.setdefault(envelope.tool_name, []).append(
                    Occurrence(probe_id=envelope.probe_id)
                )
        flag = ctx.policy.envelope.inference_flag_key
        return [
            _finding(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.default_severity,
                tool_name=tool_name,
                normalized_path=None,
                evidence="Inferred content is present and the inference flag is absent.",
                remediation=(
                    f"Add `{flag}` (boolean) to the response envelope of `{tool_name}` "
                    "in the response-shaping layer, set per request from governance policy."
                ),
                occurrences=tuple(items[:5]),
            )
            for tool_name, items in by_tool.items()
        ]


@register_rule
class LayerConflation:
    id = "EPI-002"
    name = "Layer conflation"
    default_severity = Severity.HIGH
    scope: Scope = "response"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        groups: dict[tuple[str, str, str], list[FieldClassification]] = {}
        for item in ctx.classifications:
            if item.layer == Layer.UNKNOWN:
                continue
            groups.setdefault((item.probe_id, item.tool_name, item.parent_path), []).append(item)
        label = ctx.policy.envelope.field_label_key
        for (_probe_id, tool_name, parent), items in groups.items():
            layers = {item.layer for item in items}
            mixed = Layer.INFERRED in layers and (
                Layer.CERTIFIED in layers or Layer.OBSERVED in layers
            )
            explicit = all(item.method in {"field_label", "envelope_label"} for item in items)
            if mixed and not explicit:
                findings.append(
                    _finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity=self.default_severity,
                        tool_name=tool_name,
                        normalized_path=parent,
                        evidence=f"Mixed epistemic layers under {parent}.",
                        remediation=(
                            "Separate certified/observed values and AI inferences under "
                            f"`{parent}` in `{tool_name}` into distinct layer containers, "
                            f"or label each object with `{label}`."
                        ),
                    )
                )
        for item in ctx.classifications:
            if item.mixed_layers and _is_text(ctx, item):
                findings.append(
                    _finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity=self.default_severity,
                        tool_name=item.tool_name,
                        normalized_path=item.normalized_path,
                        evidence="Text leaf mixes epistemic layers.",
                        remediation=(
                            f"Separate certified/observed values and AI inferences under "
                            f"`{item.normalized_path}` in `{item.tool_name}` into distinct layer "
                            f"containers, or label each object with `{label}`."
                        ),
                    )
                )
        return findings


@register_rule
class UnlabelledInference:
    id = "EPI-003"
    name = "Unlabelled inference"
    default_severity = Severity.HIGH
    scope: Scope = "response"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        container = ctx.policy.envelope.layer_container_keys.inferred
        label = ctx.policy.envelope.field_label_key
        seen: set[tuple[str, str]] = set()
        findings: list[Finding] = []
        for item in ctx.classifications:
            if item.layer != Layer.INFERRED or item.method not in {"policy_pattern", "llm"}:
                continue
            key = (item.tool_name, item.normalized_path)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                _finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    tool_name=item.tool_name,
                    normalized_path=item.normalized_path,
                    evidence=f"{item.normalized_path} is inferred by {item.method}.",
                    remediation=(
                        f"Move `{item.normalized_path}` into `{container}` or add "
                        f"`{label}: inferred` to its parent object."
                    ),
                )
            )
        return findings


@register_rule
class InferencePresentedAsCertified:
    id = "EPI-004"
    name = "Inference presented as certified"
    default_severity = Severity.CRITICAL
    scope: Scope = "response"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        inferred_keys = set(ctx.policy.provenance_keys.inferred)
        container = ctx.policy.envelope.layer_container_keys.certified
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for obj in ctx.objects:
            if obj.layer != Layer.CERTIFIED or not inferred_keys.intersection(obj.keys):
                continue
            key = (obj.tool_name, obj.normalized_path)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                _finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    tool_name=obj.tool_name,
                    normalized_path=obj.normalized_path,
                    evidence="Certified object includes inferred provenance keys.",
                    remediation=(
                        f"Remove AI-generated content from `{container}` in `{obj.tool_name}`. "
                        "Certified findings must come only from approved data-quality rule results."
                    ),
                )
            )
        for item in ctx.classifications:
            if not item.crosscheck_disagreement:
                continue
            findings.append(
                _finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    tool_name=item.tool_name,
                    normalized_path=item.normalized_path,
                    evidence="Classifier disagrees with a certified label.",
                    remediation=(
                        f"Remove AI-generated content from `{container}` in `{item.tool_name}`. "
                        "Certified findings must come only from approved data-quality rule results."
                    ),
                )
            )
        return findings


@register_rule
class CertifiedProvenanceIncomplete:
    id = "EPI-005"
    name = "Certified provenance incomplete"
    default_severity = Severity.MEDIUM
    scope: Scope = "response"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        required = tuple(ctx.policy.provenance_keys.certified)
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for obj in ctx.objects:
            if obj.layer != Layer.CERTIFIED:
                continue
            missing = [key for key in required if key not in obj.keys]
            if not missing:
                continue
            identity = (obj.tool_name, obj.normalized_path)
            if identity in seen:
                continue
            seen.add(identity)
            listed = ", ".join(missing)
            findings.append(
                _finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    tool_name=obj.tool_name,
                    normalized_path=obj.normalized_path,
                    evidence=f"Missing certified provenance: {listed}.",
                    remediation=(
                        f"Include `{listed}` on every certified finding returned by "
                        f"`{obj.tool_name}`."
                    ),
                )
            )
        return findings


@register_rule
class ObservationTimestampMissing:
    id = "EPI-006"
    name = "Observation timestamp missing"
    default_severity = Severity.LOW
    scope: Scope = "response"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        freshness = ctx.policy.freshness.key
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for obj in ctx.objects:
            if obj.layer != Layer.OBSERVED:
                continue
            if obj.freshness_value is None:
                evidence = f"Missing {freshness}."
            elif _parse_time(obj.freshness_value) is None:
                evidence = "unparsable timestamp"
            else:
                continue
            identity = (obj.tool_name, obj.normalized_path)
            if identity in seen:
                continue
            seen.add(identity)
            findings.append(
                _finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    tool_name=obj.tool_name,
                    normalized_path=obj.normalized_path,
                    evidence=evidence,
                    remediation=(
                        f"Add `{freshness}` (ISO-8601) to every profiling observation "
                        f"returned by `{obj.tool_name}`."
                    ),
                )
            )
        return findings


@register_rule
class ObservationStale:
    id = "EPI-007"
    name = "Observation stale"
    default_severity = Severity.MEDIUM
    scope: Scope = "response"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        freshness = ctx.policy.freshness.key
        limit = ctx.now - timedelta(days=ctx.policy.freshness.observation_max_age_days)
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for obj in ctx.objects:
            if obj.layer != Layer.OBSERVED or obj.freshness_value is None:
                continue
            parsed = _parse_time(obj.freshness_value)
            if parsed is None or parsed >= limit:
                continue
            identity = (obj.tool_name, obj.normalized_path)
            if identity in seen:
                continue
            seen.add(identity)
            findings.append(
                _finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    tool_name=obj.tool_name,
                    normalized_path=obj.normalized_path,
                    evidence=f"{freshness} {obj.freshness_value} is older than the allowed age.",
                    remediation=(
                        "Refresh profiling for the affected assets or surface staleness "
                        f"explicitly in `{obj.tool_name}`'s response."
                    ),
                )
            )
        return findings


@register_rule
class InferenceWhileProhibited:
    id = "EPI-008"
    name = "Inference present while prohibited"
    default_severity = Severity.CRITICAL
    scope: Scope = "response"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        flag = ctx.policy.envelope.inference_flag_key
        by_tool: dict[str, ProbeEnvelope] = {}
        for envelope in ctx.envelopes:
            if envelope.inference_flag_value is not False:
                continue
            if not _has_inferred(ctx, envelope.probe_id, envelope):
                continue
            by_tool.setdefault(envelope.tool_name, envelope)
        return [
            _finding(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.default_severity,
                tool_name=tool_name,
                normalized_path=None,
                evidence=f"{flag} is false while inferred content is present.",
                remediation=(
                    f"`{tool_name}` returns AI inferences while declaring `{flag}: false`. "
                    "Strip inferred content in response shaping when inference is not permitted."
                ),
                occurrences=(Occurrence(probe_id=envelope.probe_id),),
            )
            for tool_name, envelope in by_tool.items()
        ]


@register_rule
class GovernanceNoticeMissing:
    id = "EPI-009"
    name = "Governance notice missing"
    default_severity = Severity.MEDIUM
    scope: Scope = "response"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        notice = ctx.policy.envelope.governance_notice_keys[0]
        by_tool: dict[str, list[Occurrence]] = {}
        for envelope in ctx.envelopes:
            if envelope.governance_notice_present or not _has_inferred(
                ctx, envelope.probe_id, envelope
            ):
                continue
            by_tool.setdefault(envelope.tool_name, []).append(
                Occurrence(probe_id=envelope.probe_id)
            )
        return [
            _finding(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.default_severity,
                tool_name=tool_name,
                normalized_path=None,
                evidence="Inferred content is present and no governance notice was returned.",
                remediation=(
                    f"Inject a governance notice (`{notice}`) into `{tool_name}` responses "
                    "whenever inferred content is present."
                ),
                occurrences=tuple(items),
            )
            for tool_name, items in by_tool.items()
        ]


def _is_text(ctx: RuleContext, item: FieldClassification) -> bool:
    return any(
        field.probe_id == item.probe_id
        and field.normalized_path == item.normalized_path
        and field.value_type == "text"
        for field in ctx.fields
    )
