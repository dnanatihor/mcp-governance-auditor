"""Response parsing and flattening (§10.1-10.2)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

from mcp_gov_audit.config import Policy
from mcp_gov_audit.models import (
    FieldObservation,
    Layer,
    ObjectObservation,
    ProbeEnvelope,
    ProbeResult,
)

MAX_FIELDS_PER_PROBE = 500
SendValues = Literal["none", "truncated", "full"]
_LAYERS = {layer.value: layer for layer in Layer}


@dataclass(frozen=True)
class NormalizedProbe:
    envelope: ProbeEnvelope
    fields: tuple[FieldObservation, ...]
    objects: tuple[ObjectObservation, ...]


def normalize_probe(
    probe: ProbeResult,
    policy: Policy,
    *,
    send_values: SendValues,
    max_value_chars: int,
    max_fields: int = MAX_FIELDS_PER_PROBE,
) -> NormalizedProbe | None:
    """Parse one successful probe. Failed probes are not envelopes."""
    if probe.status != "ok":
        return None
    root, parse_mode = _parse_root(probe)
    flag_present, flag_value = _inference_flag(root, policy)
    envelope = ProbeEnvelope(
        probe_id=probe.probe_id,
        tool_name=probe.tool_name,
        parse_mode=parse_mode,
        inference_flag_present=flag_present,
        inference_flag_value=flag_value,
        governance_notice_present=_notice_present(root, probe.meta, policy),
        inferred_container_nonempty=_inferred_nonempty(root, policy),
        truncated=False,
    )
    if root is None and parse_mode != "text":
        return NormalizedProbe(envelope, (), ())
    fields, objects = _flatten(
        probe,
        root,
        probe.text_content if parse_mode == "text" else (),
        policy,
        send_values=send_values,
        max_value_chars=max_value_chars,
    )
    if len(fields) > max_fields:
        envelope = envelope.model_copy(update={"truncated": True})
        fields = fields[:max_fields]
    return NormalizedProbe(envelope, tuple(fields), tuple(objects))


def _parse_root(
    probe: ProbeResult,
) -> tuple[dict[str, object] | None, Literal["structured", "text_json", "text", "none"]]:
    if probe.structured_content is not None:
        return probe.structured_content, "structured"
    if len(probe.text_content) == 1:
        parsed = _json_object(probe.text_content[0])
        if parsed is not None:
            return parsed, "text_json"
    if probe.text_content:
        return None, "text"
    return None, "none"


def _json_object(text: str) -> dict[str, object] | None:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict):
        return parsed
    return None


def _inference_flag(root: dict[str, object] | None, policy: Policy) -> tuple[bool, bool | None]:
    if root is None or policy.envelope.inference_flag_key not in root:
        return False, None
    value = root[policy.envelope.inference_flag_key]
    if isinstance(value, bool):
        return True, value
    return True, None


def _notice_present(
    root: dict[str, object] | None,
    meta: dict[str, object] | None,
    policy: Policy,
) -> bool:
    for key in policy.envelope.governance_notice_keys:
        value = _resolve_policy_key(root, meta, key)
        if isinstance(value, str) and value != "":
            return True
    return False


def _resolve_policy_key(
    root: dict[str, object] | None,
    meta: dict[str, object] | None,
    key: str,
) -> object:
    if key.startswith("_meta."):
        if meta is None:
            return None
        return meta.get(key.removeprefix("_meta."))
    if root is None:
        return None
    return root.get(key)


def _inferred_nonempty(root: dict[str, object] | None, policy: Policy) -> bool:
    if root is None:
        return False
    value = root.get(policy.envelope.layer_container_keys.inferred)
    if isinstance(value, dict):
        return len(value) > 0
    if isinstance(value, list):
        return len(value) > 0
    return False


def _flatten(
    probe: ProbeResult,
    root: dict[str, object] | None,
    texts: tuple[str, ...],
    policy: Policy,
    *,
    send_values: SendValues,
    max_value_chars: int,
) -> tuple[list[FieldObservation], list[ObjectObservation]]:
    fields: list[FieldObservation] = []
    objects: list[ObjectObservation] = []
    structural = _structural_keys(policy)
    containers = {
        policy.envelope.layer_container_keys.certified: Layer.CERTIFIED,
        policy.envelope.layer_container_keys.observed: Layer.OBSERVED,
        policy.envelope.layer_container_keys.inferred: Layer.INFERRED,
    }
    label_key = policy.envelope.field_label_key
    freshness_key = policy.freshness.key
    if root is not None:
        _walk_object(
            root,
            concrete="$",
            normalized="$",
            container=None,
            label=None,
            probe=probe,
            policy_patterns=structural,
            containers=containers,
            label_key=label_key,
            freshness_key=freshness_key,
            fields=fields,
            objects=objects,
            send_values=send_values,
            max_value_chars=max_value_chars,
            structural_patterns=tuple(policy.structural_patterns),
        )
    if texts:
        _append_text_leaves(
            texts,
            probe,
            fields,
            send_values=send_values,
            max_value_chars=max_value_chars,
        )
    return fields, objects


def _walk_object(
    obj: dict[str, object],
    *,
    concrete: str,
    normalized: str,
    container: Layer | None,
    label: Layer | None,
    probe: ProbeResult,
    policy_patterns: set[str],
    containers: dict[str, Layer],
    label_key: str,
    freshness_key: str,
    fields: list[FieldObservation],
    objects: list[ObjectObservation],
    send_values: SendValues,
    max_value_chars: int,
    structural_patterns: tuple[str, ...],
) -> None:
    own_label = _layer_value(obj.get(label_key)) if label_key in obj else None
    active_label = own_label if own_label is not None else label
    siblings = tuple(str(key) for key in obj)
    for key, value in obj.items():
        key_text = str(key)
        child_concrete = f"{concrete}.{key_text}"
        child_normalized = f"{normalized}.{key_text}"
        child_container = containers.get(key_text, container)
        if _is_container_object(key_text, value, containers):
            assert isinstance(value, dict)
            objects.append(
                _object_observation(
                    probe,
                    child_normalized,
                    containers[key_text],
                    "container",
                    value,
                    freshness_key,
                )
            )
        if _is_container_list(key_text, value, containers):
            assert isinstance(value, list)
            for element in value:
                if isinstance(element, dict):
                    objects.append(
                        _object_observation(
                            probe,
                            f"{child_normalized}[*]",
                            containers[key_text],
                            "container",
                            element,
                            freshness_key,
                        )
                    )
        if isinstance(value, dict):
            _walk_object(
                value,
                concrete=child_concrete,
                normalized=child_normalized,
                container=child_container if key_text in containers else container,
                label=active_label,
                probe=probe,
                policy_patterns=policy_patterns,
                containers=containers,
                label_key=label_key,
                freshness_key=freshness_key,
                fields=fields,
                objects=objects,
                send_values=send_values,
                max_value_chars=max_value_chars,
                structural_patterns=structural_patterns,
            )
            if key_text not in containers and _layer_value(value.get(label_key)) is not None:
                layer = _layer_value(value.get(label_key))
                assert layer is not None
                objects.append(
                    _object_observation(
                        probe, child_normalized, layer, "field_label", value, freshness_key
                    )
                )
            continue
        if isinstance(value, list) and not _scalar_list(value):
            for index, element in enumerate(value):
                element_concrete = f"{child_concrete}[{index}]"
                element_normalized = f"{child_normalized}[*]"
                element_container = containers.get(key_text, container)
                if isinstance(element, dict):
                    _walk_object(
                        element,
                        concrete=element_concrete,
                        normalized=element_normalized,
                        container=element_container,
                        label=active_label,
                        probe=probe,
                        policy_patterns=policy_patterns,
                        containers=containers,
                        label_key=label_key,
                        freshness_key=freshness_key,
                        fields=fields,
                        objects=objects,
                        send_values=send_values,
                        max_value_chars=max_value_chars,
                        structural_patterns=structural_patterns,
                    )
                    labelled = _layer_value(element.get(label_key))
                    if key_text not in containers and labelled is not None:
                        objects.append(
                            _object_observation(
                                probe,
                                element_normalized,
                                labelled,
                                "field_label",
                                element,
                                freshness_key,
                            )
                        )
                elif _is_scalar(element):
                    _append_leaf(
                        fields,
                        probe=probe,
                        concrete=element_concrete,
                        normalized=element_normalized,
                        parent=normalized,
                        key=key_text,
                        value=element,
                        value_type=_scalar_type(element),
                        container=element_container,
                        label=active_label,
                        siblings=siblings,
                        structural=_is_structural(key_text, policy_patterns, structural_patterns),
                        send_values=send_values,
                        max_value_chars=max_value_chars,
                    )
            continue
        value_type: Literal["string", "number", "boolean", "null", "list"] = (
            "list" if isinstance(value, list) else _scalar_type(value)
        )
        _append_leaf(
            fields,
            probe=probe,
            concrete=child_concrete,
            normalized=child_normalized,
            parent=normalized,
            key=key_text,
            value=value,
            value_type=value_type,
            container=container,
            label=active_label,
            siblings=siblings,
            structural=_is_structural(key_text, policy_patterns, structural_patterns),
            send_values=send_values,
            max_value_chars=max_value_chars,
        )


def _append_text_leaves(
    texts: tuple[str, ...],
    probe: ProbeResult,
    fields: list[FieldObservation],
    *,
    send_values: SendValues,
    max_value_chars: int,
) -> None:
    for index, text in enumerate(texts):
        preview, length = _preview(text, "text", send_values, max_value_chars)
        fields.append(
            FieldObservation(
                probe_id=probe.probe_id,
                tool_name=probe.tool_name,
                concrete_path=f"$text[{index}]",
                normalized_path="$text[*]",
                parent_path="$text",
                key="text",
                value_type="text",
                value_preview=preview,
                value_length=length,
                container_layer=None,
                field_label=None,
                sibling_keys=(),
                is_structural=False,
            )
        )


def _append_leaf(
    fields: list[FieldObservation],
    *,
    probe: ProbeResult,
    concrete: str,
    normalized: str,
    parent: str,
    key: str,
    value: object,
    value_type: Literal["string", "number", "boolean", "null", "list", "text"],
    container: Layer | None,
    label: Layer | None,
    siblings: tuple[str, ...],
    structural: bool,
    send_values: SendValues,
    max_value_chars: int,
) -> None:
    preview, length = _preview(value, value_type, send_values, max_value_chars)
    fields.append(
        FieldObservation(
            probe_id=probe.probe_id,
            tool_name=probe.tool_name,
            concrete_path=concrete,
            normalized_path=normalized,
            parent_path=parent,
            key=key,
            value_type=value_type,
            value_preview=preview,
            value_length=length,
            container_layer=container,
            field_label=label,
            sibling_keys=siblings,
            is_structural=structural,
        )
    )


def _object_observation(
    probe: ProbeResult,
    path: str,
    layer: Layer,
    source: Literal["container", "field_label"],
    obj: dict[str, object],
    freshness_key: str,
) -> ObjectObservation:
    raw = obj.get(freshness_key) if freshness_key in obj else None
    freshness = raw if isinstance(raw, str) else (None if raw is None else str(raw))
    if freshness_key not in obj:
        freshness = None
    return ObjectObservation(
        probe_id=probe.probe_id,
        tool_name=probe.tool_name,
        normalized_path=path,
        layer=layer,
        source=source,
        keys=tuple(str(key) for key in obj),
        freshness_value=freshness,
    )


def _is_container_object(key: str, value: object, containers: dict[str, Layer]) -> bool:
    return key in containers and isinstance(value, dict)


def _is_container_list(key: str, value: object, containers: dict[str, Layer]) -> bool:
    return key in containers and isinstance(value, list)


def _scalar_list(value: list[object]) -> bool:
    return all(_is_scalar(item) for item in value)


def _is_scalar(value: object) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _scalar_type(value: object) -> Literal["string", "number", "boolean", "null"]:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "string"


def _layer_value(value: object) -> Layer | None:
    if not isinstance(value, str):
        return None
    return _LAYERS.get(value)


def _structural_keys(policy: Policy) -> set[str]:
    keys = {
        policy.envelope.inference_flag_key,
        policy.envelope.field_label_key,
        policy.envelope.layer_container_keys.certified,
        policy.envelope.layer_container_keys.observed,
        policy.envelope.layer_container_keys.inferred,
        policy.freshness.key,
    }
    for key in policy.envelope.governance_notice_keys:
        keys.add(key.removeprefix("_meta.") if key.startswith("_meta.") else key)
    keys.update(policy.provenance_keys.certified)
    keys.update(policy.provenance_keys.observed)
    keys.update(policy.provenance_keys.inferred)
    return keys


def _is_structural(key: str, exact: set[str], patterns: tuple[str, ...]) -> bool:
    if key in exact:
        return True
    folded = key.casefold()
    return any(_fnmatch(folded, pattern.casefold()) for pattern in patterns)


def _fnmatch(name: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatch(name, pattern)


def _preview(
    value: object,
    value_type: str,
    send_values: SendValues,
    max_value_chars: int,
) -> tuple[str, int]:
    if value_type == "list":
        rendered = json.dumps(value, ensure_ascii=False)
    elif value_type == "boolean":
        rendered = "true" if value else "false"
    elif value_type == "null":
        rendered = "null"
    elif value_type == "number":
        rendered = json.dumps(value)
    else:
        rendered = str(value)
    if send_values == "none":
        return "", len(rendered)
    if send_values == "truncated":
        return rendered[:max_value_chars], len(rendered)
    return rendered, len(rendered)
