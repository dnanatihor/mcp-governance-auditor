"""LangChain classifiers and the §10.4 classification procedure."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from jinja2 import Environment, StrictUndefined

from mcp_gov_audit.classification.cache import ClassificationCache, cache_key
from mcp_gov_audit.models import (
    FieldClassification,
    FieldObservation,
    Layer,
    LLMClassificationBatch,
    LLMFieldVerdict,
    LLMProbeInputs,
    ToolDescriptor,
)

_PROMPTS = Path(__file__).resolve().parent / "prompts"
_JINJA = Environment(undefined=StrictUndefined, autoescape=False)
CLASSIFY_PROMPT_VERSION = "classify_field.v1"
PLANNER_PROMPT_VERSION = "generate_probe_input.v1"


def load_prompt(name: str) -> tuple[str, str]:
    """Split a versioned prompt file into system and user bodies."""
    text = (_PROMPTS / f"{name}.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    if text.startswith("\n"):
        text = text.lstrip("\n")
    heading = "## system\n"
    if not text.startswith(heading):
        raise ValueError(f"{name} is missing the ## system section")
    body = text[len(heading) :]
    marker = "\n## user\n"
    if marker not in body:
        raise ValueError(f"{name} is missing the ## user section")
    system, user = body.split(marker, 1)
    return system.strip("\n"), user.strip("\n")


def render_prompt(name: str, variables: dict[str, object]) -> tuple[str, str]:
    system_text, user_text = load_prompt(name)
    system = _JINJA.from_string(system_text).render(**variables)
    user = _JINJA.from_string(user_text).render(**variables)
    return system, user


def parse_classification_payload(payload: object) -> list[LLMFieldVerdict]:
    """Turn a structured-output payload into verdicts."""
    if isinstance(payload, LLMClassificationBatch):
        return list(payload.verdicts)
    if isinstance(payload, dict):
        return list(LLMClassificationBatch.model_validate(payload).verdicts)
    raise TypeError(f"unsupported classification payload: {type(payload).__name__}")


def parse_probe_input_payload(payload: object) -> list[dict[str, Any]]:
    if isinstance(payload, LLMProbeInputs):
        return [dict(item) for item in payload.argument_sets]
    if isinstance(payload, dict):
        parsed = LLMProbeInputs.model_validate(payload)
        return [dict(item) for item in parsed.argument_sets]
    raise TypeError(f"unsupported probe-input payload: {type(payload).__name__}")


class LangChainFieldClassifier:
    """FieldClassifier backed by `init_chat_model` and structured output."""

    prompt_version = CLASSIFY_PROMPT_VERSION

    def __init__(self, model_id: str, *, temperature: float = 0, runnable: Any = None) -> None:
        self.model_id = model_id
        self._temperature = temperature
        self._runnable = runnable

    async def classify(
        self,
        tool: ToolDescriptor,
        fields: list[FieldObservation],
        *,
        crosscheck: bool = False,
    ) -> list[LLMFieldVerdict]:
        del crosscheck
        system, user = _render_classify(tool, fields)
        payload = await self._model().ainvoke(_messages(system, user))
        return parse_classification_payload(payload)

    def _model(self) -> Any:
        if self._runnable is None:
            from langchain.chat_models import init_chat_model

            chat = init_chat_model(self.model_id, temperature=self._temperature)
            self._runnable = chat.with_structured_output(LLMClassificationBatch)
        return self._runnable


class LangChainProbePlanner:
    """ProbePlanner backed by `init_chat_model` and structured output."""

    prompt_version = PLANNER_PROMPT_VERSION

    def __init__(self, model_id: str, *, temperature: float = 0, runnable: Any = None) -> None:
        self.model_id = model_id
        self._temperature = temperature
        self._runnable = runnable

    async def generate(
        self,
        tool: ToolDescriptor,
        seeds: dict[str, list[str]],
        n: int,
    ) -> list[dict[str, Any]]:
        system, user = _render_planner(tool, seeds, n)
        payload = await self._model().ainvoke(_messages(system, user))
        return parse_probe_input_payload(payload)[:n]

    def _model(self) -> Any:
        if self._runnable is None:
            from langchain.chat_models import init_chat_model

            chat = init_chat_model(self.model_id, temperature=self._temperature)
            self._runnable = chat.with_structured_output(LLMProbeInputs)
        return self._runnable


async def classify_with_model(
    *,
    fields: list[FieldObservation],
    deterministic: list[FieldClassification],
    tools: list[ToolDescriptor],
    classifier: Any,
    cache: ClassificationCache,
    batch_size: int,
    min_confidence: float,
    crosscheck: bool,
) -> list[FieldClassification]:
    """Fill row-4 residuals from the classifier, then optionally cross-check certified labels."""
    by_name = {tool.name: tool for tool in tools}
    decided = {(item.probe_id, item.normalized_path) for item in deterministic}
    residuals = [
        field
        for field in fields
        if not field.is_structural and (field.probe_id, field.normalized_path) not in decided
    ]
    produced = list(deterministic)
    produced.extend(
        await _classify_fields(
            residuals,
            by_name,
            classifier,
            cache,
            batch_size=batch_size,
            min_confidence=min_confidence,
            crosscheck=False,
        )
    )
    if crosscheck:
        produced = await _crosscheck(
            produced,
            fields,
            by_name,
            classifier,
            cache,
            batch_size=batch_size,
            min_confidence=min_confidence,
        )
    return produced


async def _classify_fields(
    fields: list[FieldObservation],
    tools: dict[str, ToolDescriptor],
    classifier: Any,
    cache: ClassificationCache,
    *,
    batch_size: int,
    min_confidence: float,
    crosscheck: bool,
) -> list[FieldClassification]:
    classified: list[FieldClassification] = []
    grouped: dict[tuple[str, str], list[FieldObservation]] = defaultdict(list)
    for field in fields:
        grouped[(field.tool_name, field.probe_id)].append(field)
    for (tool_name, _probe_id), probe_fields in grouped.items():
        tool = tools.get(tool_name)
        if tool is None:
            continue
        for chunk in _chunks(probe_fields, batch_size):
            classified.extend(
                await _classify_chunk(
                    tool,
                    chunk,
                    classifier,
                    cache,
                    min_confidence=min_confidence,
                    crosscheck=crosscheck,
                )
            )
    return classified


async def _classify_chunk(
    tool: ToolDescriptor,
    fields: list[FieldObservation],
    classifier: Any,
    cache: ClassificationCache,
    *,
    min_confidence: float,
    crosscheck: bool,
) -> list[FieldClassification]:
    pending: list[FieldObservation] = []
    cached: dict[str, LLMFieldVerdict] = {}
    for field in fields:
        key = _key(classifier, tool.name, field)
        hit = cache.get(key)
        if hit is None:
            pending.append(field)
        else:
            cached[field.normalized_path] = hit
    fresh = await _request_verdicts(classifier, tool, pending, crosscheck=crosscheck)
    for field in pending:
        verdict = fresh.get(field.normalized_path)
        if verdict is None:
            continue
        cache.put(_key(classifier, tool.name, field), verdict)
    results: list[FieldClassification] = []
    for field in fields:
        verdict = cached.get(field.normalized_path) or fresh.get(field.normalized_path)
        if verdict is None:
            results.append(_mismatch(field, classifier))
        else:
            results.append(_from_verdict(field, verdict, classifier, min_confidence))
    return results


async def _request_verdicts(
    classifier: Any,
    tool: ToolDescriptor,
    fields: list[FieldObservation],
    *,
    crosscheck: bool,
) -> dict[str, LLMFieldVerdict]:
    if not fields:
        return {}
    verdicts = await classifier.classify(tool, fields, crosscheck=crosscheck)
    matched = _exact_verdicts(fields, verdicts)
    if matched is None:
        verdicts = await classifier.classify(tool, fields, crosscheck=crosscheck)
        matched = _exact_verdicts(fields, verdicts)
    if matched is not None:
        return matched
    return _unique_verdicts(verdicts)


async def _crosscheck(
    classifications: list[FieldClassification],
    fields: list[FieldObservation],
    tools: dict[str, ToolDescriptor],
    classifier: Any,
    cache: ClassificationCache,
    *,
    batch_size: int,
    min_confidence: float,
) -> list[FieldClassification]:
    by_identity = {(field.probe_id, field.normalized_path): field for field in fields}
    selected: list[FieldObservation] = []
    for item in classifications:
        if item.layer != Layer.CERTIFIED or item.method not in {"field_label", "envelope_label"}:
            continue
        field = by_identity.get((item.probe_id, item.normalized_path))
        if field is None or field.value_type not in {"string", "text"}:
            continue
        selected.append(field)
    verdicts = await _verdicts_for_fields(
        selected,
        tools,
        classifier,
        cache,
        batch_size=batch_size,
        crosscheck=True,
    )
    updated: list[FieldClassification] = []
    for item in classifications:
        verdict = verdicts.get((item.probe_id, item.normalized_path))
        if (
            verdict is not None
            and verdict.layer == "inferred"
            and verdict.confidence >= min_confidence
        ):
            updated.append(item.model_copy(update={"crosscheck_disagreement": True}))
        else:
            updated.append(item)
    return updated


async def _verdicts_for_fields(
    fields: list[FieldObservation],
    tools: dict[str, ToolDescriptor],
    classifier: Any,
    cache: ClassificationCache,
    *,
    batch_size: int,
    crosscheck: bool,
) -> dict[tuple[str, str], LLMFieldVerdict]:
    found: dict[tuple[str, str], LLMFieldVerdict] = {}
    grouped: dict[tuple[str, str], list[FieldObservation]] = defaultdict(list)
    for field in fields:
        grouped[(field.tool_name, field.probe_id)].append(field)
    for (tool_name, _probe_id), probe_fields in grouped.items():
        tool = tools.get(tool_name)
        if tool is None:
            continue
        for chunk in _chunks(probe_fields, batch_size):
            pending: list[FieldObservation] = []
            for field in chunk:
                hit = cache.get(_key(classifier, tool.name, field))
                if hit is None:
                    pending.append(field)
                else:
                    found[(field.probe_id, field.normalized_path)] = hit
            fresh = await _request_verdicts(classifier, tool, pending, crosscheck=crosscheck)
            for field in pending:
                verdict = fresh.get(field.normalized_path)
                if verdict is None:
                    continue
                cache.put(_key(classifier, tool.name, field), verdict)
                found[(field.probe_id, field.normalized_path)] = verdict
    return found


def _from_verdict(
    field: FieldObservation,
    verdict: LLMFieldVerdict,
    classifier: Any,
    min_confidence: float,
) -> FieldClassification:
    layer = Layer(verdict.layer)
    if verdict.confidence < min_confidence:
        layer = Layer.UNKNOWN
    return FieldClassification(
        probe_id=field.probe_id,
        tool_name=field.tool_name,
        normalized_path=field.normalized_path,
        concrete_path=field.concrete_path,
        parent_path=field.parent_path,
        layer=layer,
        method="llm",
        confidence=verdict.confidence,
        evidence=verdict.evidence,
        mixed_layers=verdict.mixed_layers,
        prompt_version=str(classifier.prompt_version),
        model=str(classifier.model_id),
    )


def _mismatch(field: FieldObservation, classifier: Any) -> FieldClassification:
    return FieldClassification(
        probe_id=field.probe_id,
        tool_name=field.tool_name,
        normalized_path=field.normalized_path,
        concrete_path=field.concrete_path,
        parent_path=field.parent_path,
        layer=Layer.UNKNOWN,
        method="llm",
        confidence=0.0,
        evidence="llm_output_mismatch",
        prompt_version=str(classifier.prompt_version),
        model=str(classifier.model_id),
    )


def _exact_verdicts(
    fields: list[FieldObservation],
    verdicts: list[LLMFieldVerdict],
) -> dict[str, LLMFieldVerdict] | None:
    if len(verdicts) != len(fields):
        return None
    unique = _unique_verdicts(verdicts)
    expected = {field.normalized_path for field in fields}
    if set(unique) != expected:
        return None
    return unique


def _unique_verdicts(verdicts: list[LLMFieldVerdict]) -> dict[str, LLMFieldVerdict]:
    counts: dict[str, int] = defaultdict(int)
    chosen: dict[str, LLMFieldVerdict] = {}
    for verdict in verdicts:
        counts[verdict.field_path] += 1
        chosen[verdict.field_path] = verdict
    return {path: verdict for path, verdict in chosen.items() if counts[path] == 1}


def _key(classifier: Any, tool_name: str, field: FieldObservation) -> str:
    return cache_key(
        prompt_version=str(classifier.prompt_version),
        model_id=str(classifier.model_id),
        tool_name=tool_name,
        normalized_path=field.normalized_path,
        value_preview=field.value_preview,
    )


def _chunks(fields: list[FieldObservation], batch_size: int) -> list[list[FieldObservation]]:
    size = max(batch_size, 1)
    return [fields[index : index + size] for index in range(0, len(fields), size)]


def _render_classify(tool: ToolDescriptor, fields: list[FieldObservation]) -> tuple[str, str]:
    payload = [
        {
            "field_path": field.normalized_path,
            "key": field.key,
            "value_type": field.value_type,
            "value_preview": field.value_preview,
            "value_length": field.value_length,
            "sibling_keys": list(field.sibling_keys),
        }
        for field in fields
    ]
    return render_prompt(
        CLASSIFY_PROMPT_VERSION,
        {
            "tool_name": tool.name,
            "tool_description": tool.description or "",
            "fields_json": json.dumps(payload, ensure_ascii=False, indent=2),
        },
    )


def _render_planner(
    tool: ToolDescriptor,
    seeds: dict[str, list[str]],
    n: int,
) -> tuple[str, str]:
    return render_prompt(
        PLANNER_PROMPT_VERSION,
        {
            "n": n,
            "tool_name": tool.name,
            "tool_description": tool.description or "",
            "input_schema_json": json.dumps(tool.input_schema, ensure_ascii=False, indent=2),
            "seed_values_json": json.dumps(seeds, ensure_ascii=False, indent=2),
        },
    )


def _messages(system: str, user: str) -> list[Any]:
    from langchain_core.messages import HumanMessage, SystemMessage

    return [SystemMessage(content=system), HumanMessage(content=user)]
