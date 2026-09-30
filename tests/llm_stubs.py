"""In-process stand-ins for the classifier and planner. No network."""

from __future__ import annotations

from typing import Any

from mcp_gov_audit.models import FieldObservation, LLMFieldVerdict, ToolDescriptor


class StubClassifier:
    prompt_version = "classify_field.v1"
    model_id = "stub"

    def __init__(
        self,
        verdicts: dict[str, LLMFieldVerdict] | None = None,
        *,
        scripted: list[list[LLMFieldVerdict]] | None = None,
    ) -> None:
        self.verdicts = verdicts or {}
        self.scripted = scripted
        self.calls = 0
        self.batches: list[list[str]] = []

    async def classify(
        self,
        tool: ToolDescriptor,
        fields: list[FieldObservation],
        *,
        crosscheck: bool = False,
    ) -> list[LLMFieldVerdict]:
        del tool, crosscheck
        self.calls += 1
        self.batches.append([field.normalized_path for field in fields])
        if self.scripted is not None:
            return self.scripted.pop(0)
        produced: list[LLMFieldVerdict] = []
        for field in fields:
            verdict = self.verdicts.get(field.normalized_path)
            if verdict is None:
                verdict = LLMFieldVerdict(
                    field_path=field.normalized_path,
                    layer="unknown",
                    confidence=0.2,
                    evidence="no stub verdict",
                )
            produced.append(verdict)
        return produced


class StubPlanner:
    prompt_version = "generate_probe_input.v1"
    model_id = "stub-planner"

    def __init__(self, argument_sets: list[dict[str, Any]]) -> None:
        self.argument_sets = argument_sets
        self.calls = 0

    async def generate(
        self,
        tool: ToolDescriptor,
        seeds: dict[str, list[str]],
        n: int,
    ) -> list[dict[str, Any]]:
        del tool, seeds
        self.calls += 1
        return [dict(item) for item in self.argument_sets[:n]]
