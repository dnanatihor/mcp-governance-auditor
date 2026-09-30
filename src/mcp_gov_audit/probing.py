"""Probe input resolution (§9.3)."""

from __future__ import annotations

from typing import Any, Literal

import structlog
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from mcp_gov_audit.config import ProbeFixtures, ProbingConfig
from mcp_gov_audit.models import ProbePlanner, ProbeRequest, ToolDescriptor

InputSource = Literal["fixture", "empty", "llm_generated"]
_LOG = structlog.get_logger()


async def plan_probes(
    tools: list[ToolDescriptor],
    fixtures: ProbeFixtures,
    probing: ProbingConfig,
    *,
    planner: ProbePlanner | None = None,
    llm_enabled: bool = False,
) -> tuple[list[ToolDescriptor], list[ProbeRequest]]:
    """Set `probe` or `skip_no_input` on eligible tools and build the probe plan."""
    decided: list[ToolDescriptor] = []
    requests: list[ProbeRequest] = []
    for tool in tools:
        if tool.probe_decision is not None:
            decided.append(tool)
            continue
        argument_sets = await resolve_inputs(
            tool,
            fixtures,
            probing,
            planner=planner,
            llm_enabled=llm_enabled,
        )
        if not argument_sets:
            decided.append(tool.model_copy(update={"probe_decision": "skip_no_input"}))
            continue
        decided.append(tool.model_copy(update={"probe_decision": "probe"}))
        for index, (arguments, source) in enumerate(argument_sets):
            requests.append(
                ProbeRequest(
                    probe_id=f"{tool.name}#{index}",
                    tool_name=tool.name,
                    arguments=arguments,
                    input_source=source,
                )
            )
    return decided, requests


async def resolve_inputs(
    tool: ToolDescriptor,
    fixtures: ProbeFixtures,
    probing: ProbingConfig,
    *,
    planner: ProbePlanner | None = None,
    llm_enabled: bool = False,
) -> list[tuple[dict[str, Any], InputSource]]:
    """Return validated argument sets for an eligible tool."""
    fixture_sets = fixtures.get(tool.name, ())
    if fixture_sets:
        chosen = fixture_sets[: probing.max_probes_per_tool]
        return _validated(tool, [(dict(arguments), "fixture") for arguments in chosen])
    required = tool.input_schema.get("required")
    if not isinstance(required, list) or len(required) == 0:
        return _validated(tool, [({}, "empty")])
    if llm_enabled and probing.llm_generated_inputs and planner is not None:
        seeds = {key: list(values) for key, values in probing.seed_values.items()}
        generated = await planner.generate(tool, seeds, probing.max_probes_per_tool)
        source: InputSource = "llm_generated"
        candidates = [
            (dict(arguments), source) for arguments in generated if isinstance(arguments, dict)
        ]
        return _validated(tool, candidates)
    return []


def _validated(
    tool: ToolDescriptor,
    candidates: list[tuple[dict[str, Any], InputSource]],
) -> list[tuple[dict[str, Any], InputSource]]:
    kept: list[tuple[dict[str, Any], InputSource]] = []
    try:
        validator = Draft202012Validator(tool.input_schema)
    except SchemaError as exc:
        _LOG.info("discarded_probe_input", tool_name=tool.name, reason=exc.message)
        return []
    for arguments, source in candidates:
        try:
            validator.validate(arguments)
        except ValidationError as exc:
            _LOG.info("discarded_probe_input", tool_name=tool.name, reason=exc.message)
            continue
        kept.append((arguments, source))
    return kept
