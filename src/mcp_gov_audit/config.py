"""Audit and policy configuration (§5)."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, TypeAlias, TypeVar, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, field_validator

from mcp_gov_audit.models import Severity

_ENV_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

ModelT = TypeVar("ModelT", bound=BaseModel)
LoaderT = TypeVar("LoaderT")
ProbeFixtures: TypeAlias = dict[str, tuple[dict[str, Any], ...]]
_PROBE_FIXTURES: TypeAdapter[ProbeFixtures] = TypeAdapter(ProbeFixtures)


class ConfigError(Exception):
    """A config file failed to load. `key` is the first offending path."""

    def __init__(self, errors: list[tuple[str, str]]) -> None:
        if not errors:
            raise ValueError("ConfigError requires at least one error")
        self.errors: tuple[tuple[str, str], ...] = tuple(errors)
        self.key: str = errors[0][0]
        message = "; ".join(f"{key}: {detail}" for key, detail in errors)
        super().__init__(message)


class ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RunConfig(ConfigModel):
    name: str
    fail_on: Severity
    fail_on_llm_assisted: bool
    max_concurrency: int
    tool_timeout_s: float
    clock_override: str | None

    @field_validator("clock_override", mode="before")
    @classmethod
    def _validate_clock_override(cls, value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            rendered = value.isoformat()
            if rendered.endswith("+00:00"):
                return rendered.removesuffix("+00:00") + "Z"
            return rendered
        if not isinstance(value, str):
            raise ValueError("must be an ISO-8601 timestamp")
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("must be an ISO-8601 timestamp") from exc
        return value


class TargetConfig(ConfigModel):
    transport: Literal["stdio", "streamable_http", "sse"]
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = Field(default_factory=dict)


class ProbingConfig(ConfigModel):
    mode: Literal["safe", "allowlist", "off", "open"]
    allowlist: tuple[str, ...]
    denylist: tuple[str, ...]
    max_probes_per_tool: int
    fixtures_file: str
    llm_generated_inputs: bool
    seed_values: dict[str, tuple[str, ...]]


class LLMConfig(ConfigModel):
    enabled: bool
    classifier_model: str
    planner_model: str
    temperature: float
    batch_size: int
    send_values: Literal["none", "truncated", "full"]
    max_value_chars: int
    min_confidence: float
    crosscheck_labelled_certified: bool
    cache_dir: str


class RedactionConfig(ConfigModel):
    extra_patterns: tuple[str, ...]


class StaticScanConfig(ConfigModel):
    enabled: bool
    repo_path: str
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    telemetry_flush_function_names: tuple[str, ...]
    tool_decorator_patterns: tuple[str, ...]


class ReviewConfig(ConfigModel):
    enabled: bool


class OutputConfig(ConfigModel):
    dir: str
    formats: tuple[Literal["json", "md"], ...]
    save_raw: bool
    include_classifications: bool


class AuditConfig(ConfigModel):
    run: RunConfig
    target: TargetConfig
    probing: ProbingConfig
    llm: LLMConfig
    redaction: RedactionConfig
    policy_file: str
    static_scan: StaticScanConfig
    review: ReviewConfig
    output: OutputConfig

    def without_secrets(self) -> AuditConfig:
        """Return a copy with `target.headers` and `target.env` removed."""
        return self.model_copy(
            update={"target": self.target.model_copy(update={"headers": {}, "env": {}})}
        )


class LayerContainerKeys(ConfigModel):
    certified: str
    observed: str
    inferred: str


class EnvelopePolicy(ConfigModel):
    inference_flag_key: str
    governance_notice_keys: tuple[str, ...]
    layer_container_keys: LayerContainerKeys
    field_label_key: str


class ProvenanceKeys(ConfigModel):
    certified: tuple[str, ...]
    observed: tuple[str, ...]
    inferred: tuple[str, ...]


class FreshnessPolicy(ConfigModel):
    key: str
    observation_max_age_days: int


class FieldPatterns(ConfigModel):
    certified: tuple[str, ...]
    observed: tuple[str, ...]
    inferred: tuple[str, ...]


class InferenceRiskPolicy(ConfigModel):
    keywords: tuple[str, ...]
    min_score: float


class Policy(ConfigModel):
    policy_version: str
    envelope: EnvelopePolicy
    provenance_keys: ProvenanceKeys
    freshness: FreshnessPolicy
    field_patterns: FieldPatterns
    structural_patterns: tuple[str, ...]
    inference_risk: InferenceRiskPolicy
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)
    framework_refs: dict[str, tuple[str, ...]] = Field(default_factory=dict)


class LoadedConfig(ConfigModel):
    audit: AuditConfig
    policy: Policy
    probe_fixtures: ProbeFixtures


def load_config(path: Path) -> LoadedConfig:
    """Load audit.yaml, the policy it names, and its probe fixtures."""
    audit = load_audit_config(path)
    policy = _load_sibling(
        Path(audit.policy_file),
        key="policy_file",
        loader=load_policy,
    )
    probe_fixtures = _load_sibling(
        Path(audit.probing.fixtures_file),
        key="probing.fixtures_file",
        loader=load_probe_fixtures,
    )
    return LoadedConfig(audit=audit, policy=policy, probe_fixtures=probe_fixtures)


def load_audit_config(path: Path) -> AuditConfig:
    data = _load_mapping(path)
    return _validate(AuditConfig, data, fallback=str(path))


def load_policy(path: Path) -> Policy:
    data = _load_mapping(path)
    return _validate(Policy, data, fallback=str(path))


def load_probe_fixtures(path: Path) -> ProbeFixtures:
    data = _load_mapping(path)
    try:
        return _PROBE_FIXTURES.validate_python(data)
    except ValidationError as exc:
        raise ConfigError(_validation_errors(exc, str(path))) from exc


def _load_sibling(path: Path, *, key: str, loader: Callable[[Path], LoaderT]) -> LoaderT:
    if not path.is_file():
        raise ConfigError([(key, f"file not found: {path}")])
    try:
        return loader(path)
    except ConfigError as exc:
        if len(exc.errors) == 1 and exc.errors[0][0] == str(path):
            raise ConfigError([(key, exc.errors[0][1])]) from exc
        raise


def _load_mapping(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        detail = exc.strerror or "cannot read config file"
        raise ConfigError([(str(path), detail)]) from exc
    try:
        loaded: object = cast(object, yaml.safe_load(text))
    except yaml.YAMLError as exc:
        raise ConfigError([(str(path), "invalid YAML")]) from exc
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise ConfigError([(str(path), "config file must be a mapping")])
    errors: list[tuple[str, str]] = []
    interpolated = _interpolate(loaded, "", errors)
    if errors:
        raise ConfigError(errors)
    if not isinstance(interpolated, dict):
        raise ConfigError([(str(path), "config file must be a mapping")])
    return cast(dict[str, Any], interpolated)


def _interpolate(value: object, key: str, errors: list[tuple[str, str]]) -> object:
    if isinstance(value, str):
        return _interpolate_string(value, key, errors)
    if isinstance(value, list):
        items = cast(list[object], value)
        return [_interpolate(item, _join(key, index), errors) for index, item in enumerate(items)]
    if isinstance(value, dict):
        mapping = cast(dict[object, object], value)
        interpolated: dict[str, object] = {}
        for raw_key, item in mapping.items():
            if not isinstance(raw_key, str):
                parent = key or "<root>"
                errors.append((parent, f"mapping key {raw_key!r} must be a string"))
                continue
            interpolated[raw_key] = _interpolate(item, _join(key, raw_key), errors)
        return interpolated
    return value


def _interpolate_string(value: str, key: str, errors: list[tuple[str, str]]) -> str:
    def replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        if var_name not in os.environ:
            errors.append((key or "<root>", f"missing environment variable {var_name}"))
            return match.group(0)
        return os.environ[var_name]

    return _ENV_VAR.sub(replace, value)


def _join(parent: str, child: str | int) -> str:
    if isinstance(child, int):
        return f"{parent}[{child}]"
    if parent:
        return f"{parent}.{child}"
    return child


def _validate(model: type[ModelT], data: dict[str, Any], *, fallback: str) -> ModelT:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(_validation_errors(exc, fallback)) from exc


def _validation_errors(exc: ValidationError, fallback: str) -> list[tuple[str, str]]:
    errors: list[tuple[str, str]] = []
    for err in exc.errors():
        loc = cast(tuple[object, ...], err.get("loc", ()))
        key = _format_loc(loc) if loc else fallback
        message = str(err.get("msg", "invalid value"))
        errors.append((key, message))
    if not errors:
        errors.append((fallback, "invalid configuration"))
    return errors


def _format_loc(loc: tuple[object, ...]) -> str:
    key = ""
    for part in loc:
        if isinstance(part, int):
            key = f"{key}[{part}]"
        else:
            text = str(part)
            key = f"{key}.{text}" if key else text
    return key
