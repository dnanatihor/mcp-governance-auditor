"""Domain models (§6)."""

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class Severity(str, Enum):  # noqa: UP042
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def rank(self) -> int:
        """Higher rank is more severe: critical > high > medium > low > info."""
        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank() < other.rank()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank() <= other.rank()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank() > other.rank()

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank() >= other.rank()


class Layer(str, Enum):  # noqa: UP042
    CERTIFIED = "certified"
    OBSERVED = "observed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


ProbeDecision = Literal[
    "probe",
    "skip_mode_off",
    "skip_denylisted",
    "skip_destructive",
    "skip_not_allowlisted",
    "skip_no_input",
]


class ServerInfo(Frozen):
    name: str | None
    version: str | None
    protocol_version: str | None
    transport: Literal["stdio", "streamable_http", "sse"]
    endpoint: str


class ToolDescriptor(Frozen):
    name: str
    description: str | None = None
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None
    risk_score: float = 0.0
    inference_risk: bool = False
    probe_decision: ProbeDecision | None = None


class ProbeRequest(Frozen):
    probe_id: str
    tool_name: str
    arguments: dict[str, Any]
    input_source: Literal["fixture", "empty", "llm_generated"]


class ProbeResult(Frozen):
    probe_id: str
    tool_name: str
    arguments: dict[str, Any]
    input_source: Literal["fixture", "empty", "llm_generated"]
    status: Literal["ok", "tool_error", "timeout", "transport_error"]
    structured_content: dict[str, Any] | None
    text_content: tuple[str, ...]
    meta: dict[str, Any] | None
    error_message: str | None
    latency_ms: int
    captured_at: datetime


class ProbeEnvelope(Frozen):
    probe_id: str
    tool_name: str
    parse_mode: Literal["structured", "text_json", "text", "none"]
    inference_flag_present: bool
    inference_flag_value: bool | None
    governance_notice_present: bool
    inferred_container_nonempty: bool
    truncated: bool


class FieldObservation(Frozen):
    probe_id: str
    tool_name: str
    concrete_path: str
    normalized_path: str
    parent_path: str
    key: str
    value_type: Literal["string", "number", "boolean", "null", "list", "text"]
    value_preview: str
    value_length: int
    container_layer: Layer | None
    field_label: Layer | None
    sibling_keys: tuple[str, ...]
    is_structural: bool


class ObjectObservation(Frozen):
    probe_id: str
    tool_name: str
    normalized_path: str
    layer: Layer
    source: Literal["container", "field_label"]
    keys: tuple[str, ...]
    freshness_value: str | None


class FieldClassification(Frozen):
    probe_id: str
    tool_name: str
    normalized_path: str
    concrete_path: str
    parent_path: str
    layer: Layer
    method: Literal["field_label", "envelope_label", "policy_pattern", "llm", "none"]
    confidence: float
    evidence: str
    mixed_layers: bool = False
    crosscheck_disagreement: bool = False
    prompt_version: str | None = None
    model: str | None = None


class Occurrence(Frozen):
    probe_id: str | None = None
    concrete_path: str | None = None
    line: int | None = None
    detail: str | None = None


ReviewStatus = Literal["not_required", "pending", "confirmed", "dismissed", "downgraded"]


class Finding(Frozen):
    finding_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    scope: Literal["manifest", "response", "coverage", "static"]
    tool_name: str | None = None
    normalized_path: str | None = None
    file_path: str | None = None
    symbol: str | None = None
    evidence: str
    remediation: str
    basis: Literal["deterministic", "llm_assisted", "heuristic"]
    needs_human_review: bool
    review_status: ReviewStatus = "not_required"
    review_note: str | None = None
    occurrences: tuple[Occurrence, ...] = ()
    framework_refs: tuple[str, ...] = ()


class ReviewDecision(Frozen):
    finding_id: str
    decision: Literal["confirm", "dismiss", "downgrade"]
    severity: Severity | None = None
    note: str | None = None


class AuditMetrics(Frozen):
    probe_coverage: float | None
    explicit_label_coverage: float | None
    inference_disclosure_rate: float | None
    governance_notice_rate: float | None
    unknown_rate: float | None


class LLMFieldVerdict(BaseModel):
    field_path: str
    layer: Literal["certified", "observed", "inferred", "unknown"]
    confidence: float = Field(ge=0.0, le=1.0)
    mixed_layers: bool = False
    evidence: str = Field(max_length=300)


class LLMClassificationBatch(BaseModel):
    verdicts: list[LLMFieldVerdict]


class LLMProbeInputs(BaseModel):
    argument_sets: list[dict[str, Any]]


class FieldClassifier(Protocol):
    prompt_version: str
    model_id: str

    async def classify(
        self,
        tool: ToolDescriptor,
        fields: list[FieldObservation],
        *,
        crosscheck: bool = False,
    ) -> list[LLMFieldVerdict]: ...


class ProbePlanner(Protocol):
    prompt_version: str
    model_id: str

    async def generate(
        self,
        tool: ToolDescriptor,
        seeds: dict[str, list[str]],
        n: int,
    ) -> list[dict[str, Any]]: ...
