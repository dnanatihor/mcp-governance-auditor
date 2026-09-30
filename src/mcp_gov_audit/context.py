"""Run-scoped resources that must not enter graph state (§7.3)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from mcp import ClientSession

from mcp_gov_audit.classification.cache import ClassificationCache
from mcp_gov_audit.config import AuditConfig, Policy, ProbeFixtures
from mcp_gov_audit.models import FieldClassifier, ProbePlanner, ToolDescriptor


@dataclass
class AuditContext:
    config: AuditConfig
    policy: Policy
    policy_sha256: str
    session: ClientSession | None
    classifier: FieldClassifier | None
    planner: ProbePlanner | None
    cache: ClassificationCache
    semaphore: asyncio.Semaphore
    clock: Callable[[], datetime]
    run_dir: Path
    fixtures: ProbeFixtures
    # Send payloads do not include parent state, so plan_probes publishes the
    # decided tools here for probe_tool's re-check (§9.2).
    tools_by_name: dict[str, ToolDescriptor] = field(default_factory=dict)
