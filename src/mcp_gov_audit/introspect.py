"""List and triage tools without calling them (§14)."""

from __future__ import annotations

from mcp_gov_audit.config import LoadedConfig
from mcp_gov_audit.graph.run import make_clock
from mcp_gov_audit.mcp_client.operations import list_all_tools
from mcp_gov_audit.mcp_client.session import open_session
from mcp_gov_audit.models import Finding, ToolDescriptor
from mcp_gov_audit.rules import REGISTRY, evaluate_rules
from mcp_gov_audit.rules.base import RuleContext
from mcp_gov_audit.rules.security import remote_auth_configured
from mcp_gov_audit.triage import triage_tools


async def introspect_server(loaded: LoadedConfig) -> tuple[list[ToolDescriptor], list[Finding]]:
    """Connect, list tools, triage, and evaluate MAN rules. Never calls tools/call."""
    async with open_session(loaded.audit.target) as session:
        listed = await list_all_tools(session)
    tools = triage_tools(listed, loaded.audit.probing, loaded.policy)
    findings = evaluate_rules(
        RuleContext(
            tools=tools,
            probes=[],
            envelopes=[],
            fields=[],
            objects=[],
            classifications=[],
            policy=loaded.policy,
            now=make_clock(loaded.audit.run.clock_override)(),
            remote_auth_configured=remote_auth_configured(loaded.audit.target),
        ),
        rule_ids=tuple(rule_id for rule_id in sorted(REGISTRY) if rule_id.startswith("MAN-")),
    )
    return tools, findings
