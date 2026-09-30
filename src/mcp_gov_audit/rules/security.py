"""Defensive manifest checks for tool text, credential arguments, and remote auth."""

from __future__ import annotations

import re
from typing import Literal

from mcp_gov_audit.config import TargetConfig
from mcp_gov_audit.models import Finding, Severity, ToolDescriptor
from mcp_gov_audit.rules.base import RuleContext, finding_id, register_rule

_INJECTION = (
    re.compile(r"ignore (?:all |any |previous )?instructions", re.IGNORECASE),
    re.compile(r"disregard (?:the )?(?:system|developer|previous)", re.IGNORECASE),
    re.compile(r"do not tell the user", re.IGNORECASE),
    re.compile(r"exfiltrat", re.IGNORECASE),
    re.compile(r"send (?:the )?(?:secrets|credentials|api keys) to", re.IGNORECASE),
)
_CREDENTIAL_NAMES = frozenset(
    {
        "password",
        "passwd",
        "api_key",
        "apikey",
        "secret",
        "access_token",
        "refresh_token",
        "client_secret",
    }
)
_AUTH_MARKERS = ("authorization", "token", "secret", "api-key", "apikey")


def remote_auth_configured(target: TargetConfig) -> bool | None:
    """False when a remote transport has no auth-like header. stdio is not judged."""
    if target.transport == "stdio":
        return None
    names = [name.casefold() for name in target.headers]
    return any(any(marker in name for marker in _AUTH_MARKERS) for name in names)


@register_rule
class ToolDescriptionInjection:
    id = "SEC-001"
    name = "Tool description contains injected instructions"
    default_severity = Severity.HIGH
    scope: Literal["manifest"] = "manifest"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            text = tool.description or ""
            matched = next((hit for pattern in _INJECTION if (hit := pattern.search(text))), None)
            if matched is None:
                continue
            findings.append(
                _finding(
                    rule=self,
                    tool_name=tool.name,
                    evidence=f"description matches {matched.group(0)!r}",
                    remediation=(
                        "Remove instruction-like text from the tool description. "
                        "Descriptions must describe the tool, not steer the model."
                    ),
                )
            )
        return findings


@register_rule
class CredentialArgument:
    id = "SEC-002"
    name = "Tool input schema asks for a credential"
    default_severity = Severity.MEDIUM
    scope: Literal["manifest"] = "manifest"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            names = _credential_names(tool)
            if not names:
                continue
            listed = ", ".join(sorted(names))
            findings.append(
                _finding(
                    rule=self,
                    tool_name=tool.name,
                    evidence=f"input schema properties: {listed}",
                    remediation=(
                        f"Do not ask the model to supply {listed}. "
                        "Pass credentials on the server connection, not as tool arguments."
                    ),
                )
            )
        return findings


@register_rule
class RemoteTargetWithoutAuth:
    id = "SEC-003"
    name = "Remote target has no auth header"
    default_severity = Severity.HIGH
    scope: Literal["manifest"] = "manifest"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        if ctx.remote_auth_configured is not False:
            return []
        return [
            Finding(
                finding_id=finding_id(rule_id=self.id),
                rule_id=self.id,
                rule_name=self.name,
                severity=self.default_severity,
                scope=self.scope,
                evidence="streamable HTTP or SSE target headers include no auth-like name",
                remediation=(
                    "Set an Authorization, token, or secret header in target.headers. "
                    "Do not rely on an unauthenticated remote MCP session."
                ),
                basis="deterministic",
                needs_human_review=False,
            )
        ]


def _finding(
    *,
    rule: ToolDescriptionInjection | CredentialArgument,
    tool_name: str,
    evidence: str,
    remediation: str,
) -> Finding:
    return Finding(
        finding_id=finding_id(rule_id=rule.id, tool_name=tool_name),
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.default_severity,
        scope=rule.scope,
        tool_name=tool_name,
        evidence=evidence,
        remediation=remediation,
        basis="deterministic",
        needs_human_review=False,
    )


def _credential_names(tool: ToolDescriptor) -> set[str]:
    properties = tool.input_schema.get("properties")
    if not isinstance(properties, dict):
        return set()
    found: set[str] = set()
    for name in properties:
        if not isinstance(name, str):
            continue
        folded = name.casefold().replace("-", "_")
        if folded in _CREDENTIAL_NAMES:
            found.add(name)
    return found
