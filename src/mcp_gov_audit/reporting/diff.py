"""Compare two report.json files by finding id (§13.7)."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_gov_audit.models import Finding, Frozen, Severity
from mcp_gov_audit.reporting.json_report import Report, load_report


class DiffEntry(Frozen):
    finding_id: str
    rule_id: str
    tool_name: str | None = None
    normalized_path: str | None = None
    file_path: str | None = None
    symbol: str | None = None
    severity: str
    basis: str
    review_status: str


class PersistingEntry(Frozen):
    finding_id: str
    rule_id: str
    tool_name: str | None = None
    normalized_path: str | None = None
    old_severity: str
    new_severity: str
    severity_changed: bool


class FindingDiff(Frozen):
    new: list[DiffEntry]
    resolved: list[DiffEntry]
    persisting: list[PersistingEntry]


def diff_reports(old: Report, new: Report) -> FindingDiff:
    """Group findings that appeared, disappeared, or remained."""
    old_by_id = {item.finding_id: item for item in old.findings}
    new_by_id = {item.finding_id: item for item in new.findings}
    appeared = [_entry(new_by_id[key]) for key in sorted(set(new_by_id) - set(old_by_id))]
    disappeared = [_entry(old_by_id[key]) for key in sorted(set(old_by_id) - set(new_by_id))]
    persisting = [
        PersistingEntry(
            finding_id=key,
            rule_id=new_by_id[key].rule_id,
            tool_name=new_by_id[key].tool_name,
            normalized_path=new_by_id[key].normalized_path,
            old_severity=old_by_id[key].severity.value,
            new_severity=new_by_id[key].severity.value,
            severity_changed=old_by_id[key].severity != new_by_id[key].severity,
        )
        for key in sorted(set(old_by_id) & set(new_by_id))
    ]
    return FindingDiff(new=appeared, resolved=disappeared, persisting=persisting)


def diff_exit_code(
    result: FindingDiff,
    *,
    fail_on: Severity,
    fail_on_llm_assisted: bool,
) -> int:
    """1 when a new active finding is at or above `fail_on`."""
    for entry in result.new:
        if not _entry_active(entry, fail_on_llm_assisted=fail_on_llm_assisted):
            continue
        if Severity(entry.severity).rank() >= fail_on.rank():
            return 1
    return 0


def load_run_diff(old_dir: Path, new_dir: Path) -> tuple[FindingDiff, Report]:
    result = diff_reports(
        load_report(old_dir / "report.json"),
        load_report(new_dir / "report.json"),
    )
    return result, load_report(new_dir / "report.json")


def fail_on_llm_assisted(run_dir: Path) -> bool:
    path = run_dir / "run_config.json"
    if not path.is_file():
        return False
    payload = json.loads(path.read_text(encoding="utf-8"))
    run = payload.get("run", {})
    if not isinstance(run, dict):
        return False
    return bool(run.get("fail_on_llm_assisted", False))


def format_diff(result: FindingDiff) -> str:
    lines = ["New"]
    lines.extend(_entry_lines(result.new) or ["- none"])
    lines.append("Resolved")
    lines.extend(_entry_lines(result.resolved) or ["- none"])
    lines.append("Persisting")
    if not result.persisting:
        lines.append("- none")
    for item in result.persisting:
        where = _where(item.tool_name, item.normalized_path)
        change = ""
        if item.severity_changed:
            change = f" severity {item.old_severity} -> {item.new_severity}"
        lines.append(f"- {item.rule_id} {where}{change}")
    return "\n".join(lines) + "\n"


def _entry(finding: Finding) -> DiffEntry:
    return DiffEntry(
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        tool_name=finding.tool_name,
        normalized_path=finding.normalized_path,
        file_path=finding.file_path,
        symbol=finding.symbol,
        severity=finding.severity.value,
        basis=finding.basis,
        review_status=finding.review_status,
    )


def _entry_active(entry: DiffEntry, *, fail_on_llm_assisted: bool) -> bool:
    pending_llm = (
        entry.basis == "llm_assisted"
        and entry.review_status == "pending"
        and not fail_on_llm_assisted
    )
    return entry.review_status != "dismissed" and not pending_llm


def _entry_lines(entries: list[DiffEntry]) -> list[str]:
    return [
        f"- {item.rule_id} {_where(item.tool_name, item.normalized_path)} {item.severity}"
        for item in entries
    ]


def _where(tool_name: str | None, path: str | None) -> str:
    place = tool_name or "—"
    if path:
        return f"{place} {path}"
    return place
