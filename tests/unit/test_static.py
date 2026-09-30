"""§15.5 static samples and OBS-001 / OBS-002."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.helpers import ROOT

from mcp_gov_audit.config import load_config, load_policy
from mcp_gov_audit.graph.run import run_until_normalize
from mcp_gov_audit.models import Finding
from mcp_gov_audit.rules import REGISTRY
from mcp_gov_audit.rules.base import RuleContext
from mcp_gov_audit.static.python_ast import analyze_repository

SAMPLES = ROOT / "tests" / "fixtures" / "static_samples"
NOW = datetime(2026, 9, 28, tzinfo=UTC)
POLICY = load_policy(ROOT / "configs" / "policy.default.yaml")
EXPECTED = {
    "uninstrumented_client": {("OBS-001", "httpx.AsyncClient")},
    "instrumented_global": set(),
    "inject_propagation": set(),
    "flush_per_request": {("OBS-002", "per_request")},
    "flush_exit_only_no_batch": {("OBS-002", "exit_only")},
    "flush_exit_with_batch": set(),
}


def _scan(repo: Path) -> list[Finding]:
    analysis = analyze_repository(
        repo,
        include=("**/*.py",),
        exclude=("tests/**", ".venv/**", "**/site-packages/**"),
        telemetry_flush_function_names=("flush_telemetry",),
        tool_decorator_patterns=("*.tool", "*.call_tool", "*.route", "*.get", "*.post"),
    )
    context = RuleContext(
        tools=[],
        probes=[],
        envelopes=[],
        fields=[],
        objects=[],
        classifications=[],
        policy=POLICY,
        now=NOW,
        static_analysis=analysis,
    )
    findings: list[Finding] = []
    for rule_id in ("OBS-001", "OBS-002"):
        findings.extend(REGISTRY[rule_id].evaluate(context))
    return findings


@pytest.mark.parametrize("case", sorted(EXPECTED))
@pytest.mark.asyncio
async def test_static_only_sample_matches_expected_findings(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    loaded = load_config(ROOT / "tests" / "fixtures" / "audit.fixture.yaml")
    audit = loaded.audit.model_copy(
        update={
            "static_scan": loaded.audit.static_scan.model_copy(
                update={"enabled": False, "repo_path": str(SAMPLES / case)}
            )
        }
    )
    completed = await run_until_normalize(
        loaded.model_copy(update={"audit": audit}),
        run_dir=tmp_path / case,
        static_only=True,
    )
    assert {(item.rule_id, item.evidence) for item in completed.findings} == EXPECTED[case]
    for finding in completed.findings:
        assert finding.tool_name is None
        assert finding.file_path == "app.py"
        assert finding.scope == "static"


def test_sample_basis_and_symbols() -> None:
    [client] = _scan(SAMPLES / "uninstrumented_client")
    assert client.basis == "deterministic"
    assert client.needs_human_review is False
    assert client.symbol == "<module>"
    assert client.occurrences[0].line == 3

    [per_request] = _scan(SAMPLES / "flush_per_request")
    assert per_request.basis == "heuristic"
    assert per_request.needs_human_review is True
    assert per_request.review_status == "pending"
    assert per_request.symbol == "lookup"

    [exit_only] = _scan(SAMPLES / "flush_exit_only_no_batch")
    assert exit_only.evidence == "exit_only"
    assert exit_only.symbol == "main"


def test_shifting_a_sample_keeps_the_finding_id(tmp_path: Path) -> None:
    original = _scan(SAMPLES / "uninstrumented_client")
    shifted = tmp_path / "shifted"
    shifted.mkdir()
    source = (SAMPLES / "uninstrumented_client" / "app.py").read_text(encoding="utf-8")
    (shifted / "app.py").write_text("\n" * 10 + source, encoding="utf-8")
    moved = _scan(shifted)
    assert moved[0].finding_id == original[0].finding_id
    assert moved[0].occurrences[0].line == original[0].occurrences[0].line + 10


def test_import_aliases_resolve_to_httpx_clients(tmp_path: Path) -> None:
    repo = tmp_path / "alias"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import httpx as h\nfrom httpx import Client as C\n\nh.AsyncClient()\nC()\n",
        encoding="utf-8",
    )
    [finding] = _scan(repo)
    assert finding.rule_id == "OBS-001"
    assert {item.detail for item in finding.occurrences} == {"httpx.AsyncClient", "httpx.Client"}


def test_instrument_client_suppresses_only_that_variable(tmp_path: Path) -> None:
    repo = tmp_path / "site"
    repo.mkdir()
    (repo / "app.py").write_text(
        "\n".join(
            [
                "import httpx",
                "from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor",
                "kept = httpx.AsyncClient()",
                "HTTPXClientInstrumentor.instrument_client(kept)",
                "flagged = httpx.Client()",
            ]
        ),
        encoding="utf-8",
    )
    [finding] = _scan(repo)
    assert finding.evidence == "httpx.Client"
    assert [item.line for item in finding.occurrences] == [5]


def test_global_instrument_in_another_file_suppresses_the_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "startup.py").write_text(
        "\n".join(
            [
                "from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor",
                "HTTPXClientInstrumentor().instrument()",
            ]
        ),
        encoding="utf-8",
    )
    (repo / "pkg" / "client.py").write_text(
        "import httpx\n\nclient = httpx.AsyncClient()\n",
        encoding="utf-8",
    )
    assert _scan(repo) == []


def test_exclude_globs_skip_matching_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    (repo / "tests" / "hidden.py").write_text(
        "import httpx\nclient = httpx.AsyncClient()\n",
        encoding="utf-8",
    )
    assert _scan(repo) == []


def test_unparsable_files_are_skipped(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bad.py").write_text("def (\n", encoding="utf-8")
    (repo / "app.py").write_text("import httpx\nhttpx.AsyncClient()\n", encoding="utf-8")
    [finding] = _scan(repo)
    assert finding.rule_id == "OBS-001"
    assert finding.file_path == "app.py"


def test_flush_inside_a_loop_or_shutdown_hook(tmp_path: Path) -> None:
    loop = tmp_path / "loop"
    loop.mkdir()
    (loop / "app.py").write_text(
        "\n".join(
            [
                "def flush_telemetry() -> None:",
                "    return None",
                "def worker() -> None:",
                "    while True:",
                "        flush_telemetry()",
                "        break",
            ]
        ),
        encoding="utf-8",
    )
    [per_request] = _scan(loop)
    assert per_request.rule_id == "OBS-002"
    assert per_request.evidence == "per_request"
    assert per_request.symbol == "worker"

    hook = tmp_path / "hook"
    hook.mkdir()
    (hook / "app.py").write_text(
        "\n".join(
            [
                "import atexit",
                "def flush_telemetry() -> None:",
                "    return None",
                "def cleanup() -> None:",
                "    flush_telemetry()",
                "atexit.register(cleanup)",
            ]
        ),
        encoding="utf-8",
    )
    [exit_only] = _scan(hook)
    assert exit_only.evidence == "exit_only"
    assert exit_only.symbol == "cleanup"
