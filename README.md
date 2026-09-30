# MCP Governance Auditor

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/badge/lint-ruff-D7FF64?logo=ruff&logoColor=black)](https://docs.astral.sh/ruff/)
[![mypy](https://img.shields.io/badge/types-mypy%20strict-blue)](https://mypy-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Audits an MCP server's tools and responses so certified facts, observed profiles, and AI inferences stay separated and disclosed.

The auditor connects to a running server, lists its tools, probes only what the safety policy allows, classifies response fields by epistemic layer, and writes a JSON report, a Markdown report, and a CI exit code. Target-specific names live in a policy file, so the same program can audit more than one catalog server.

The design contract is [SPEC.md](SPEC.md).

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

The console script is `mcpaudit`.

## Quick start

```bash
cp configs/audit.example.yaml audit.yaml
# Put secrets in the environment. Do not paste them into the YAML.
export OE_MCP_TOKEN='…'

uv run mcpaudit introspect -c audit.yaml --output-dir ./reports/introspect
uv run mcpaudit run -c audit.yaml --no-llm --output-dir ./reports
```

`introspect` lists tools, triages them, and evaluates manifest rules. It never calls a tool.

`run` probes eligible read-only tools and writes `report.json` and `report.md` under `./reports/<run-id>/`. The command prints that directory and `verdict=pass` or `verdict=fail`.

Start with `--no-llm`. A later run can classify unmatched fields with a model only after you set a provider key and real fixture identifiers.

## Commands

| Command | What it does |
|---|---|
| `mcpaudit introspect -c audit.yaml [--output-dir DIR]` | Connect, list, triage, MAN rules, write `manifest.json` |
| `mcpaudit run -c audit.yaml [--no-llm] [--no-cache] [--static-only] [--fail-on LEVEL] [--output-dir DIR]` | Full audit |
| `mcpaudit review RUN_ID [--output-dir DIR]` | Resume a run paused for human review |
| `mcpaudit diff OLD_RUN_DIR NEW_RUN_DIR [--json] [--fail-on LEVEL]` | Compare finding ids |
| `mcpaudit rules [--json]` | List rule id, name, scope, and default severity |

`${VAR}` in YAML is filled from the environment. A missing variable or invalid config exits 2 and names the key.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No active finding at or above `fail_on` |
| 1 | At least one active finding at or above `fail_on` |
| 2 | Configuration or internal error |
| 3 | Target unreachable, or `initialize` failed |
| 4 | Run paused for human review |

A finding is inactive when it is dismissed. With `fail_on_llm_assisted: false`, a pending `llm_assisted` finding does not fail the run.

## Safety

- `safe` mode calls a tool only when `readOnlyHint` is true or the name is on the allowlist. Denylist matches and `destructiveHint: true` are never called.
- `open` mode also probes tools that omit annotations. An explicit destructive hint and the denylist still apply.
- Responses are masked before they are stored. `target.headers` and `target.env` are omitted from `run_config.json`.
- Do not commit live audit files, tokens, or `reports/`. Those paths are gitignored.

## Configuration

| File | Role |
|---|---|
| `configs/audit.example.yaml` | Transports, probing mode, models, output |
| `configs/policy.default.yaml` | Layer containers, field patterns, severity |
| `configs/probe_fixtures.example.yaml` | Sample arguments for read-only probes |

Copy the examples. Point `policy_file` and `fixtures_file` at your own files. The default policy looks for `inference_permitted`, `certified_findings`, `profiling_observations`, `ai_inferences`, and `epistemic_layer`. A server that uses different names needs its own policy before the findings mean much.

Static analysis is optional. Set `static_scan.enabled` and `static_scan.repo_path` to the server's source tree. It covers Python `httpx` (OBS-001), telemetry flush (OBS-002), and other HTTP clients in Python, JavaScript, Go, and Java (OBS-003).

## Development

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
```

The stdio fixture server used by tests is `tests/fixtures/fake_catalog_server.py`. Tests do not call the network. Live model calls are opt-in with `RUN_LIVE=1`.

## License

[MIT](LICENSE)
