# Testing against a live MCP server

Confirmed against the OvalEdge MCP server (`OvalEdge MCP Server` 2.0.0, protocol `2025-11-25`) on 28 Sep 2026.

| Step | Command | Result |
|---|---|---|
| Introspect | `mcpaudit introspect` | Exit 0. 15 tools listed. No tool was called. |
| Safe audit | `mcpaudit run --no-llm` | Exit 1, verdict `fail`. Three read-only tools were probed and all returned ok. |

The shared docs connector is not available in this session, so this runbook lives in the repo.

## Before you start

Work from the repository root.

Put the OvalEdge token and secret in the environment. Do not write them into YAML. `run_config.json` stores header keys with empty values, and the confirmed run directory contained neither secret.

```bash
export OE_OVALEDGE_TOKEN='…'
export OE_OVALEDGE_SECRET='…'
```

The config used for the confirmed run is `configs/audit.oe.yaml`. It points `target.transport` at `streamable_http`, sets the API Gateway URL, and reads the two headers from those variables. Probing mode is `safe`, `llm.enabled` is false, and `llm_generated_inputs` is false.

A connect that does not finish within 30 seconds is reported as exit 3.

## 1. Introspect

This lists tools, triages them, and evaluates MAN rules. It never calls a tool.

```bash
uv run mcpaudit introspect -c configs/audit.oe.yaml --output-dir ./reports/introspect-oe
```

Exit codes: 0 connected, 2 bad config, 3 unreachable or `initialize` failed.

Confirmed output:

- Exit 0. Manifest: `reports/introspect-oe/manifest.json`.
- Server accepted the session (`HTTP 200`, protocol `2025-11-25`).
- 15 tools. Eligible tools print as `probe`. Writes matching `update_*` or `create_*` are `skip_denylisted`. `dq_rule_advisor` and `dq_rule_manager` are `skip_not_allowlisted` because safe mode requires `readOnlyHint: true`.
- Every tool produced MAN-002 (output schema does not declare the inference flag).

## 2. Safe audit without an LLM

Run this after introspect succeeds. `--no-llm` keeps responses off a model provider. Safe mode still calls eligible read-only tools. Tools with required arguments and no fixture are skipped, not called.

`configs/probe_fixtures.example.yaml` only contains the fake catalog ids `tbl_orders` and `col_email`. It does not match this server's tool names, so those fixtures were not used.

```bash
uv run mcpaudit run -c configs/audit.oe.yaml --no-llm --output-dir ./reports
```

The command prints the run directory and `verdict=pass` or `verdict=fail`. Exit 1 means at least one active finding is at or above `fail_on` (`high` in this config). Exit 0 means none are.

Confirmed run `reports/20260928T034550Z-9cedd8`:

- Exit 1, verdict `fail`.
- `report.md` contains Summary, Target and run, Coverage, Epistemic distribution, Findings, Static findings, and Appendix.
- Coverage: 15 tools, 3 probed, 12 not probed (`skip_no_input` 3, `skip_denylisted` 7, `skip_not_allowlisted` 2). 3 probes, 0 failed.
- Called, all ok: `asset_explorer`, `metadata_changes_between_crawls`, `knowledge_search`. They have no required arguments, so they were called with `{}`.
- Not called because an id or `operation` is required and no fixture exists: `asset_details`, `asset_lineage`, `access_explorer`.
- Not called because of the denylist or missing `readOnlyHint`: the `update_*` / `create_*` tools, `dq_rule_advisor`, `dq_rule_manager`.
- Findings: MAN-002 on all 15 tools (medium), COV-001 on the 12 unprobed tools (info), and on `metadata_changes_between_crawls` EPI-001 (high), EPI-003 at `$.data.recommendedJob` (high), EPI-009 (medium). The two high findings make the verdict fail.
- Metrics: probe coverage 0.200, explicit label coverage 0.000, inference disclosure 0.000, governance notice 0.000, unknown rate 0.996.
- Header secrets were absent from `run_config.json` and from every file in the run directory.

## What this run did not cover

- LLM classification and the planner. Turn those on only with a provider key, and put real asset ids in `seed_values` and a fixtures file named for this server's tools.
- Human review (`review.enabled`) and `mcpaudit review`.
- Static analysis. `static_scan.repo_path` is still `../oe_mcp`.
- Probes of `asset_details`, `asset_lineage`, and `access_explorer`. Add fixtures with real `object_id` / `object_type` values you are allowed to read, then run again.
