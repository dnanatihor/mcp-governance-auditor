"""Helpers shared by unit tests."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write_audit_config(tmp_path: Path, *, authorization: str = "Bearer token") -> Path:
    policy = (ROOT / "configs" / "policy.default.yaml").read_text(encoding="utf-8")
    (tmp_path / "policy.yaml").write_text(policy, encoding="utf-8")
    (tmp_path / "fixtures.yaml").write_text(
        "get_column_quality:\n  - {asset_id: col_email}\n",
        encoding="utf-8",
    )
    policy_path = (tmp_path / "policy.yaml").as_posix()
    fixtures_path = (tmp_path / "fixtures.yaml").as_posix()
    audit = f"""
run:
  name: demo
  fail_on: high
  fail_on_llm_assisted: false
  max_concurrency: 4
  tool_timeout_s: 30
  clock_override: null
target:
  transport: streamable_http
  url: http://localhost:8000/mcp
  headers:
    Authorization: "{authorization}"
  env:
    OE_API_BASE: "https://example.test"
probing:
  mode: safe
  allowlist: []
  denylist: ["delete_*"]
  max_probes_per_tool: 2
  fixtures_file: "{fixtures_path}"
  llm_generated_inputs: true
  seed_values:
    asset_id: ["tbl_orders", "col_email"]
llm:
  enabled: true
  classifier_model: "anthropic:claude-haiku-4-5-20251001"
  planner_model: "anthropic:claude-sonnet-5"
  temperature: 0
  batch_size: 25
  send_values: truncated
  max_value_chars: 200
  min_confidence: 0.7
  crosscheck_labelled_certified: false
  cache_dir: .mcpaudit_cache
redaction:
  extra_patterns: []
policy_file: "{policy_path}"
static_scan:
  enabled: false
  repo_path: ../oe_mcp
  include: ["**/*.py"]
  exclude: ["tests/**"]
  telemetry_flush_function_names: ["flush_telemetry"]
  tool_decorator_patterns: ["*.tool"]
review:
  enabled: false
output:
  dir: ./reports
  formats: [json, md]
  save_raw: true
  include_classifications: true
"""
    path = tmp_path / "audit.yaml"
    path.write_text(audit, encoding="utf-8")
    return path
