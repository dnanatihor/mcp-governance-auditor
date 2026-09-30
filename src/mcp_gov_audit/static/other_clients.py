"""HTTP clients other than httpx, including non-Python sources."""

from __future__ import annotations

import re

from mcp_gov_audit.static.python_ast import OtherClientSite

_PY = re.compile(
    r"\b(?:requests\.(?:Session|get|post|put|patch|delete|request)|"
    r"aiohttp\.ClientSession|urllib\.request\.urlopen)\b"
)
_JS = re.compile(r"\b(?:fetch|axios(?:\.\w+)?|got)\s*\(|require\([\"']node-fetch[\"']\)")
_GO = re.compile(r"\bhttp\.(?:Client\{|Get|Post|NewRequest)\b")
_JAVA = re.compile(r"\b(?:HttpClient\.newHttpClient|RestTemplate|WebClient\.create)\b")
_PY_INSTRUMENTED = re.compile(
    r"opentelemetry\.(?:propagate|instrumentation\.(?:requests|aiohttp|urllib))"
)
_JS_INSTRUMENTED = re.compile(r"@opentelemetry/")
_GO_INSTRUMENTED = re.compile(r"go\.opentelemetry\.io/otel")
_JAVA_INSTRUMENTED = re.compile(r"io\.opentelemetry")


def scan_other_clients(file_path: str, source: str) -> list[OtherClientSite]:
    """Return uninstrumented client sites. httpx stays on the Python AST path."""
    suffix = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    if suffix in {"py", "pyw"}:
        return _sites(file_path, source, "python", _PY, _PY_INSTRUMENTED)
    if suffix in {"js", "jsx", "ts", "tsx", "mjs", "cjs"}:
        return _sites(file_path, source, "javascript", _JS, _JS_INSTRUMENTED)
    if suffix == "go":
        return _sites(file_path, source, "go", _GO, _GO_INSTRUMENTED)
    if suffix == "java":
        return _sites(file_path, source, "java", _JAVA, _JAVA_INSTRUMENTED)
    return []


def _sites(
    file_path: str,
    source: str,
    language: str,
    call: re.Pattern[str],
    instrumented: re.Pattern[str],
) -> list[OtherClientSite]:
    if instrumented.search(source):
        return []
    found: list[OtherClientSite] = []
    for index, line in enumerate(source.splitlines(), start=1):
        match = call.search(line)
        if match is None:
            continue
        found.append(
            OtherClientSite(
                file_path=file_path,
                line=index,
                callee=match.group(0),
                language=language,
            )
        )
    return found
