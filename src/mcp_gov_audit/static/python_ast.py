"""Select, parse, and describe Python sources for OBS-001 and OBS-002 (§12)."""

from __future__ import annotations

import ast
import fnmatch
import re
from pathlib import Path
from typing import Literal

import structlog

from mcp_gov_audit.models import Frozen

_LOG = structlog.get_logger()
_HTTP_CLIENTS = frozenset({"httpx.Client", "httpx.AsyncClient"})
_INSTRUMENTOR = "opentelemetry.instrumentation.httpx.HTTPXClientInstrumentor"
_INJECT = "opentelemetry.propagate.inject"
_BATCH_TYPES = frozenset(
    {"BatchSpanProcessor", "BatchLogRecordProcessor", "PeriodicExportingMetricReader"}
)
_EXIT_FUNCTIONS = frozenset({"shutdown", "lifespan", "on_shutdown"})
FlushContext = Literal["per_request", "exit_only", "other"]


class ClientSite(Frozen):
    file_path: str
    symbol: str
    line: int
    callee: str
    variable: str | None = None


class ModuleFacts(Frozen):
    file_path: str
    clients: tuple[ClientSite, ...]
    mitigated_variables: tuple[str, ...]
    has_propagate_inject: bool


class FlushSite(Frozen):
    file_path: str
    symbol: str
    line: int
    context: FlushContext


class OtherClientSite(Frozen):
    """HTTP client construction outside the httpx-only OBS-001 check."""

    file_path: str
    line: int
    callee: str
    language: str


class StaticAnalysis(Frozen):
    modules: tuple[ModuleFacts, ...]
    repo_instrumented: bool
    has_batch_processor: bool
    flush_sites: tuple[FlushSite, ...]
    other_clients: tuple[OtherClientSite, ...] = ()


def analyze_repository(
    repo_path: Path,
    *,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
    telemetry_flush_function_names: tuple[str, ...],
    tool_decorator_patterns: tuple[str, ...],
) -> StaticAnalysis:
    """Parse every selected file. Unparsable files are logged and skipped."""
    repo = repo_path if repo_path.is_absolute() else Path.cwd() / repo_path
    if not repo.is_dir():
        _LOG.warning("static_scan_repo_missing", repo_path=str(repo))
        return StaticAnalysis(
            modules=(),
            repo_instrumented=False,
            has_batch_processor=False,
            flush_sites=(),
        )
    from mcp_gov_audit.static.other_clients import scan_other_clients

    modules: list[ModuleFacts] = []
    flush_sites: list[FlushSite] = []
    other_clients: list[OtherClientSite] = []
    repo_instrumented = False
    has_batch_processor = False
    for path in _select_files(repo, include, exclude):
        relative = path.resolve().relative_to(repo.resolve()).as_posix()
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _LOG.warning("skipped_unparsable_file", file_path=relative, error=str(exc))
            continue
        if path.suffix.lower() not in {".py", ".pyw"}:
            other_clients.extend(scan_other_clients(relative, source))
            continue
        try:
            tree = ast.parse(source, filename=relative)
        except SyntaxError as exc:
            _LOG.warning("skipped_unparsable_file", file_path=relative, error=str(exc))
            continue
        other_clients.extend(scan_other_clients(relative, source))
        parsed = _analyze_tree(
            tree,
            file_path=relative,
            flush_names=frozenset(telemetry_flush_function_names),
            decorator_patterns=tool_decorator_patterns,
        )
        modules.append(parsed.module)
        flush_sites.extend(parsed.flush_sites)
        repo_instrumented = repo_instrumented or parsed.repo_instrumented
        has_batch_processor = has_batch_processor or parsed.has_batch_processor
    return StaticAnalysis(
        modules=tuple(modules),
        repo_instrumented=repo_instrumented,
        has_batch_processor=has_batch_processor,
        flush_sites=tuple(flush_sites),
        other_clients=tuple(other_clients),
    )


class _ParsedFile:
    def __init__(
        self,
        module: ModuleFacts,
        flush_sites: list[FlushSite],
        *,
        repo_instrumented: bool,
        has_batch_processor: bool,
    ) -> None:
        self.module = module
        self.flush_sites = flush_sites
        self.repo_instrumented = repo_instrumented
        self.has_batch_processor = has_batch_processor


class _Frame:
    def __init__(
        self,
        *,
        kind: Literal["function", "class"],
        name: str,
        is_async: bool,
        decorators: tuple[str, ...],
        node: ast.AST,
    ) -> None:
        self.kind = kind
        self.name = name
        self.is_async = is_async
        self.decorators = decorators
        self.node = node


class _State:
    def __init__(
        self,
        frames: tuple[_Frame, ...],
        *,
        in_while: bool,
        in_finally: bool,
    ) -> None:
        self.frames = frames
        self.in_while = in_while
        self.in_finally = in_finally

    def enter_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> _State:
        decorators = tuple(
            name for item in node.decorator_list if (name := _decorator_name(item)) is not None
        )
        frame = _Frame(
            kind="function",
            name=node.name,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            decorators=decorators,
            node=node,
        )
        return _State((*self.frames, frame), in_while=False, in_finally=False)

    def enter_class(self, node: ast.ClassDef) -> _State:
        frame = _Frame(
            kind="class",
            name=node.name,
            is_async=False,
            decorators=(),
            node=node,
        )
        return _State(
            (*self.frames, frame),
            in_while=self.in_while,
            in_finally=self.in_finally,
        )

    def enter_while(self) -> _State:
        return _State(self.frames, in_while=True, in_finally=self.in_finally)

    def enter_finally(self) -> _State:
        return _State(self.frames, in_while=self.in_while, in_finally=True)

    def symbol(self) -> str:
        if not any(frame.kind == "function" for frame in self.frames):
            return "<module>"
        parts: list[str] = []
        previous_function = False
        for frame in self.frames:
            if frame.kind == "function" and previous_function:
                parts.append("<locals>")
            parts.append(frame.name)
            previous_function = frame.kind == "function"
        return ".".join(parts)

    def innermost_function(self) -> _Frame | None:
        for frame in reversed(self.frames):
            if frame.kind == "function":
                return frame
        return None


def _analyze_tree(
    tree: ast.AST,
    *,
    file_path: str,
    flush_names: frozenset[str],
    decorator_patterns: tuple[str, ...],
) -> _ParsedFile:
    bound = _bindings(tree)
    parents = _parents(tree)
    registered = _atexit_functions(tree, bound)
    clients: list[ClientSite] = []
    mitigated: list[str] = []
    flush_sites: list[FlushSite] = []
    flags = {"instrumented": False, "inject": False, "batch": False}
    tail_cache: dict[int, set[int]] = {}

    def record(call: ast.Call, state: _State) -> None:
        resolved = _resolve(call.func, bound)
        if resolved in _HTTP_CLIENTS:
            clients.append(
                ClientSite(
                    file_path=file_path,
                    symbol=state.symbol(),
                    line=call.lineno,
                    callee=resolved,
                    variable=_assigned_variable(call, parents),
                )
            )
        if _is_global_instrument(call, bound):
            flags["instrumented"] = True
        if resolved == _INJECT:
            flags["inject"] = True
        if _is_instrument_client(call, bound):
            variable = _first_argument_name(call)
            if variable is not None:
                mitigated.append(variable)
        if resolved is not None and resolved.split(".")[-1] in _BATCH_TYPES:
            flags["batch"] = True
        if _is_flush(call, bound, flush_names):
            flush_sites.append(
                FlushSite(
                    file_path=file_path,
                    symbol=state.symbol(),
                    line=call.lineno,
                    context=_flush_context(
                        call,
                        state,
                        bound=bound,
                        flush_names=flush_names,
                        decorator_patterns=decorator_patterns,
                        registered=registered,
                        tail_cache=tail_cache,
                    ),
                )
            )

    def visit(node: ast.AST, state: _State) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                visit(decorator, state)
            entered = state.enter_function(node)
            for statement in node.body:
                visit(statement, entered)
            return
        if isinstance(node, ast.ClassDef):
            entered = state.enter_class(node)
            for statement in node.body:
                visit(statement, entered)
            return
        if isinstance(node, ast.While):
            looped = state.enter_while()
            visit(node.test, looped)
            for statement in node.body:
                visit(statement, looped)
            for statement in node.orelse:
                visit(statement, state)
            return
        if isinstance(node, ast.Try):
            for statement in node.body:
                visit(statement, state)
            for handler in node.handlers:
                visit(handler, state)
            final = state.enter_finally()
            for statement in node.finalbody:
                visit(statement, final)
            for statement in node.orelse:
                visit(statement, state)
            return
        if isinstance(node, ast.Call):
            record(call=node, state=state)
        for child in ast.iter_child_nodes(node):
            visit(child, state)

    visit(tree, _State((), in_while=False, in_finally=False))
    return _ParsedFile(
        ModuleFacts(
            file_path=file_path,
            clients=tuple(clients),
            mitigated_variables=tuple(dict.fromkeys(mitigated)),
            has_propagate_inject=flags["inject"],
        ),
        flush_sites,
        repo_instrumented=flags["instrumented"],
        has_batch_processor=flags["batch"],
    )


def _flush_context(
    call: ast.Call,
    state: _State,
    *,
    bound: dict[str, str],
    flush_names: frozenset[str],
    decorator_patterns: tuple[str, ...],
    registered: set[str],
    tail_cache: dict[int, set[int]],
) -> FlushContext:
    if state.in_while or _decorated(state, decorator_patterns) or _handles_request(state):
        return "per_request"
    if _named_exit(state, registered) or _main_exit(call, state, bound, flush_names, tail_cache):
        return "exit_only"
    return "other"


def _decorated(state: _State, patterns: tuple[str, ...]) -> bool:
    for frame in state.frames:
        if frame.kind != "function":
            continue
        for name in frame.decorators:
            if any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns):
                return True
    return False


def _handles_request(state: _State) -> bool:
    return any(
        frame.kind == "function" and frame.is_async and fnmatch.fnmatchcase(frame.name, "handle_*")
        for frame in state.frames
    )


def _named_exit(state: _State, registered: set[str]) -> bool:
    return any(
        frame.kind == "function" and (frame.name in _EXIT_FUNCTIONS or frame.name in registered)
        for frame in state.frames
    )


def _main_exit(
    call: ast.Call,
    state: _State,
    bound: dict[str, str],
    flush_names: frozenset[str],
    tail_cache: dict[int, set[int]],
) -> bool:
    frame = state.innermost_function()
    if frame is None or frame.name != "main":
        return False
    if state.in_finally:
        return True
    if not isinstance(frame.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    key = id(frame.node)
    if key not in tail_cache:
        tail_cache[key] = _tail_flush_ids(frame.node, bound, flush_names)
    return id(call) in tail_cache[key]


def _tail_flush_ids(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    bound: dict[str, str],
    flush_names: frozenset[str],
) -> set[int]:
    index = len(func.body)
    while index > 0 and _is_cleanup(func.body[index - 1], bound, flush_names):
        index -= 1
    found: set[int] = set()
    for statement in func.body[index:]:
        found.update(_flush_ids(statement, bound, flush_names))
    return found


def _is_cleanup(statement: ast.stmt, bound: dict[str, str], flush_names: frozenset[str]) -> bool:
    if isinstance(statement, ast.Pass):
        return True
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
        return _is_flush(statement.value, bound, flush_names)
    if isinstance(statement, ast.Return):
        return statement.value is None or (
            isinstance(statement.value, ast.Call) and _is_flush(statement.value, bound, flush_names)
        )
    return False


def _flush_ids(node: ast.AST, bound: dict[str, str], flush_names: frozenset[str]) -> set[int]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return set()
    found: set[int] = set()
    if isinstance(node, ast.Call) and _is_flush(node, bound, flush_names):
        found.add(id(node))
    for child in ast.iter_child_nodes(node):
        found.update(_flush_ids(child, bound, flush_names))
    return found


def _bindings(tree: ast.AST) -> dict[str, str]:
    bound: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bound[alias.asname] = alias.name
                else:
                    bound[alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return bound


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _resolve(node: ast.expr, bound: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return bound.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _resolve(node.value, bound)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


def _is_flush(call: ast.Call, bound: dict[str, str], names: frozenset[str]) -> bool:
    simple = call.func.attr if isinstance(call.func, ast.Attribute) else None
    if isinstance(call.func, ast.Name):
        simple = call.func.id
    if simple in names:
        return True
    resolved = _resolve(call.func, bound)
    return resolved is not None and resolved.split(".")[-1] in names


def _is_global_instrument(call: ast.Call, bound: dict[str, str]) -> bool:
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr != "instrument":
        return False
    if not isinstance(func.value, ast.Call):
        return False
    return _resolve(func.value.func, bound) == _INSTRUMENTOR


def _is_instrument_client(call: ast.Call, bound: dict[str, str]) -> bool:
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr != "instrument_client":
        return False
    target = func.value.func if isinstance(func.value, ast.Call) else func.value
    return _resolve(target, bound) == _INSTRUMENTOR


def _assigned_variable(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> str | None:
    parent = parents.get(call)
    if isinstance(parent, ast.Assign) and len(parent.targets) == 1:
        return _target_name(parent.targets[0])
    if isinstance(parent, ast.AnnAssign):
        return _target_name(parent.target)
    if isinstance(parent, ast.withitem) and parent.optional_vars is not None:
        return _target_name(parent.optional_vars)
    return None


def _first_argument_name(call: ast.Call) -> str | None:
    if call.args:
        return _target_name(call.args[0])
    for keyword in call.keywords:
        if keyword.arg == "client":
            return _target_name(keyword.value)
    return None


def _target_name(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _target_name(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


def _decorator_name(node: ast.expr) -> str | None:
    target = node.func if isinstance(node, ast.Call) else node
    return _resolve(target, {})


def _atexit_functions(tree: ast.AST, bound: dict[str, str]) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if _resolve(target, bound) == "atexit.register":
                    names.add(node.name)
        if (
            isinstance(node, ast.Call)
            and _resolve(node.func, bound) == "atexit.register"
            and node.args
            and isinstance(node.args[0], ast.Name)
        ):
            names.add(node.args[0].id)
    return names


def _select_files(repo: Path, include: tuple[str, ...], exclude: tuple[str, ...]) -> list[Path]:
    chosen: set[Path] = set()
    for pattern in include:
        for path in repo.glob(pattern):
            if path.is_file():
                chosen.add(path.resolve())
    root = repo.resolve()
    kept: list[Path] = []
    for path in sorted(chosen):
        relative = path.relative_to(root).as_posix()
        if any(_glob_match(relative, pattern) for pattern in exclude):
            continue
        kept.append(path)
    return kept


def _glob_match(path: str, pattern: str) -> bool:
    return re.fullmatch(_glob_to_regex(pattern), path) is not None


def _glob_to_regex(pattern: str) -> str:
    parts: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            parts.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            parts.append(".*")
            index += 2
        elif pattern[index] == "*":
            parts.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            parts.append("[^/]")
            index += 1
        else:
            parts.append(re.escape(pattern[index]))
            index += 1
    return "".join(parts)
