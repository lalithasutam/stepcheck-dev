"""Gate implementations. Private to StateKernel — reached only through commit()."""
from __future__ import annotations

import ast
import builtins
import re


def required_export_names(dependent_source: str, target_module: str) -> set[str]:
    """Names a flat dependent imports from `target_module` (its mechanical contract).
    Package-aware resolution lives in _okf.resolve_imports; this keeps the flat form."""
    from . import _okf

    return _okf.resolve_imports(
        "<dependent>", "<dependent>.py", dependent_source, {target_module: target_module}
    ).get(target_module, set())


def _bound_names(tree: ast.Module) -> set[str]:
    """Every name bound at module top level: defs, classes, assignments, imports —
    including those bound inside top-level `if` / `try` / `with` blocks (version
    shims and optional imports are exports too) and the strings a module lists
    in `__all__`, which a lazy package serves through a module-level
    `__getattr__` without ever binding them (pydantic's `__init__`)."""
    names: set[str] = set()

    def visit(stmts) -> None:
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(stmt.name)
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for t in targets:
                    names.update(n.id for n in ast.walk(t) if isinstance(n, ast.Name))
                value = getattr(stmt, "value", None)
                if (any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets)
                        and isinstance(value, (ast.List, ast.Tuple))):
                    names.update(
                        e.value for e in value.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    )
            elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
                for alias in stmt.names:
                    if alias.name != "*":
                        names.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(stmt, ast.If):
                visit(stmt.body)
                visit(stmt.orelse)
            elif isinstance(stmt, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                visit(stmt.body)
                for handler in stmt.handlers:
                    visit(handler.body)
                visit(stmt.orelse)
                visit(stmt.finalbody)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                visit(stmt.body)

    visit(tree.body)
    return names


def export_names(exports: list[str]) -> set[str]:
    out = set()
    for sig in exports:
        head = sig.split("(")[0]
        out.add(head.removeprefix("class ").strip())
    return out


def _stub_kind(body: list) -> str | None:
    """'...' / 'pass' / 'docstring-only' when a def body is a skeleton stub, else None."""
    stmts = body
    if stmts and isinstance(stmts[0], ast.Expr) and isinstance(stmts[0].value, ast.Constant) \
            and isinstance(stmts[0].value.value, str):
        stmts = stmts[1:]
    if not stmts:
        return "docstring-only"
    if len(stmts) == 1 and isinstance(stmts[0], ast.Pass):
        return "pass"
    if len(stmts) == 1 and isinstance(stmts[0], ast.Expr) and isinstance(stmts[0].value, ast.Constant) \
            and stmts[0].value.value is Ellipsis:
        return "..."
    return None


def _def_bodies(tree: ast.Module) -> dict[str, list]:
    """Qualified name -> body for top-level defs and (nested) class methods."""
    out: dict[str, list] = {}

    def visit(stmts, prefix: str) -> None:
        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out[prefix + s.name] = s.body
            elif isinstance(s, ast.ClassDef):
                visit(s.body, f"{prefix}{s.name}.")

    visit(tree.body, "")
    return out


def _stubbed_bodies(path: str, old_source: str, new_source: str) -> list[tuple[str, str]]:
    """Defs whose real body the staged source turns into a skeleton stub — what a
    whole-file write copied from an OKF frame (unfocused bodies shown as `...`)
    does. Python modules only."""
    if not str(path).endswith((".py", ".pyi")):
        return []
    try:
        old, new = _def_bodies(ast.parse(old_source)), _def_bodies(ast.parse(new_source))
    except SyntaxError:
        return []
    return [(name, kind) for name, body in old.items()
            if name in new and _stub_kind(body) is None and (kind := _stub_kind(new[name])) is not None]


def gate_b(node, staged_info, old_source: str, new_source: str, allow_deletion: bool) -> None:
    """Omission detection: symbol fingerprinting, skeleton-stub body overwrites
    (a def whose real body became `...` / `pass` / docstring-only), and the
    mass-deletion guard.

    Raises kernel.OmissionError. `allow_deletion=True` declares the deletion
    and bypasses both checks (GLOSSARY: Gate B). When several fingerprints are
    missing, the per-symbol one (`@dec on name`) is reported: it says which
    def or class lost its decorator.
    """
    from . import OmissionError, _okf

    if allow_deletion:
        return

    staged_symbols = set(staged_info.preserved_symbols)
    dropped = [s for s in node.info.preserved_symbols if s not in staged_symbols]
    if dropped:
        named = [s for s in dropped if " on " in s]
        raise OmissionError(
            f"preserved symbol '{(named or dropped)[0]}' of '{node.info.node_id}' was silently "
            f"dropped from the staged source",
            subtype="INTRA_NODE_SYMBOL_DROPPED",
        )

    stubbed = _stubbed_bodies(node.info.path, old_source, new_source)
    if stubbed:
        name, stub = stubbed[0]
        raise OmissionError(
            f"symbol '{name}' body was replaced with skeleton stub '{stub}' "
            f"(preserve original implementation or use patch replace_symbol)",
            subtype="INTRA_NODE_BODY_STUBBED",
        )

    old_n = _okf.statement_count(old_source)
    new_n = _okf.statement_count(new_source)
    if old_n and (old_n - new_n) / old_n > 0.15:
        lost = _lost_bindings(node.info.path, old_source, new_source)
        changed = sorted(set(node.info.exports) - set(staged_info.exports))
        if lost is None or lost or changed:
            what = f" (lost: {', '.join((lost or []) + changed)[:200]})" if lost or changed else ""
            raise OmissionError(
                f"staged source drops {old_n - new_n}/{old_n} AST statements "
                f"(> 15%) without allow_deletion=True{what}",
                subtype="INTRA_NODE_MASS_DELETION",
            )
        # Otherwise a concise refactor: every def, class, method and module- or
        # class-level binding survives with its exported signature, no body became
        # a stub (checked above), and Gate C still holds every mined guard clause.


def _bindings(tree: ast.Module) -> set[str]:
    """Named things a module defines: top-level and class-level defs, classes and
    assigned names, dotted by their owner class (`Box.width`)."""
    out: set[str] = set()

    def walk(body: list, prefix: str) -> None:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.add(prefix + stmt.name)
            elif isinstance(stmt, ast.ClassDef):
                out.add(prefix + stmt.name)
                walk(stmt.body, f"{prefix}{stmt.name}.")
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for t in targets:
                    out.update(prefix + n.id for n in ast.walk(t) if isinstance(n, ast.Name))

    walk(tree.body, "")
    return out


def _lost_bindings(path: str, old_source: str, new_source: str) -> list[str] | None:
    """Bindings of the old module missing from the new one (sorted); None when the
    sources are not Python (the plain statement-count rule then applies)."""
    if not str(path).endswith((".py", ".pyi")):
        return None
    try:
        old, new = _bindings(ast.parse(old_source)), _bindings(ast.parse(new_source))
    except SyntaxError:
        return None
    return sorted(old - new)


def unchanged_since_lock(node, source: str) -> bool:
    """Gate A's one exception to a lock: a commit to a LOCKED node that changes
    nothing — the staged source is the canonical one and the bytes the session
    last saw are the node's latest attestation (or, never attested since, the
    bytes it was locked with). Such a commit re-verifies the node against
    upstream changes (Gates B and C still run) instead of mutating it, so a
    DIRTY_OMISSION_RISK mark can be cleared. A file changed behind the session
    is still refused when the commit lands (`changed on disk since …`)."""
    if source != node.info.source or not node.disk_sha256:
        return False
    attested = node.verified[-1]["payload"]["sha256"] if node.verified else node.disk_sha256
    return node.disk_sha256 == attested


def gate_a(node_id: str, locked: bool, source: str, nodes) -> "ast.Module":
    """Mechanical & locked protection. Returns the parsed tree on pass.

    Raises kernel.MechanicalError on: locked mutation, syntax error, or a name a
    dependent imports from this module (absolute or relative, through packages)
    going missing from the staged module's top level. A module that defines a
    module-level `__getattr__` can serve any name, so the missing-export check
    does not apply to it.
    """
    from . import _okf as _okf_, _ts

    if locked and node_id in nodes and unchanged_since_lock(nodes[node_id], source):
        locked = False  # re-verification of the locked bytes, not a mutation
    _path = next((n.info.path for nid, n in nodes.items() if nid == node_id), f"{node_id}.py")
    _mod = _okf_.lang_module(_path)
    if _mod is not None:
        return _mod.gate_a(node_id, locked, source, nodes)
    from . import MechanicalError, _okf  # local import: avoid cycle at module load

    if locked:
        raise MechanicalError(
            f"node '{node_id}' is LOCKED — mutations are rejected at Gate A"
        )
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise MechanicalError(f"invalid AST syntax in '{node_id}': {exc.msg} (line {exc.lineno})")

    paths = {nid: n.info.path for nid, n in nodes.items()}
    modules = _okf.module_map(paths)
    staged = _okf.analyze(node_id, paths.get(node_id, f"{node_id}.py"), source, modules)
    bound = export_names(staged.exports) | _bound_names(tree)
    if "__getattr__" in bound:
        return tree
    for dep_id, dep_node in nodes.items():
        if dep_id == node_id or node_id not in dep_node.info.deps:
            continue
        required = _okf.resolve_imports(
            dep_id, dep_node.info.path, dep_node.info.source, modules
        ).get(node_id, set())
        missing = sorted(required - bound)
        if missing:
            raise MechanicalError(
                f"export '{missing[0]}' of '{node_id}' is required by dependent "
                f"'{dep_id}' and is missing from the staged source"
            )
    return tree


_CALL_RE = re.compile(r"^call:(.+?)\s+raises\s+([A-Za-z_][\w.]*)\s*$")


def _call_equals(inv: str) -> tuple[str, object] | None:
    """`call:<call expr> == <literal>` → (call expr, expected value), else None.
    The form `_okf.mine_branch_invariants` synthesizes; hand-written ones work too."""
    if not inv.startswith("call:"):
        return None
    try:
        node = ast.parse(inv[len("call:"):], mode="eval").body
    except SyntaxError:
        return None
    if not (isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq)
            and isinstance(node.left, ast.Call)):
        return None
    try:
        expected = ast.literal_eval(node.comparators[0])
    except ValueError:
        return None
    return ast.unparse(node.left), expected


def _fill_new_required(expr: str, tree: ast.Module) -> str:
    """Add typed mocks for required parameters of a mined `fn(...)` call that the
    staged signature gained, so the guard is exercised instead of a TypeError."""
    from . import _okf

    call = ast.parse(expr, mode="eval").body
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)):
        return expr
    if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
        return expr
    fn = next(
        (
            s
            for s in tree.body
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and s.name == call.func.id
        ),
        None,
    )
    if fn is None:
        return expr

    a = fn.args
    positional = a.posonlyargs + a.args
    required = positional[: len(positional) - len(a.defaults)]
    required += [p for p, default in zip(a.kwonlyargs, a.kw_defaults) if default is None]
    given = {k.arg for k in call.keywords} | {p.arg for p in positional[: len(call.args)]}
    for p in required:
        if p.arg in given:
            continue
        value = ast.parse(_okf.mock_value(p), mode="eval").body
        if p in a.posonlyargs:
            call.args.append(value)
        else:
            call.keywords.append(ast.keyword(arg=p.arg, value=value))
    return ast.unparse(call)


def _raises(fn, exc_name: str, ns: dict) -> bool:
    import inspect

    from . import _sandbox

    exc_type = ns.get(exc_name) or getattr(builtins, exc_name, None)
    if not isinstance(exc_type, type):
        raise NameError(f"unknown exception type {exc_name!r}")
    try:
        value = _complete(fn())  # an `async def` hands back a coroutine: run it so its guard fires
        # A generator's leading guard fires on its first step, not on the call.
        if inspect.isgenerator(value):
            next(value, None)
        elif inspect.isasyncgen(value):
            try:
                _complete(value.__anext__())
            except StopAsyncIteration:
                pass
    except _sandbox.ExecutionBudgetExceeded:
        raise
    except exc_type:
        return True
    except Exception:  # includes RecursionError: wrong exception → invariant fails
        return False
    return False


def _complete(value):
    """Run an awaitable to completion and return its result; plain values pass
    through. Uses a private event loop. When this thread already runs a loop (the
    gateway's), the private loop runs on a helper thread under its own execution
    guard, because event loops cannot nest."""
    import asyncio
    import inspect
    import threading

    from . import _sandbox

    if not inspect.isawaitable(value):
        return value

    async def main():
        return await value

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(main())

    box: dict = {}

    def worker() -> None:
        try:
            box["value"] = _sandbox.guarded(lambda: asyncio.run(main()))
        except BaseException as exc:  # re-raised on the caller's thread
            box["error"] = exc

    thread = threading.Thread(target=worker, name="stepcheck-await", daemon=True)
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["value"]


def gate_c(
    node_id: str,
    invariants: list[str],
    staged_source: str,
    project_sources: dict[str, str] | None = None,
    mined: list[str] | None = None,
    project_paths: dict[str, str] | None = None,
) -> None:
    """Logical micro-invariants: every standing frame invariant must hold.

    Each invariant is a deterministic Python expression evaluated with:
      src  — `ast.unparse(tree)`: whitespace/quote-normalized source with every
             comment (including the invariant lines themselves) gone, so an
             invariant can never satisfy itself and never trips on formatting;
      tree — the parsed `ast.Module`;
      ns   — the staged module exec-loaded into an isolated namespace, with
             project imports — absolute or relative; `project_paths` gives each
             node's file so packages resolve — bound to canonical sources
             (loaded lazily, only when an invariant mentions `ns` or uses `call:`);
      ast, raises(fn, ExcName) — helpers; an awaitable result is run to
             completion, so `async def` functions are checked like sync ones.
    Sugar: `call:<expr> raises <Exc>` ≡ `raises(lambda: <expr>, "<Exc>")`
    with `<expr>` evaluated inside `ns`; `call:<call> == <literal>` holds when the
    call, evaluated inside `ns`, returns a value of the literal's type equal to
    it (the deterministic-branch form `_okf.mine_branch_invariants` synthesizes).
    Auto-mined `call:` invariants also get
    typed mocks for any required parameters the staged signature added.
    Budgets: loading the module runs under the wall clock only
    (`_sandbox.IMPORT_WALL_BUDGET_SECONDS`) — real packages execute far more
    than the step budget at import time; each invariant call then runs under
    the full step + clock guard. A falsy result, or any exception, is a
    kernel.LogicalError.
    """
    guard_invariants = [inv for inv in invariants if inv.startswith("guard:")]
    invariants = [inv for inv in invariants if not inv.startswith("guard:")]
    if not invariants:
        # nothing to execute (foreign modules carry only guard invariants)
        return _structural_guards(node_id, guard_invariants, staged_source, project_paths)
    from . import LogicalError, _sandbox

    tree = ast.parse(staged_source)
    src = ast.unparse(tree)
    needs_ns = any(inv.startswith("call:") or re.search(r"\bns\b", inv) for inv in invariants)
    ns: dict | None = None
    if needs_ns:
        try:
            ns = _sandbox.guarded(
                lambda: _sandbox.load_namespace(
                    node_id, staged_source, project_sources or {}, project_paths
                ),
                steps=None,
                seconds=_sandbox.IMPORT_WALL_BUDGET_SECONDS,
            )
        except _sandbox.ExecutionBudgetExceeded as exc:
            raise LogicalError(
                f"staged module '{node_id}' blew the Gate C import budget while "
                f"loading ({exc}) — runaway code at import time"
            )
        except Exception as exc:
            raise LogicalError(
                f"staged module '{node_id}' failed to load for callable invariants: {exc!r}"
            )

    for inv in invariants:
        got: list = []
        try:
            m = _CALL_RE.match(inv)
            eq = None if m else _call_equals(inv)
            if eq is not None:
                expr, expected = eq
                if mined and inv in mined:
                    expr = _fill_new_required(expr, tree)
                code = compile(expr, "<okf-invariant>", "eval")

                def check(code=code, expected=expected) -> bool:
                    value = _complete(eval(code, dict(ns or {})))  # noqa: S307
                    got.append(value)
                    return type(value) is type(expected) and value == expected

                ok = _sandbox.guarded(check)
            elif m:
                expr, exc_name = m.group(1), m.group(2)
                if mined and inv in mined:
                    expr = _fill_new_required(expr, tree)
                code = compile(expr, "<okf-invariant>", "eval")
                ok = _sandbox.guarded(
                    lambda: _raises(lambda: eval(code, dict(ns or {})), exc_name, ns or {})  # noqa: S307
                )
            else:
                scope = {
                    "src": src,
                    "tree": tree,
                    "ns": ns,
                    "ast": ast,
                    "raises": lambda fn, exc_name: _raises(fn, exc_name, ns or {}),
                    "len": len,
                    "all": all,
                    "any": any,
                    "isinstance": isinstance,
                    "getattr": getattr,
                }
                # helpers go in globals: generator expressions inside an
                # invariant run in their own frame and see globals only.
                ok = _sandbox.guarded(
                    lambda: bool(eval(inv, {"__builtins__": {}, **scope}))  # noqa: S307
                )
        except LogicalError:
            raise
        except _sandbox.ExecutionBudgetExceeded as exc:
            raise LogicalError(
                f"invariant {inv!r} of '{node_id}' blew the Gate C execution budget "
                f"({exc}) — runaway loop or recursion in the staged code"
            )
        except Exception as exc:
            raise LogicalError(
                f"invariant {inv!r} of '{node_id}' raised during evaluation: {exc!r}"
            )
        if not ok:
            if got:
                tag = " (auto-mined deterministic branch)" if mined and inv in mined else ""
                raise LogicalError(
                    f"staged diff violates frame invariant {inv!r} of '{node_id}'{tag}: "
                    f"the call now returns {got[0]!r}"
                )
            tag = " (auto-mined from a leading guard clause)" if mined and inv in mined else ""
            raise LogicalError(
                f"staged diff violates frame invariant {inv!r} of '{node_id}'{tag}"
            )
    _structural_guards(node_id, guard_invariants, staged_source, project_paths)


def _structural_guards(node_id: str, guard_invariants: list[str], staged_source: str,
                       project_paths: dict[str, str] | None) -> None:
    """Structural `guard:<symbol>:<clause>` invariants (Python, TypeScript, Go, Rust,
    Java): each mined guard clause must still exist in its symbol's body — anywhere
    in it, equal after normalisation — unless the commit declared the deletion.
    Runs after the executable invariants, whose failures are more specific."""
    if not guard_invariants:
        return
    from . import LogicalError, _okf

    path = (project_paths or {}).get(node_id, f"{node_id}.py")
    present = _okf.present_guards(staged_source, path)
    kind = "guard clause" if _okf.lang_module(path) is None else "leading guard clause"
    for inv in guard_invariants:
        if inv not in present:
            raise LogicalError(
                f"staged diff violates frame invariant {inv!r} of '{node_id}' "
                f"(auto-mined {kind} removed or weakened)"
            )
