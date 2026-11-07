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
    does. Python: `...` / `pass` / docstring-only. TS/JS, Go, Rust, Java: a brace
    body that was at least two statements becomes empty, comment-only, a
    placeholder macro (`todo!()`, `unimplemented!()`) or one trivial `return`
    (`return;`, `return nil / null / 0 / "" / false / {} / []`)."""
    if not str(path).endswith((".py", ".pyi")):
        return _foreign_stubbed_bodies(path, old_source, new_source)
    try:
        old, new = _def_bodies(ast.parse(old_source)), _def_bodies(ast.parse(new_source))
    except SyntaxError:
        return []
    return [(name, kind) for name, body in old.items()
            if name in new and _stub_kind(body) is None and (kind := _stub_kind(new[name])) is not None]


_TRIVIAL_RETURN = re.compile(
    r"^return(\s+(nil|null|undefined|None|0|0\.0|-1|\"\"|''|``|false|true|\{\s*\}|\[\s*\]|\(\s*\)))?\s*;?$")
_PLACEHOLDER = re.compile(r"^(todo|unimplemented|panic)!\s*\(.*\)\s*;?$|^throw new Error\((['\"]).*(TODO|implement|Remove this).*\2\)\s*;?$", re.S)


def _brace_close(src: str, open_idx: int) -> int | None:
    """Index of the `}` matching src[open_idx] == '{', skipping strings and comments."""
    depth, i, n = 0, open_idx, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            i = src.find("\n", i)
            if i < 0:
                return None
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                return None
            i = j + 2
            continue
        if c in "\"'`" and not (c == "'" and not (i + 2 < n and (src[i + 1] == "\\" or src[i + 2] == "'"))):
            j = i + 1  # a Rust lifetime `'a` is not a string; a char literal `'x'` / `'\n'` is
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            i = j + 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _body_statements(body: str) -> list[str]:
    """Statement-ish lines of a brace body: comments and bare braces dropped."""
    text = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    out = []
    for line in text.splitlines():
        line = re.sub(r"//.*$", "", line).strip().strip("{}").strip()
        if line:
            out.extend(p.strip() for p in line.split(";") if p.strip())
    return out


def _foreign_stub_kind(body: str) -> str | None:
    stmts = _body_statements(body)
    if not stmts:
        return "comment-only" if body.strip() else "{}"
    if len(stmts) == 1:
        if _PLACEHOLDER.match(stmts[0]):
            return stmts[0].split("(")[0] + "()"
        if _TRIVIAL_RETURN.match(stmts[0]):
            return stmts[0]
    return None


def _foreign_stubbed_bodies(path: str, old_source: str, new_source: str) -> list[tuple[str, str]]:
    from . import _okf

    mod = _okf.lang_module(path)
    if mod is None:
        return []

    def bodies(src: str) -> dict[str, str]:
        out: dict[str, str] = {}

        def visit(d) -> None:
            if getattr(d, "is_function", False) and getattr(d, "body_open", None) is not None:
                close = _brace_close(src, d.body_open)
                if close is not None:
                    out.setdefault(d.dotted, src[d.body_open + 1: close])
            for m in getattr(d, "members", None) or []:
                visit(m)

        try:
            decls, _ = mod.parse(src)
        except Exception:  # noqa: BLE001 — unparsable staged text is Gate A's business
            return out
        for d in decls:
            visit(d)
        return out

    old, new = bodies(old_source), bodies(new_source)
    return [(name, kind) for name, body in old.items()
            if name in new and len(_body_statements(body)) >= 2 and _foreign_stub_kind(body) is None
            and (kind := _foreign_stub_kind(new[name])) is not None]


def gate_b(node, staged_info, old_source: str, new_source: str, allow_deletion: bool, nodes=None) -> None:
    """Omission detection: symbol fingerprinting, skeleton-stub body overwrites
    (a def whose real body became `...` / `pass` / docstring-only), and the
    mass-deletion guard.

    Raises kernel.OmissionError. `allow_deletion=True` declares the deletion
    and bypasses both checks (GLOSSARY: Gate B). When several fingerprints are
    missing, the per-symbol one (`@dec on name`) is reported: it says which
    def or class lost its decorator. `nodes` (the session's node map) lets a
    dropped Python def / class that nothing — here or in any dependent — refers
    to any more pass strict mode as a refactor (`_dead_symbol`).
    """
    from . import OmissionError, _okf

    if allow_deletion:
        return

    staged_symbols = set(staged_info.preserved_symbols)
    dropped = [s for s in node.info.preserved_symbols if s not in staged_symbols]
    if dropped and str(node.info.path).endswith((".py", ".pyi")):
        dependents = {nid: n.info.source for nid, n in (nodes or {}).items() if node.info.node_id in n.info.deps}
        dropped = [s for s in dropped if not _dead_symbol(s, new_source, staged_info, dependents)]
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


def _dead_symbol(sym: str, new_source: str, staged_info, dependents: dict[str, str]) -> bool:
    """A dropped `def X` / `class X` that nothing refers to any more: the name occurs
    nowhere in the staged module (as a name, an attribute, a definition or a string
    such as an `__all__` entry), nowhere in any dependent's source, and the module
    still exports something. Removing or renaming it is a refactor, not an omission,
    so strict Gate B lets it through. A decorator fingerprint (`@dec on X`) or an
    internal call (`call:X`) is never dead this way: those are the silent drops."""
    kind, _, name = sym.partition(" ")
    if kind not in ("def", "class") or not name or not staged_info.exports:
        return False
    try:
        tree = ast.parse(new_source)
    except SyntaxError:
        return False
    for n in ast.walk(tree):
        if ((isinstance(n, ast.Name) and n.id == name) or (isinstance(n, ast.Attribute) and n.attr == name)
                or (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == name)
                or (isinstance(n, ast.Constant) and n.value == name)):
            return False
    mention = re.compile(rf"(?<!\w){re.escape(name)}(?!\w)")
    return not any(mention.search(src) for src in dependents.values())


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
    gone = _dead_roots({inv.split(":", 2)[1].split(".")[0] for inv in guard_invariants}, staged_source, path)
    for inv in guard_invariants:
        if inv not in present and (inv.split(":", 2)[1].split(".")[0] in gone
                                   or _assert_waived(inv, staged_source, present, path)):
            continue  # its symbol was removed as dead code (Gate B vetted that), or an assert waiver
        if inv not in present:
            raise LogicalError(
                f"staged diff violates frame invariant {inv!r} of '{node_id}' "
                f"(auto-mined {kind} removed or weakened)"
            )


def _dead_roots(roots: set[str], staged_source: str, path: str) -> set[str]:
    """The top-level symbol names among `roots` that the staged Python module neither
    defines nor mentions (as a name, attribute or string). Such a symbol was removed
    as dead code — a deletion Gate B has already vetted (`_dead_symbol`) — so its
    guard clauses cannot be conserved and Gate C does not require them."""
    from . import _okf

    if _okf.lang_module(path) is not None:
        return set()
    try:
        tree = ast.parse(staged_source)
    except SyntaxError:
        return set()
    live: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            live.add(n.name)
        elif isinstance(n, ast.Name):
            live.add(n.id)
        elif isinstance(n, ast.Attribute):
            live.add(n.attr)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            live.add(n.value)
    return {r for r in roots if r not in live}


_FLIP = {ast.Gt: ast.LtE, ast.GtE: ast.Lt, ast.Lt: ast.GtE, ast.LtE: ast.Gt, ast.Eq: ast.NotEq,
         ast.NotEq: ast.Eq, ast.Is: ast.IsNot, ast.IsNot: ast.Is, ast.In: ast.NotIn, ast.NotIn: ast.In}


def _negations(cond: ast.expr) -> list[str]:
    """Normalized spellings of `not <cond>`: the bare negation, the operand of a
    `not`, and a single comparison with its operator flipped (`x > 0` -> `x <= 0`)."""
    out = [ast.unparse(ast.UnaryOp(op=ast.Not(), operand=cond))]
    if isinstance(cond, ast.UnaryOp) and isinstance(cond.op, ast.Not):
        out.append(ast.unparse(cond.operand))
    if isinstance(cond, ast.Compare) and len(cond.ops) == 1 and type(cond.ops[0]) in _FLIP:
        out.append(ast.unparse(ast.Compare(left=cond.left, ops=[_FLIP[type(cond.ops[0])]()],
                                           comparators=cond.comparators)))
    return out


def _assert_waived(inv: str, staged_source: str, present: set[str], path: str) -> bool:
    """A missing Python `assert <cond>` guard that strict mode still accepts: a
    variable the assertion read no longer exists anywhere in its symbol (removed or
    renamed in the same refactor, so the assertion could not have survived), or the
    assertion became an equivalent `if not <cond>: raise …` (a flipped comparison
    counts). A live assertion deleted outright, or weakened in place, is still a
    Gate C rejection."""
    from . import _okf

    if _okf.lang_module(path) is not None:
        return False
    try:
        _kind, sym, clause = inv.split(":", 2)
    except ValueError:
        return False
    clause = re.sub(r" #\d+$", "", clause)
    if not clause.startswith("assert "):
        return False
    try:
        cond = ast.parse(clause[len("assert "):], mode="eval").body
        tree = ast.parse(staged_source)
    except SyntaxError:
        return False
    fn = next((f for s, f in _okf._py_symbols(tree.body) if s == sym), None)
    if fn is None:
        return False  # the symbol itself is gone: Gate B's call, not a waiver
    used = {n.id for n in ast.walk(cond) if isinstance(n, ast.Name)} - set(dir(builtins))
    # "gone" means gone from the whole module: a parameter renamed away, not a
    # module constant or import the assertion happened to be the only reader of.
    alive = ({n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
             | {a.arg for a in ast.walk(tree) if isinstance(a, ast.arg)}
             | {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
             | {(a.asname or a.name).split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                for a in n.names})
    if used and not used <= alive:
        return True
    return any(p.startswith(f"guard:{sym}:if {neg} raises ") for neg in _negations(cond) for p in present)
