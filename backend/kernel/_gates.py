"""Gate implementations. Private to StateKernel — reached only through commit()."""
from __future__ import annotations

import ast
import builtins
import re


def required_export_names(dependent_source: str, target_module: str) -> set[str]:
    """Names a dependent imports from `target_module` (its mechanical contract)."""
    names: set[str] = set()
    try:
        tree = ast.parse(dependent_source)
    except SyntaxError:
        return names
    for stmt in tree.body:
        if isinstance(stmt, ast.ImportFrom) and (stmt.module or "").split(".")[0] == target_module:
            names.update(alias.name for alias in stmt.names)
    return names


def export_names(exports: list[str]) -> set[str]:
    out = set()
    for sig in exports:
        head = sig.split("(")[0]
        out.add(head.removeprefix("class ").strip())
    return out


def gate_b(node, staged_info, old_source: str, new_source: str, allow_deletion: bool) -> None:
    """Omission detection: symbol fingerprinting + mass-deletion guard.

    Raises kernel.OmissionError. `allow_deletion=True` declares the deletion
    and bypasses both checks (GLOSSARY: Gate B).
    """
    from . import OmissionError, _okf

    if allow_deletion:
        return

    staged_symbols = set(staged_info.preserved_symbols)
    dropped = [s for s in node.info.preserved_symbols if s not in staged_symbols]
    if dropped:
        raise OmissionError(
            f"preserved symbol '{dropped[0]}' of '{node.info.node_id}' was silently "
            f"dropped from the staged source",
            subtype="INTRA_NODE_SYMBOL_DROPPED",
        )

    old_n = _okf.statement_count(old_source)
    new_n = _okf.statement_count(new_source)
    if old_n and (old_n - new_n) / old_n > 0.15:
        raise OmissionError(
            f"staged source drops {old_n - new_n}/{old_n} AST statements "
            f"(> 15%) without allow_deletion=True",
            subtype="INTRA_NODE_MASS_DELETION",
        )


def gate_a(node_id: str, locked: bool, source: str, nodes) -> "ast.Module":
    """Mechanical & locked protection. Returns the parsed tree on pass.

    Raises kernel.MechanicalError on: locked mutation, syntax error, or an
    exported name required by a dependent going missing.
    """
    from . import MechanicalError, _okf  # local import: avoid cycle at module load

    if locked:
        raise MechanicalError(
            f"node '{node_id}' is LOCKED — mutations are rejected at Gate A"
        )
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise MechanicalError(f"invalid AST syntax in '{node_id}': {exc.msg} (line {exc.lineno})")

    new_exports = export_names(
        _okf.analyze(node_id, "<staged>", source, set(nodes)).exports
    )
    for dep_id, dep_node in nodes.items():
        if node_id not in dep_node.info.deps:
            continue
        required = required_export_names(dep_node.info.source, node_id)
        missing = sorted(required - new_exports)
        if missing:
            raise MechanicalError(
                f"export '{missing[0]}' of '{node_id}' is required by dependent "
                f"'{dep_id}' and is missing from the staged source"
            )
    return tree


_CALL_RE = re.compile(r"^call:(.+?)\s+raises\s+([A-Za-z_][\w.]*)\s*$")


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
        (s for s in tree.body if isinstance(s, ast.FunctionDef) and s.name == call.func.id),
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
    from . import _sandbox

    exc_type = ns.get(exc_name) or getattr(builtins, exc_name, None)
    if not isinstance(exc_type, type):
        raise NameError(f"unknown exception type {exc_name!r}")
    try:
        fn()
    except _sandbox.ExecutionBudgetExceeded:
        raise
    except exc_type:
        return True
    except Exception:  # includes RecursionError: wrong exception → invariant fails
        return False
    return False


def gate_c(
    node_id: str,
    invariants: list[str],
    staged_source: str,
    project_sources: dict[str, str] | None = None,
    mined: list[str] | None = None,
) -> None:
    """Logical micro-invariants: every standing frame invariant must hold.

    Each invariant is a deterministic Python expression evaluated with:
      src  — `ast.unparse(tree)`: whitespace/quote-normalized source with every
             comment (including the invariant lines themselves) gone, so an
             invariant can never satisfy itself and never trips on formatting;
      tree — the parsed `ast.Module`;
      ns   — the staged module exec-loaded into an isolated namespace, with
             project imports resolved to canonical sources (loaded lazily, only
             when an invariant mentions `ns` or uses the `call:` form);
      ast, raises(fn, ExcName) — helpers.
    Sugar: `call:<expr> raises <Exc>` ≡ `raises(lambda: <expr>, "<Exc>")`
    with `<expr>` evaluated inside `ns`. Auto-mined `call:` invariants also get
    typed mocks for any required parameters the staged signature added.
    A falsy result, or any exception, is a kernel.LogicalError.
    """
    from . import LogicalError, _sandbox

    tree = ast.parse(staged_source)
    src = ast.unparse(tree)
    needs_ns = any(inv.startswith("call:") or re.search(r"\bns\b", inv) for inv in invariants)
    ns: dict | None = None
    if needs_ns:
        try:
            ns = _sandbox.guarded(
                lambda: _sandbox.load_namespace(node_id, staged_source, project_sources or {})
            )
        except _sandbox.ExecutionBudgetExceeded as exc:
            raise LogicalError(
                f"staged module '{node_id}' blew the Gate C execution budget while "
                f"loading ({exc}) — runaway code at import time"
            )
        except Exception as exc:
            raise LogicalError(
                f"staged module '{node_id}' failed to load for callable invariants: {exc!r}"
            )

    for inv in invariants:
        try:
            m = _CALL_RE.match(inv)
            if m:
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
            tag = " (auto-mined from a leading guard clause)" if mined and inv in mined else ""
            raise LogicalError(
                f"staged diff violates frame invariant {inv!r} of '{node_id}'{tag}"
            )
