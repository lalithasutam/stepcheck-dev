"""OKF analysis + frame serialization. Private implementation of StateKernel.

Never mocked in tests (GLOSSARY "Testing rules"): exercised only through Seam 1.
"""
from __future__ import annotations

import ast
import codecs
import io
import os
import re
import shutil
import tokenize
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_INVARIANT_RE = re.compile(r"#\s*okf-invariant:\s*(.+)$")


@dataclass
class ModuleInfo:
    node_id: str
    path: str
    source: str
    exports: list[str] = field(default_factory=list)
    deps: list[str] = field(default_factory=list)
    preserved_symbols: list[str] = field(default_factory=list)
    invariants: list[str] = field(default_factory=list)
    mined_invariants: list[str] = field(default_factory=list)  # subset of invariants


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = ast.unparse(node.args)
    ret = f" -> {ast.unparse(node.returns)}" if node.returns is not None else ""
    return f"{node.name}({args}){ret}"


def harvest_invariants(source: str) -> list[str]:
    """`# okf-invariant: <python-expr over `src`>` comments, in file order."""
    found: list[str] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                m = _INVARIANT_RE.match(tok.string.strip())
                if m:
                    found.append(m.group(1).strip())
    except tokenize.TokenizeError:
        pass
    return found


def analyze(node_id: str, path: str, source: str, project_modules: set[str]) -> ModuleInfo:
    """Parse one module into its OKF facts. Raises SyntaxError on broken source."""
    tree = ast.parse(source)
    exports: list[str] = []
    preserved: list[str] = []
    deps: set[str] = set()

    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not stmt.name.startswith("_"):
                exports.append(_signature(stmt))
                preserved.append(f"def {stmt.name}")
            for dec in stmt.decorator_list:
                name = ast.unparse(dec).split("(")[0]
                sym = f"@{name}"
                if sym not in preserved:
                    preserved.append(sym)
        elif isinstance(stmt, ast.ClassDef):
            if not stmt.name.startswith("_"):
                bases = ", ".join(ast.unparse(b) for b in stmt.bases)
                exports.append(f"class {stmt.name}({bases})" if bases else f"class {stmt.name}")
                preserved.append(f"class {stmt.name}")
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                root = alias.name.split(".")[0]
                if root in project_modules and root != node_id:
                    deps.add(root)
        elif isinstance(stmt, ast.ImportFrom):
            root = (stmt.module or "").split(".")[0]
            if root in project_modules and root != node_id:
                deps.add(root)

    # Internal calls into project dependencies are preserved symbols too.
    imported_names = {
        alias.asname or alias.name
        for stmt in tree.body
        if isinstance(stmt, ast.ImportFrom)
        and (stmt.module or "").split(".")[0] in project_modules
        for alias in stmt.names
    }
    called = {
        n.func.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    for name in sorted(imported_names & called):
        sym = f"call:{name}"
        if sym not in preserved:
            preserved.append(sym)

    manual = harvest_invariants(source)
    mined = [inv for inv in mine_guard_invariants(tree) if inv not in manual]
    invariants = manual + mined

    return ModuleInfo(
        node_id=node_id,
        path=path,
        source=source,
        exports=exports,
        deps=sorted(deps),
        preserved_symbols=preserved,
        invariants=invariants,
        mined_invariants=mined,
    )


def statement_count(source: str) -> int:
    return sum(1 for n in ast.walk(ast.parse(source)) if isinstance(n, ast.stmt))


def frame_markdown(
    info: ModuleInfo,
    status: str,
    locked: bool,
    verified: list[dict],
    *,
    focus: list[str] | None = None,
    fold_history: bool = False,
    symbol_index: bool = False,
) -> str:
    """The OKF frame. On disk: full source + append-only verified[] chain.
    In a CheckoutPayload (`fold_history=True`): superseded attestations fold
    into one summary, and `focus` slices the body to an AST skeleton."""
    meta: dict = {
        "node_id": info.node_id,
        "path": info.path,
        "status": status,
        "locked": locked,
        "deps": info.deps,
        "exports": info.exports,
        "preserved_symbols": info.preserved_symbols,
        "invariants": info.invariants,
        "invariants_auto_mined": info.mined_invariants,
    }
    if fold_history:
        latest = verified[-1] if verified else None
        meta["attestation"] = {
            "count": len(verified),
            "latest_sha256": latest["payload"]["sha256"] if latest else None,
            "latest_turn": latest["payload"]["turn"] if latest else None,
        }
    else:
        meta["verified"] = verified
    fm = yaml.safe_dump(meta, sort_keys=False, default_flow_style=False)
    if focus is None:
        body_src, note = info.source, ""
    elif symbol_index:
        body_src = skeleton(info.source, [])
        names = [n for n in symbol_names(info.source)]
        note = (
            f" Source is {len(info.source.splitlines())} lines — over the checkout budget, so this"
            f" frame was auto-skeletonized. Re-checkout with focus=[<name>, …] for full bodies."
            f"\n\nSymbol index ({len(names)}): " + ", ".join(names)
        )
    else:
        body_src = skeleton(info.source, focus)
        note = (
            f" Sliced to focus {focus!r}; other symbols are skeletons —"
            " commit a `patch` (append / replace_symbol / delete_symbol) to fold edits in."
            if focus
            else " Pure skeleton; commit a `patch` to fold edits in."
        )
    body = (
        f"# {info.node_id}\n\n"
        f"Compacted OKF frame for `{info.path}` — "
        f"{len(info.exports)} exports, {len(info.deps)} deps.{note}\n\n"
        f"```python\n{body_src}```\n"
    )
    return f"---\n{fm}---\n\n{body}"


def index_markdown(nodes: dict[str, "object"]) -> str:
    """nodes: node_id -> Node (duck-typed: .status, .info.deps)."""
    edges = [
        f"{nid} -> {dep}"
        for nid, node in sorted(nodes.items())
        for dep in node.info.deps
    ]
    meta = {
        "node_id": "__index__",
        "nodes": sorted(nodes),
        "edges": edges,
    }
    fm = yaml.safe_dump(meta, sort_keys=False, default_flow_style=False)
    lines = [f"- {nid} ({node.status})" for nid, node in sorted(nodes.items())]
    edge_lines = [f"- {e}" for e in edges]
    return (
        f"---\n{fm}---\n\n# OKF Index\n\n"
        + "\n".join(lines)
        + "\n\n## Edges\n\n"
        + ("\n".join(edge_lines) if edge_lines else "(none)")
        + "\n"
    )


def write_frames(okf_dir: Path, nodes: dict[str, "object"]) -> None:
    okf_dir.mkdir(parents=True, exist_ok=True)
    for nid, node in nodes.items():
        (okf_dir / f"{nid}.md").write_text(
            frame_markdown(node.info, node.status, node.locked, node.verified),
            encoding="utf-8",
        )
    (okf_dir / "index.md").write_text(index_markdown(nodes), encoding="utf-8")


# ---------------------------------------------------- tracked-file round trip


def decode_source(raw: bytes) -> str:
    """Tracked-file bytes -> canonical source: UTF-8, no BOM, LF line endings."""
    text = raw.decode("utf-8").removeprefix("﻿")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def encode_like(source: str, existing: bytes) -> bytes:
    """Canonical source -> bytes in the existing file's BOM + line-ending style."""
    crlf = existing.count(b"\r\n") * 2 > existing.count(b"\n")
    data = (source.replace("\n", "\r\n") if crlf else source).encode("utf-8")
    return codecs.BOM_UTF8 + data if existing.startswith(codecs.BOM_UTF8) else data


def write_atomic(path: Path, data: bytes) -> None:
    """Replace `path` in one step so a crash cannot leave a half-written module."""
    target = path.resolve()
    tmp = target.with_name(target.name + ".stepcheck-tmp")
    try:
        tmp.write_bytes(data)
        shutil.copymode(target, tmp)
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)


# ----------------------------------------------------- AST skeleton slicing


def _segment(source_lines: list[str], node: ast.stmt) -> str:
    """Exact source text of a top-level statement, decorators + comments included."""
    start = node.lineno
    decos = getattr(node, "decorator_list", [])
    if decos:
        start = min(start, min(d.lineno for d in decos))
    # Pull leading comment lines (e.g. okf-invariant) that sit directly above.
    while start > 1 and source_lines[start - 2].strip().startswith("#"):
        start -= 1
    return "".join(source_lines[start - 1 : node.end_lineno])


def _skeleton_def(node: ast.FunctionDef | ast.AsyncFunctionDef, indent: str = "") -> str:
    out = [f"{indent}@{ast.unparse(d)}\n" for d in node.decorator_list]
    kw = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    out.append(f"{indent}{kw} {_signature(node)}:\n")
    doc = ast.get_docstring(node)
    if doc:
        out.append(f'{indent}    """{doc}"""\n')
    out.append(f"{indent}    ...\n")
    return "".join(out)


def _skeleton_class(node: ast.ClassDef) -> str:
    bases = ", ".join(ast.unparse(b) for b in node.bases)
    out = [f"@{ast.unparse(d)}\n" for d in node.decorator_list]
    out.append(f"class {node.name}({bases}):\n" if bases else f"class {node.name}:\n")
    doc = ast.get_docstring(node)
    if doc:
        out.append(f'    """{doc}"""\n')
    members = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if not members and not doc:
        out.append("    ...\n")
    for m in members:
        out.append(_skeleton_def(m, indent="    "))
    return "".join(out)


def _assign_names(node: ast.stmt) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [ast.unparse(t) for t in targets]


def skeleton(source: str, focus: list[str]) -> str:
    """Slice a module: `focus` defs/classes verbatim; every other def/class as
    decorators + signature + docstring + `...`; runs of module-level
    assignments folded into one summary line; imports kept verbatim."""
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    keep = set(focus)
    out: list[str] = []
    pending_assigns: list[str] = []

    def flush_assigns() -> None:
        if not pending_assigns:
            return
        if len(pending_assigns) <= 2:
            out.extend(f"{a} = ...\n" for a in pending_assigns)
        else:
            out.append(
                f"# folded {len(pending_assigns)} module-level assignments: "
                f"{pending_assigns[0]} … {pending_assigns[-1]} "
                f"(checkout without focus for full source)\n"
            )
        pending_assigns.clear()

    for stmt in tree.body:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            pending_assigns.extend(_assign_names(stmt))
            continue
        flush_assigns()
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            out.append(ast.unparse(stmt) + "\n")
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append("\n\n" + (_segment(lines, stmt) if stmt.name in keep else _skeleton_def(stmt)))
        elif isinstance(stmt, ast.ClassDef):
            out.append("\n\n" + (_segment(lines, stmt) if stmt.name in keep else _skeleton_class(stmt)))
        elif isinstance(stmt, ast.Expr) and isinstance(getattr(stmt, "value", None), ast.Constant):
            out.append(ast.unparse(stmt) + "\n")  # module docstring
        else:
            out.append("# " + ast.unparse(stmt).splitlines()[0][:60] + " …\n")
    flush_assigns()
    return "".join(out).lstrip("\n")


def interface_skeleton(source: str) -> str:
    """Dependency view: signatures, decorators, docstrings — no bodies, no data."""
    tree = ast.parse(source)
    parts: list[str] = []
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and not stmt.name.startswith("_"):
            parts.append(_skeleton_def(stmt))
        elif isinstance(stmt, ast.ClassDef) and not stmt.name.startswith("_"):
            parts.append(_skeleton_class(stmt))
    return "\n".join(parts)


# ------------------------------------------------------------ patch folding


def apply_patch(source: str, patch: list[dict]) -> str:
    """Fold AST-level ops into canonical source. Ops:
    {"op":"append","code":…} · {"op":"replace_symbol","name":…,"code":…}
    · {"op":"delete_symbol","name":…}. Raises ValueError on a bad op."""
    for op in patch:
        kind = op.get("op")
        if kind == "append":
            code = op["code"]
            source = source.rstrip("\n") + "\n\n\n" + code.rstrip("\n") + "\n"
            continue
        if kind not in ("replace_symbol", "delete_symbol"):
            raise ValueError(f"unknown patch op {kind!r}")
        tree = ast.parse(source)
        lines = source.splitlines(keepends=True)
        target = next(
            (
                s
                for s in tree.body
                if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and s.name == op["name"]
            ),
            None,
        )
        if target is None:
            raise ValueError(f"patch targets unknown top-level symbol {op['name']!r}")
        start = target.lineno
        if target.decorator_list:
            start = min(start, min(d.lineno for d in target.decorator_list))
        replacement = op["code"].rstrip("\n") + "\n" if kind == "replace_symbol" else ""
        source = "".join(lines[: start - 1]) + replacement + "".join(lines[target.end_lineno :])
    return source


def symbol_names(source: str) -> list[str]:
    """Top-level def/class names in file order (the auto-skeleton symbol index)."""
    return [
        s.name
        for s in ast.parse(source).body
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]


# ------------------------------------------ zero-config guard invariant mining

_TYPE_DEFAULTS = {"str": '"x"', "int": "1", "float": "1.0", "bool": "True",
                  "dict": "{}", "list": "[1]", "tuple": "(1,)", "set": "{1}", "bytes": 'b"x"'}
_FALSY = {"str": '""', "int": "0", "float": "0.0", "bool": "False",
          "dict": "{}", "list": "[]", "tuple": "()", "set": "set()", "bytes": 'b""'}


def _annotation_name(arg: ast.arg) -> str | None:
    if arg.annotation is None:
        return None
    a = arg.annotation
    if isinstance(a, ast.Name):
        return a.id
    if isinstance(a, ast.Subscript) and isinstance(a.value, ast.Name):
        return a.value.id  # list[str] -> list
    if isinstance(a, ast.BinOp) and isinstance(a.left, ast.Name):
        return a.left.id  # str | None -> str
    return None


def mock_value(arg: ast.arg) -> str:
    """Literal stand-in for a required parameter, chosen from its annotation."""
    return _TYPE_DEFAULTS.get(_annotation_name(arg) or "", "None")


def _violating_value(cond: ast.expr, params: dict[str, ast.arg]) -> tuple[str, str] | None:
    """Find (param, literal) such that `cond` is true when param = literal."""
    if isinstance(cond, ast.BoolOp) and isinstance(cond.op, ast.Or) and cond.values:
        return _violating_value(cond.values[0], params)
    if isinstance(cond, ast.UnaryOp) and isinstance(cond.op, ast.Not) and isinstance(cond.operand, ast.Name):
        name = cond.operand.id
        if name in params:
            return name, _FALSY.get(_annotation_name(params[name]) or "", "None")
    if isinstance(cond, ast.Compare) and len(cond.ops) == 1 and len(cond.comparators) == 1:
        left, op, right = cond.left, cond.ops[0], cond.comparators[0]
        # len(param) == 0  /  len(param) < 1
        if (isinstance(left, ast.Call) and isinstance(left.func, ast.Name) and left.func.id == "len"
                and left.args and isinstance(left.args[0], ast.Name) and left.args[0].id in params
                and isinstance(right, ast.Constant) and isinstance(right.value, int)
                and ((isinstance(op, ast.Eq) and right.value == 0) or (isinstance(op, ast.Lt) and right.value == 1))):
            name = left.args[0].id
            return name, _FALSY.get(_annotation_name(params[name]) or "list", "[]")
        if isinstance(left, ast.Name) and left.id in params:
            name = left.id
            if isinstance(op, ast.Is) and isinstance(right, ast.Constant) and right.value is None:
                return name, "None"
            if isinstance(right, ast.Constant) and isinstance(right.value, (int, float)) and not isinstance(right.value, bool):
                v = right.value
                if isinstance(op, (ast.LtE, ast.GtE, ast.Eq)):
                    return name, repr(v)
                if isinstance(op, ast.Lt):
                    return name, repr(v - 1)
                if isinstance(op, ast.Gt):
                    return name, repr(v + 1)
            if isinstance(right, ast.Constant) and isinstance(right.value, str) and isinstance(op, ast.Eq):
                return name, repr(right.value)
    return None


def _exception_name(raise_stmt: ast.Raise) -> str | None:
    exc = raise_stmt.exc
    if isinstance(exc, ast.Call):
        exc = exc.func
    return exc.id if isinstance(exc, ast.Name) else None


def mine_guard_invariants(tree: ast.Module) -> list[str]:
    """For every top-level function whose body opens with guard clauses
    (`if <cond on one parameter>: raise <Exc>`), synthesize a callable
    invariant `call:fn(param=value, …) raises Exc` with arguments that trip
    that guard. Stops at the first non-guard statement; skips anything it
    cannot synthesize deterministically."""
    out: list[str] = []
    for fn in tree.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or isinstance(fn, ast.AsyncFunctionDef):
            continue
        a = fn.args
        if a.posonlyargs or a.vararg or a.kwonlyargs or a.kwarg:
            continue
        params = {p.arg: p for p in a.args}
        if not params:
            continue
        n_defaults = len(a.defaults)
        required = [p.arg for p in a.args[: len(a.args) - n_defaults]]
        body = fn.body
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
            body = body[1:]  # docstring
        for stmt in body:
            if not (isinstance(stmt, ast.If) and not stmt.orelse and len(stmt.body) == 1
                    and isinstance(stmt.body[0], ast.Raise)):
                break
            exc = _exception_name(stmt.body[0])
            hit = _violating_value(stmt.test, params)
            if exc is None or hit is None:
                continue
            name, value = hit
            kwargs: list[str] = []
            for p in a.args:
                if p.arg == name:
                    kwargs.append(f"{p.arg}={value}")
                elif p.arg in required:
                    kwargs.append(f"{p.arg}={mock_value(p)}")
            inv = f"call:{fn.name}({', '.join(kwargs)}) raises {exc}"
            if inv not in out:
                out.append(inv)
    return out
