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


def analyze(node_id: str, path: str, source: str, project_modules: dict[str, str] | set[str]) -> ModuleInfo:
    """Parse one module into its OKF facts. Raises SyntaxError on broken source.
    `project_modules` maps importable dotted names to node ids (see module_map);
    a plain set of flat module names is accepted for backwards compatibility."""
    tree = ast.parse(source)
    modules = project_modules if isinstance(project_modules, dict) else {m: m for m in project_modules}
    exports: list[str] = []
    preserved: list[str] = []

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

    records = _import_records(node_id, path, tree, modules)
    deps = sorted({nid for nid, _name, _local in records})

    # Internal calls into project dependencies are preserved symbols too.
    imported_names = {local for _nid, _name, local in records if local}
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
        deps=deps,
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
    """Replace `path` in one step so a crash cannot leave a half-written file."""
    target = path.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".stepcheck-tmp")
    try:
        tmp.write_bytes(data)
        if target.exists():
            shutil.copymode(target, tmp)
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)


# ----------------------------------------------------- AST skeleton slicing


def _symbol_span(source_lines: list[str], node: ast.stmt) -> tuple[int, int]:
    """1-based inclusive line range of a top-level statement: its decorators plus
    the comment lines sitting directly above (an `# okf-invariant:` travels with
    its def). This is the range a focused checkout shows and a patch replaces."""
    start = node.lineno
    decos = getattr(node, "decorator_list", [])
    if decos:
        start = min(start, min(d.lineno for d in decos))
    while start > 1 and source_lines[start - 2].strip().startswith("#"):
        start -= 1
    return start, node.end_lineno


def _segment(source_lines: list[str], node: ast.stmt) -> str:
    """Exact source text of a top-level statement, decorators + comments included."""
    start, end = _symbol_span(source_lines, node)
    return "".join(source_lines[start - 1 : end])


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
    · {"op":"delete_symbol","name":…}. Each op splices only the target's own
    lines (decorators and attached leading comments included) into the original
    text, so comments, pragmas and formatting elsewhere survive verbatim.
    Raises ValueError on a bad op."""
    for op in patch:
        kind = op.get("op")
        if kind == "append":
            source = source.rstrip("\n") + "\n\n\n" + op["code"].rstrip("\n") + "\n"
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
        start, end = _symbol_span(lines, target)
        head, tail = "".join(lines[: start - 1]), "".join(lines[end:])
        if kind == "replace_symbol":
            source = head + op["code"].rstrip("\n") + "\n" + tail
        else:
            head, tail = head.rstrip("\n"), tail.lstrip("\n")
            if head and tail:
                source = head + "\n\n\n" + tail
            else:
                source = head + "\n" if head else tail
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
    """For every top-level function (sync or async) whose body opens with guard
    clauses (`if <cond on one parameter>: raise <Exc>`), synthesize a callable
    invariant `call:fn(param=value, …) raises Exc` with arguments that trip
    that guard. Stops at the first non-guard statement; skips anything it
    cannot synthesize deterministically."""
    out: list[str] = []
    for fn in tree.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
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


# ------------------------------------------------ package-aware import graph


def module_name(path: str) -> str:
    """Dotted import name of a tracked file: `pkg/models.py` -> `pkg.models`,
    `pkg/__init__.py` -> `pkg`; a root-level `__init__.py` stays `__init__`."""
    if not path:
        raise ValueError("empty module path")
    parts = path.replace("\\", "/").removesuffix(".py").split("/")
    if parts[-1] == "__init__" and len(parts) > 1:
        parts = parts[:-1]
    return ".".join(parts)


def _package_of(path: str) -> str:
    """Dotted package a file lives in (`pkg/__init__.py` and `pkg/x.py` -> `pkg`)."""
    parts = path.replace("\\", "/").removesuffix(".py").split("/")
    return ".".join(parts[:-1])


def module_map(paths: dict[str, str]) -> dict[str, str]:
    """Importable dotted names -> node_id. A stem that is unique in the project
    stays importable by its bare name (flat, sys.path-style projects)."""
    out = {module_name(p): nid for nid, p in paths.items()}
    stems: dict[str, int] = {}
    for p in paths.values():
        stem = p.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".py")
        stems[stem] = stems.get(stem, 0) + 1
    for nid, p in paths.items():
        stem = p.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".py")
        if stems[stem] == 1:
            out.setdefault(stem, nid)
    return out


def _lookup(dotted: str, modules: dict[str, str]) -> tuple[str | None, bool]:
    """(node_id of the longest known prefix, whether the whole name matched)."""
    parts = dotted.split(".")
    for i in range(len(parts), 0, -1):
        nid = modules.get(".".join(parts[:i]))
        if nid is not None:
            return nid, i == len(parts)
    return None, False


def _import_records(
    node_id: str, path: str, tree: ast.Module, modules: dict[str, str]
) -> list[tuple[str, str | None, str | None]]:
    """(dep node_id, name imported from it or None for the module object itself,
    local binding) for every top-level import resolving to another project module.
    Relative imports resolve against the importing file's package."""
    package = _package_of(path)
    out: list[tuple[str, str | None, str | None]] = []

    def add(nid: str | None, name: str | None, local: str | None) -> None:
        if nid is not None and nid != node_id:
            out.append((nid, name, local))

    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                nid, _exact = _lookup(alias.name, modules)
                add(nid, None, alias.asname or alias.name.split(".")[0])
        elif isinstance(stmt, ast.ImportFrom):
            if stmt.level:
                base_parts = package.split(".") if package else []
                if stmt.level - 1 > len(base_parts):
                    continue  # climbs above the project root
                base_parts = base_parts[: len(base_parts) - (stmt.level - 1)]
                base = ".".join(base_parts + ([stmt.module] if stmt.module else []))
            else:
                base = stmt.module or ""
            base_nid, exact = _lookup(base, modules) if base else (None, False)
            for alias in stmt.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                sub_nid, sub_exact = _lookup(f"{base}.{alias.name}" if base else alias.name, modules)
                if sub_exact and sub_nid != base_nid:
                    add(sub_nid, None, local)  # `from pkg import submodule`
                elif base_nid is not None:
                    add(base_nid, alias.name if exact else None, local)
    return out


def resolve_imports(node_id: str, path: str, source: str, modules: dict[str, str]) -> dict[str, set[str]]:
    """Dependency node_id -> names this module imports from it (empty when it
    imports the module object itself). Unparseable source resolves to nothing."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    out: dict[str, set[str]] = {}
    for nid, name, _local in _import_records(node_id, path, tree, modules):
        out.setdefault(nid, set())
        if name is not None:
            out[nid].add(name)
    return out
