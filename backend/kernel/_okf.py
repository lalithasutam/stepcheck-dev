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
    a plain set of flat module names is accepted for backwards compatibility.
    Decorators are fingerprinted twice: once per module (`@name`) and once per
    symbol (`@name on symbol`), so dropping `@fixture` from one function is an
    omission even while a sibling still carries it. Method decorators are
    fingerprinted per dotted symbol (`@width.setter on Box.width`)."""
    _mod = lang_module(path)
    if _mod is not None:
        return _mod.analyze(node_id, path, source, project_modules)
    tree = ast.parse(source)
    modules = project_modules if isinstance(project_modules, dict) else {m: m for m in project_modules}
    exports: list[str] = []
    preserved: list[str] = []

    def keep_decorators(stmt: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, owner: str = "") -> None:
        for dec in stmt.decorator_list:
            name = ast.unparse(dec).split("(")[0]
            symbols = (f"@{name} on {owner}.{stmt.name}",) if owner else (f"@{name}", f"@{name} on {stmt.name}")
            for sym in symbols:
                if sym not in preserved:
                    preserved.append(sym)

    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not stmt.name.startswith("_"):
                exports.append(_signature(stmt))
                preserved.append(f"def {stmt.name}")
            keep_decorators(stmt)
        elif isinstance(stmt, ast.ClassDef):
            if not stmt.name.startswith("_"):
                bases = ", ".join(ast.unparse(b) for b in stmt.bases)
                exports.append(f"class {stmt.name}({bases})" if bases else f"class {stmt.name}")
                preserved.append(f"class {stmt.name}")
            keep_decorators(stmt)
            for member in stmt.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    keep_decorators(member, owner=stmt.name)

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
    _mod = foreign_module(source)
    if _mod is not None:
        return _mod.statement_count(source)
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
    compact_meta: bool = False,
    tree: ast.Module | None = None,
) -> str:
    """The OKF frame. On disk: full source + append-only verified[] chain.
    In a CheckoutPayload (`fold_history=True`): superseded attestations fold
    into one summary, and `focus` slices the body to an AST skeleton.
    `compact_meta` scopes the frontmatter lists to the focus (counts stand in
    for the exports, preserved symbols and invariants it does not touch — all
    still enforced at the gates); `tree` is the module already parsed."""
    fence = _FENCES.get(language(info.path), "python")
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
    scoped = ""
    if compact_meta and fold_history:
        referenced: set[str] = set()
        if tree is not None and focus:
            for f in focus:
                referenced |= _names_in(_resolve_symbol(tree, f)[1])
        meta = _compact_meta(meta, focus or [], referenced)
        scoped = " Frontmatter scoped to the focus (counts stand in for the rest; all still enforced)."
    fm = yaml.safe_dump(meta, sort_keys=False, default_flow_style=False)
    if focus is None:
        body_src, note = info.source, ""
    elif symbol_index:
        body_src = skeleton(info.source, [], tree=tree)
        names = [n for n in symbol_names(info.source)]
        note = (
            f" Source is {len(info.source.splitlines())} lines — over the checkout budget, so this"
            f" frame was auto-skeletonized. Re-checkout with focus=[<name>, …] for full bodies."
            f"\n\nSymbol index ({len(names)}): " + ", ".join(names)
        )
    else:
        body_src = skeleton(info.source, focus, tree=tree)
        note = (
            f" Sliced to focus {focus!r}; other symbols are skeletons —"
            " commit a `patch` (append / replace_symbol / delete_symbol) to fold edits in."
            if focus
            else " Pure skeleton; commit a `patch` to fold edits in."
        )
    body = (
        f"# {info.node_id}\n\n"
        f"Compacted OKF frame for `{info.path}` — "
        f"{len(info.exports)} exports, {len(info.deps)} deps.{note}{scoped}\n\n"
        f"```{fence}\n{body_src}```\n"
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


def write_frames(
    okf_dir: Path, nodes: dict[str, "object"], written: dict[str, str] | None = None
) -> dict[str, str]:
    """Write one frame per node plus index.md. Returns {node_id | '__index__':
    sha256 of the frame text}; pass that back as `written` on the next call and
    frames whose text did not change are left alone (no disk write). Frames of
    nodes this session does not track (left by an older session that named them
    differently) are removed: the directory mirrors exactly one node set."""
    import hashlib

    okf_dir.mkdir(parents=True, exist_ok=True)
    previous = written or {}
    pages = {
        nid: frame_markdown(node.info, node.status, node.locked, node.verified)
        for nid, node in nodes.items()
    }
    pages["__index__"] = index_markdown(nodes)
    shas: dict[str, str] = {}
    for key, text in pages.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        shas[key] = digest
        if previous.get(key) != digest:
            name = "index.md" if key == "__index__" else f"{key}.md"
            (okf_dir / name).write_text(text, encoding="utf-8")
    for stale in okf_dir.glob("*.md"):
        if stale.name != "index.md" and stale.stem not in nodes:
            stale.unlink()
    return shas


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


def _skeleton_def(node: ast.FunctionDef | ast.AsyncFunctionDef, indent: str = "", doc: str | None = "first") -> str:
    """Decorators + signature + `...`; `doc` is "first" (summary line of the
    docstring), "full", or None (stripped — dependency interfaces)."""
    out = [f"{indent}@{ast.unparse(d)}\n" for d in node.decorator_list]
    kw = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    out.append(f"{indent}{kw} {_signature(node)}:\n")
    text = ast.get_docstring(node)
    if text and doc:
        out.append(f'{indent}    """{_doc_line(text) if doc == "first" else text}"""\n')
    out.append(f"{indent}    ...\n")
    return "".join(out)


def _skeleton_class(
    node: ast.ClassDef,
    focus_members: frozenset[str] = frozenset(),
    lines: list[str] | None = None,
    *,
    doc: str | None = "first",
    method_doc: str | None = "first",
    keep_methods: set[str] | None = None,
) -> str:
    """Class header + docstring with every method as a skeleton — except the
    `focus_members` (dotted focus `Class.method`), emitted verbatim from `lines`.
    `doc` / `method_doc` pick the docstring treatment (see _skeleton_def); when
    `keep_methods` is given, only those methods (and the focused ones) are shown
    and a one-line note counts the rest — the budget backstop."""
    bases = ", ".join(ast.unparse(b) for b in node.bases)
    out = [f"@{ast.unparse(d)}\n" for d in node.decorator_list]
    out.append(f"class {node.name}({bases}):\n" if bases else f"class {node.name}:\n")
    text = ast.get_docstring(node)
    if text and doc:
        out.append(f'    """{_doc_line(text) if doc == "first" else text}"""\n')
    members = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    shown = [m for m in members if keep_methods is None or m.name in keep_methods or m.name in focus_members]
    hidden = len(members) - len(shown)
    if not shown and not (text and doc):
        out.append("    ...\n")
    for m in shown:
        if m.name in focus_members and lines is not None:
            out.append(_segment(lines, m))
        else:
            out.append(_skeleton_def(m, indent="    ", doc=method_doc))
    if hidden:
        out.append(f"    # + {hidden} method signatures elided\n")
    return "".join(out)


def _assign_names(node: ast.stmt) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [ast.unparse(t) for t in targets]


def skeleton(source: str, focus: list[str], *, elide_methods: bool = False, compact: int = 0,
             tree: ast.Module | None = None) -> str:
    """Slice a module in two tiers. `focus=[]`: every def/class as decorators +
    signature + first docstring line + `...` (every top-level name kept); runs of
    module-level assignments folded into one summary line; imports verbatim.
    A non-empty `focus`: the focused defs/classes verbatim; a dotted
    `Class.method` keeps its class as a skeleton (sibling method signatures with
    docstrings stripped, `__init__` included) and emits only that method verbatim;
    sibling classes the focus does not reference collapse to counted one-line
    stubs (a run of four or more folds into one line naming them), the module
    docstring to its summary line, and imports the focus cannot reach to a count.
    `elide_methods` (the budget backstop) keeps only `__init__`, the focused
    methods and the methods the focus references, counting the rest.
    `compact` is the unfocused budget ladder: 1 drops docstring lines, `__init__`
    signatures (classes become counted stubs) and the parameters of private
    top-level functions; 2 also elides public function parameters and folds the
    import block — every top-level public name survives both rungs.
    `tree` is the already-parsed module (a checkout parses once)."""
    if tree is None:
        _mod = foreign_module(source)
        if _mod is not None:
            return _mod.skeleton(source, focus)
        tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    keep = {f for f in focus if "." not in f}
    members: dict[str, set[str]] = {}
    for f in focus:
        if "." in f:
            owner, _, member = f.partition(".")
            members.setdefault(owner, set()).add(member)
    focused = bool(focus)
    referenced: set[str] = set()
    if focused:
        for f in focus:
            _owner_body, group = _resolve_symbol(tree, f)
            referenced |= _names_in(group)
            if "." in f:  # the class a focused method lives in: its bases and decorators count too
                owner = next((s for s in tree.body if isinstance(s, ast.ClassDef) and s.name == f.split(".")[0]), None)
                if owner is not None:
                    referenced |= _names_in(owner.bases) | _names_in(owner.decorator_list)
        referenced |= keep | set(members)
    out: list[str] = []
    pending_assigns: list[str] = []
    pending_stubs: list[tuple[str, str]] = []
    pending_misc: list[str] = []
    pending_imports: list[str] = []
    imports_elided = 0
    last = ""

    def flush() -> None:
        nonlocal imports_elided
        if pending_imports or imports_elided:
            out.extend(pending_imports)
            if imports_elided:
                out.append(f"# + {imports_elided} imports elided (unreferenced by the focus)\n")
            pending_imports.clear()
            imports_elided = 0
        if pending_assigns:
            if len(pending_assigns) <= 2:
                out.extend(f"{a} = ...\n" for a in pending_assigns)
            else:
                out.append(
                    f"# folded {len(pending_assigns)} module-level assignments: "
                    f"{pending_assigns[0]} … {pending_assigns[-1]} "
                    f"(checkout without focus for full source)\n"
                )
            pending_assigns.clear()
        if pending_stubs:
            if len(pending_stubs) < 4:
                out.extend("\n\n" + text for _name, text in pending_stubs)
            else:
                out.append(f"\n\n# + {len(pending_stubs)} unreferenced sibling classes elided: "
                           + ", ".join(name for name, _text in pending_stubs) + "\n")
            pending_stubs.clear()
        if pending_misc:
            if len(pending_misc) <= 2:
                out.extend(pending_misc)
            else:
                out.append(f"# + {len(pending_misc)} module-level statements folded: {pending_misc[0][2:].strip()} … "
                           "(checkout without focus for full source)\n")
            pending_misc.clear()

    def category(stmt: ast.stmt) -> str:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            return "assign"
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            return "import"
        if isinstance(stmt, ast.ClassDef) and focused and stmt.name not in keep and stmt.name not in members and stmt.name not in referenced:
            return "stub"
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return "def"
        if isinstance(stmt, ast.Expr) and isinstance(getattr(stmt, "value", None), ast.Constant):
            return "doc"
        return "misc"

    for stmt in tree.body:
        kind = category(stmt)
        if kind != last:
            flush()
        last = kind
        if kind == "assign":
            pending_assigns.extend(_assign_names(stmt))
        elif kind == "import":
            if focused or compact >= 2:
                bound = {(a.asname or a.name.split(".")[0]) for a in stmt.names}
                if focused and ("*" in bound or bound & referenced):
                    pending_imports.append(ast.unparse(stmt) + "\n")
                else:
                    imports_elided += 1
            else:
                pending_imports.append(ast.unparse(stmt) + "\n")
        elif kind == "stub":
            pending_stubs.append((stmt.name, _class_stub(stmt)))
        elif kind == "doc":
            text = stmt.value.value if isinstance(stmt.value.value, str) else None
            if text is not None and (focused or compact >= 1):
                out.append(f'"""{_doc_line(text)}"""\n')
            else:
                out.append(ast.unparse(stmt) + "\n")
        elif kind == "misc":
            pending_misc.append("# " + ast.unparse(stmt).splitlines()[0][:60] + " …\n")
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if stmt.name in keep:
                out.append("\n\n" + _segment(lines, stmt))
            elif focused:  # editing view: signatures only
                out.append("\n\n" + _skeleton_def(stmt, doc=None))
            elif compact >= 2 or (compact == 1 and stmt.name.startswith("_")):
                out.append("\n\n" + _def_stub(stmt))
            else:  # orientation view: summary lines too
                out.append("\n\n" + _skeleton_def(stmt, doc=None if compact else "first"))
        else:  # a class the view keeps as a skeleton
            if stmt.name in keep:
                out.append("\n\n" + _segment(lines, stmt))
            elif stmt.name in members:
                kept = (members[stmt.name] | {"__init__"} | referenced) if elide_methods else None
                out.append("\n\n" + _skeleton_class(
                    stmt, frozenset(members[stmt.name]), lines, method_doc=None, keep_methods=kept
                ))
            elif focused:
                kept = ({"__init__"} | referenced) if elide_methods else None
                out.append("\n\n" + _skeleton_class(stmt, doc=None, method_doc=None, keep_methods=kept))
            elif compact >= 1:
                out.append("\n\n" + _class_stub(stmt))
            else:
                out.append("\n\n" + _skeleton_class(stmt, keep_methods={"__init__"} if elide_methods else None))
    flush()
    return "".join(out).lstrip("\n")


def interface_skeleton(source: str) -> str:
    """Dependency view: signatures, decorators, docstrings — no bodies, no data."""
    _mod = foreign_module(source)
    if _mod is not None:
        return _mod.interface_skeleton(source)
    tree = ast.parse(source)
    parts: list[str] = []
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and not stmt.name.startswith("_"):
            parts.append(_skeleton_def(stmt))
        elif isinstance(stmt, ast.ClassDef) and not stmt.name.startswith("_"):
            parts.append(_skeleton_class(stmt))
    return "\n".join(parts)


# ------------------------------------------------------------ patch folding


def _trailing_main_guard(tree: ast.Module) -> ast.If | None:
    """The module's last top-level statement when it is `if __name__ == "__main__":`."""
    last = tree.body[-1] if tree.body else None
    if not isinstance(last, ast.If) or not isinstance(last.test, ast.Compare):
        return None
    sides = [last.test.left, *last.test.comparators]
    names = {n.id for n in sides if isinstance(n, ast.Name)}
    values = {c.value for c in sides if isinstance(c, ast.Constant)}
    return last if names == {"__name__"} and values == {"__main__"} else None


def apply_patch(source: str, patch: list[dict]) -> str:
    """Fold AST-level ops into canonical source. Ops:
    {"op":"append","code":…} · {"op":"replace_symbol","name":…,"code":…}
    · {"op":"delete_symbol","name":…}. Each op splices only the target's own
    lines (decorators and attached leading comments included) into the original
    text, so comments, pragmas and formatting elsewhere survive verbatim. When
    the module ends with an `if __name__ == "__main__":` guard, `append` inserts
    just before it (comments attached to the guard stay attached), so a script
    never calls code that is defined after its own entry point.
    `name` may be dotted (`Class.method`): the op then splices that method
    inside its class, re-indenting unindented `code`. A name addresses its
    whole definition group — `@overload` stubs plus the implementation, a
    property getter with its setter — never just the first def.
    Raises ValueError on a bad op."""
    _mod = foreign_module(source)
    if _mod is not None:
        return _mod.apply_patch(source, patch)
    for op in patch:
        kind = op.get("op")
        if kind == "append":
            code = op["code"].rstrip("\n") + "\n"
            guard = _trailing_main_guard(ast.parse(source))
            if guard is None:
                source = source.rstrip("\n") + "\n\n\n" + code
            else:
                lines = source.splitlines(keepends=True)
                start, _end = _symbol_span(lines, guard)
                head = "".join(lines[: start - 1]).rstrip("\n")
                tail = "".join(lines[start - 1 :])
                source = (head + "\n\n\n" if head else "") + code + "\n\n" + tail
            continue
        if kind not in ("replace_symbol", "delete_symbol"):
            raise ValueError(f"unknown patch op {kind!r}")
        tree = ast.parse(source)
        lines = source.splitlines(keepends=True)
        body, group = _resolve_symbol(tree, op["name"])
        if not group:
            raise ValueError(f"patch targets unknown top-level symbol {op['name']!r}")
        start, end = _group_span(lines, group)
        head, tail = "".join(lines[: start - 1]), "".join(lines[end:])
        indent = " " * group[0].col_offset
        if kind == "replace_symbol":
            code = op["code"].rstrip("\n") + "\n"
            if indent and not code.startswith((" ", "\t")):
                code = "".join(indent + ln if ln.strip() else ln for ln in code.splitlines(keepends=True))
            source = head + code + tail
        elif indent and len(body) == len(group):
            source = head + f"{indent}...\n" + tail  # a class body cannot be empty
        else:
            head, tail = head.rstrip("\n"), tail.lstrip("\n")
            gap = "\n\n" if indent else "\n\n\n"
            if head and tail:
                source = head + gap + tail
            else:
                source = head + "\n" if head else tail
    return source


def symbol_names(source: str) -> list[str]:
    """Top-level def/class names in file order (the auto-skeleton symbol index)."""
    _mod = foreign_module(source)
    if _mod is not None:
        return _mod.symbol_names(source)
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
    cannot synthesize deterministically. Flexible signatures are fine:
    positional-only parameters are passed positionally, required keyword-only
    ones get typed mocks, and `*args` / `**kwargs` are left empty — on the wild
    corpus most `is None` / `not x` guards sit on exactly such functions.
    A guard is skipped when an earlier guard tests a parameter whose mock would
    be `None` (no usable annotation): `None < 0` raises TypeError in that
    earlier guard before the targeted one is reached (more_itertools.windowed)."""
    out: list[str] = []
    for fn in tree.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        a = fn.args
        positional = a.posonlyargs + a.args
        params = {p.arg: p for p in positional + a.kwonlyargs}
        if not params:
            continue
        required = {p.arg for p in positional[: len(positional) - len(a.defaults)]}
        required |= {p.arg for p, d in zip(a.kwonlyargs, a.kw_defaults) if d is None}
        body = fn.body
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
            body = body[1:]  # docstring
        tested_before: set[str] = set()
        for stmt in body:
            if not (isinstance(stmt, ast.If) and not stmt.orelse and len(stmt.body) == 1
                    and isinstance(stmt.body[0], ast.Raise)):
                break
            tested_here = {n.id for n in ast.walk(stmt.test) if isinstance(n, ast.Name) and n.id in params}
            exc = _exception_name(stmt.body[0])
            hit = _violating_value(stmt.test, params)
            if exc is not None and hit is not None:
                name, value = hit
                blocked = any(p != name and mock_value(params[p]) == "None" for p in tested_before)
                if not blocked:
                    # Positional-only: everything up to the violating parameter (or the
                    # required prefix, whichever is longer) must be passed in order.
                    hit_pos = next((i for i, p in enumerate(a.posonlyargs) if p.arg == name), -1)
                    n_pos = max(hit_pos + 1, sum(1 for p in a.posonlyargs if p.arg in required))
                    args = [value if p.arg == name else mock_value(p) for p in a.posonlyargs[:n_pos]]
                    for p in a.args + a.kwonlyargs:
                        if p.arg == name:
                            args.append(f"{p.arg}={value}")
                        elif p.arg in required:
                            args.append(f"{p.arg}={mock_value(p)}")
                    inv = f"call:{fn.name}({', '.join(args)}) raises {exc}"
                    if inv not in out:
                        out.append(inv)
            tested_before |= tested_here
    return out


# ------------------------------------------------ package-aware import graph


def module_name(path: str) -> str:
    """Dotted import name of a tracked file: `pkg/models.py` -> `pkg.models`,
    `pkg/__init__.py` -> `pkg`; a root-level `__init__.py` stays `__init__`."""
    if not path:
        raise ValueError("empty module path")
    parts = strip_suffix(path.replace("\\", "/")).split("/")
    if parts[-1] == "__init__" and len(parts) > 1:
        parts = parts[:-1]
    return ".".join(parts)


def _package_of(path: str) -> str:
    """Dotted package a file lives in (`pkg/__init__.py` and `pkg/x.py` -> `pkg`)."""
    parts = strip_suffix(path.replace("\\", "/")).split("/")
    return ".".join(parts[:-1])


def module_map(paths: dict[str, str]) -> dict[str, str]:
    """Importable dotted names -> node_id.

    Root-relative names always resolve (`backend.kernel`). Two kinds of alias
    resolve too, but only while unambiguous across the project: the name with
    its first directory stripped — the conventional source roots `src/`,
    `backend/`, … that land on sys.path, so `backend/kernel/__init__.py` is
    also `kernel` — and the bare stem (flat, sys.path-style projects). A
    root-relative name always beats an alias of the same spelling, and an alias
    whose top-level name belongs to the standard library is never registered:
    `utils/json.py` must not capture `import json`."""
    import sys

    out = {module_name(p): nid for nid, p in paths.items()}
    stdlib = getattr(sys, "stdlib_module_names", frozenset())
    candidates: dict[str, set[str]] = {}
    for nid, p in paths.items():
        parts = p.replace("\\", "/").split("/")
        names = {strip_suffix(parts[-1])}
        if len(parts) > 1:
            names.add(module_name("/".join(parts[1:])))
        for name in names:
            if name.split(".")[0] in stdlib:
                continue
            candidates.setdefault(name, set()).add(nid)
    for name, nids in candidates.items():
        if len(nids) == 1:
            out.setdefault(name, next(iter(nids)))
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
    _mod = lang_module(path)
    if _mod is not None:
        return _mod.resolve_imports(node_id, path, source, modules)
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


def _signatures(source: str) -> dict[str, str]:
    """Top-level name -> signature for every def and class, `_private` ones
    included: the contract a dependent that spells `from m import _name` relies
    on, which `exports` (public names only) does not cover."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    out: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[stmt.name] = _signature(stmt)
        elif isinstance(stmt, ast.ClassDef):
            out[stmt.name] = f"class {stmt.name}({', '.join(ast.unparse(b) for b in stmt.bases)})"
    return out


def _definition_group(body: list[ast.stmt], name: str) -> list[ast.stmt]:
    """The contiguous run of defs/classes named `name`, starting at its first
    definition: an `@overload` stub chain with its implementation, or a
    `@property` getter with its `.setter` / `.deleter`, is one symbol. Patch
    ops and focused checkouts address the whole run, never just the first def."""
    group: list[ast.stmt] = []
    for stmt in body:
        is_def = isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        if is_def and stmt.name == name:
            group.append(stmt)
        elif group:
            break
    return group


def _resolve_symbol(tree: ast.Module, dotted: str) -> tuple[list[ast.stmt], list[ast.stmt]]:
    """(container body, definition group) for `name` or `Class.method`
    (nested classes chain further). An empty group means no such symbol."""
    body: list[ast.stmt] = tree.body
    parts = dotted.split(".")
    for part in parts[:-1]:
        owner = next((s for s in body if isinstance(s, ast.ClassDef) and s.name == part), None)
        if owner is None:
            return body, []
        body = owner.body
    return body, _definition_group(body, parts[-1])


def _group_span(source_lines: list[str], group: list[ast.stmt]) -> tuple[int, int]:
    """Line range covering every definition of a group, leading comments and
    decorators of the first one included."""
    start, _ = _symbol_span(source_lines, group[0])
    _, end = _symbol_span(source_lines, group[-1])
    return start, end


def _doc_line(doc: str) -> str:
    """The summary line of a docstring: its first non-empty line."""
    for line in doc.strip().splitlines():
        if line.strip():
            return line.strip()
    return ""


def _names_in(nodes) -> set[str]:
    """Every `ast.Name` id and `ast.Attribute` attr under the given nodes — the
    names a piece of code can possibly refer to (reference analysis for focus
    scoping; conservative on purpose)."""
    out: set[str] = set()
    for node in nodes:
        for n in ast.walk(node):
            if isinstance(n, ast.Name):
                out.add(n.id)
            elif isinstance(n, ast.Attribute):
                out.add(n.attr)
    return out


def _class_stub(node: ast.ClassDef) -> str:
    """One-line stub for a sibling class the focus does not reference; a second
    line counts the method signatures the stub hides."""
    bases = ", ".join(ast.unparse(b) for b in node.bases)
    methods = sum(1 for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)))
    out = [f"@{ast.unparse(d)}\n" for d in node.decorator_list]
    out.append(f"class {node.name}({bases}): ...\n" if bases else f"class {node.name}: ...\n")
    if methods:
        out.append(f"    # + {methods} method signatures elided\n")
    return "".join(out)


_TRACKED_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
_EXCLUDED_DIRS = frozenset({"node_modules", "dist", "build", "out", "coverage", ".stepcheck"})


def language(path: str) -> str:
    """`python` for `.py`; `typescript`, `go`, `rust` or `java` for the other suffixes
    the kernel tracks (`.d.ts` declaration files are never tracked); `other` otherwise."""
    p = path.replace("\\", "/").lower()
    if p.endswith(".py"):
        return "python"
    if p.endswith(".d.ts"):
        return "other"
    for lang, suffixes in _LANGUAGE_SUFFIXES.items():
        if p.endswith(suffixes):
            return lang
    return "other"


def strip_suffix(path: str) -> str:
    """Path without its tracked source suffix (`pkg/models.py` -> `pkg/models`,
    `src/App.tsx` -> `src/App`, `pkg/util.go` -> `pkg/util`)."""
    for suffix in _ALL_SUFFIXES:
        if path.endswith(suffix):
            return path[: -len(suffix)]
    return path


def tracked_files(root: Path) -> list[Path]:
    """Every source file the kernel indexes under `root`: Python, TypeScript /
    JavaScript, Go, Rust and Java, skipping `.d.ts`, hidden entries, `.stepcheck/`
    and build/dependency directories (`node_modules`, `dist`, `build`, `out`,
    `vendor`, `target`, `testdata`; `.gradle` is hidden)."""
    return sorted(
        p for p in root.rglob("*")
        if p.is_file() and language(str(p)) != "other"
        and not any(part in _EXCLUDED_DIRS_ALL or part.startswith(".") for part in p.relative_to(root).parts)
    )


def _def_stub(node: ast.FunctionDef | ast.AsyncFunctionDef, indent: str = "") -> str:
    """Name-only stub of a function: decorators + `def name(…): ...` — the last
    rung of the unfocused budget ladder, where the symbol must survive but its
    parameters may not (re-checkout with focus=[name] shows them)."""
    out = [f"{indent}@{ast.unparse(d)}\n" for d in node.decorator_list]
    kw = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    out.append(f"{indent}{kw} {node.name}(…): ...\n")
    return "".join(out)


def _compact_meta(meta: dict, focus: list[str], referenced: set[str] | None = None) -> dict:
    """Scope the frontmatter lists of a checkout payload to a focus: exports,
    preserved symbols and invariants that name a focused symbol (or, for the
    preserved symbols, a name the focused code references) stay; the rest
    becomes a `<key>_elided` count. An unfocused call (the budget ladder) keeps
    every invariant — the Gate C contract — and counts the two symbol lists."""
    names: set[str] = set()
    for f in focus:
        names.add(f)
        names.update(f.split("."))
    extra = names | set(referenced or ())
    patterns = {n: re.compile(rf"(?<![\w.]){re.escape(n)}(?![\w])") for n in extra}

    def touches(entry: str, pool: set[str]) -> bool:
        return any(patterns[n].search(entry) for n in pool)

    out = dict(meta)
    for key, pool in (("exports", names), ("preserved_symbols", extra), ("invariants", names), ("invariants_auto_mined", names)):
        items = list(meta.get(key) or [])
        if key.startswith("invariants") and not focus:
            continue
        kept = [e for e in items if touches(str(e), pool)]
        out[key] = kept
        if len(kept) != len(items):
            out[f"{key}_elided"] = len(items) - len(kept)
    return out


def _compact_frontmatter(front: str, focus: list[str]) -> str:
    """`_compact_meta` applied to the YAML text of a payload frame (the budget
    backstop works on the rendered frame)."""
    meta = yaml.safe_load(front)
    if not isinstance(meta, dict):
        return front
    return yaml.safe_dump(_compact_meta(meta, focus), sort_keys=False, default_flow_style=False)


_LANGUAGE_SUFFIXES = {
    "typescript": (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"),
    "go": (".go",),
    "rust": (".rs",),
    "java": (".java",),
}
_ALL_SUFFIXES = (".py",) + tuple(s for suffixes in _LANGUAGE_SUFFIXES.values() for s in suffixes)
_LANGUAGE_MODULES = {"typescript": "_ts", "go": "_go", "rust": "_rs", "java": "_java"}
_FENCES = {"typescript": "ts", "go": "go", "rust": "rust", "java": "java"}
_EXCLUDED_DIRS_ALL = _EXCLUDED_DIRS | frozenset({"vendor", "target", "testdata"})


def lang_module(path: str):
    """The language module (`_ts`, `_go`, `_rs`, `_java`) for a tracked path, or None for Python."""
    import importlib

    name = _LANGUAGE_MODULES.get(language(path))
    return importlib.import_module("." + name, __package__) if name else None


def foreign_module(source: str):
    """For the source-only entry points: None when Python parses the text, else the
    language module whose fingerprint matches (Go `package x` line, Java
    `package …;` / `import …;` / `public class`, Rust `fn name(` / `impl`, else
    TypeScript / JavaScript). A Python module that fails to parse never reaches
    these (Gate A rejects it first)."""
    if not source.strip():
        return None
    try:
        ast.parse(source)
        return None
    except (SyntaxError, ValueError):
        pass
    from . import _go, _java, _rs, _ts

    for mod in (_go, _java, _rs):
        if mod.looks_like(source):
            return mod
    return _ts


def present_guards(source: str, path: str | None = None) -> set[str]:
    """Every `guard:<symbol>:<cond> <effect>` structurally present in `source`
    (at any depth of the symbol's body), for Gate C's conservation check."""
    mod = (lang_module(path) if path else None) or foreign_module(source)
    return set(mod.present_guards(source)) if mod is not None and hasattr(mod, "present_guards") else set()
