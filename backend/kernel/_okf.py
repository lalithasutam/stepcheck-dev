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
    fingerprinted per dotted symbol (`@width.setter on Box.width`). A decorator a
    symbol carries more than once — `@overload` on each signature of an overload
    set — is counted (`@overload on f x2`, `x3`, …), so losing one of the blocks
    is an omission too."""
    _mod = lang_module(path)
    if _mod is not None:
        return _mod.analyze(node_id, path, source, project_modules)
    tree = ast.parse(source)
    modules = project_modules if isinstance(project_modules, dict) else {m: m for m in project_modules}
    exports: list[str] = []
    preserved: list[str] = []
    dec_counts: dict[str, int] = {}

    def keep_decorators(stmt: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, owner: str = "") -> None:
        for dec in stmt.decorator_list:
            name = ast.unparse(dec).split("(")[0]
            per_symbol = f"@{name} on {owner}.{stmt.name}" if owner else f"@{name} on {stmt.name}"
            symbols = (per_symbol,) if owner else (f"@{name}", per_symbol)
            for sym in symbols:
                if sym not in preserved:
                    preserved.append(sym)
            dec_counts[per_symbol] = dec_counts.get(per_symbol, 0) + 1
            if dec_counts[per_symbol] > 1:
                preserved.append(f"{per_symbol} x{dec_counts[per_symbol]}")

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
    mined = []
    for inv in mine_guard_invariants(tree) + mine_branch_invariants(tree) + mine_structural_guards(tree):
        if inv not in manual and inv not in mined:
            mined.append(inv)
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
        if focus is not None and fence == "python":
            # A sliced payload lists structural guards once, in its Locked invariants
            # section (scoped to the focus); the frontmatter only counts them.
            guards = sum(inv.startswith("guard:") for inv in meta["invariants"])
            if guards:
                for key in ("invariants", "invariants_auto_mined"):
                    meta[key] = [inv for inv in meta[key] if not inv.startswith("guard:")]
                meta["guard_invariants"] = guards
    else:
        meta["verified"] = verified
    scoped = ""
    callees: list[str] = []
    over_budget: list[str] = []
    if tree is not None and focus:
        callees, over_budget = callee_closure(tree, focus, info.source)
    if compact_meta and fold_history:
        referenced: set[str] = set()
        effective = list(focus or []) + callees
        if tree is not None and focus:
            for f in effective:
                referenced |= _names_in(_resolve_symbol(tree, f)[1])
        meta = _compact_meta(meta, effective, referenced)
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
        if callees:
            note += (" Same-file callees, decorators and class state (__init__ / __post_init__)"
                     f" of the focus, expanded verbatim: {', '.join(callees)}.")
        if tree is not None and focus:
            consts, consts_over = cone_constants(tree, list(focus) + callees, info.source)
            if consts:
                note += f" Module constants the focus reads, kept verbatim: {', '.join(consts)}."
            if consts_over:
                note += (f" Constants folded (over the {CONST_TOKEN_BUDGET:,}-token constant budget):"
                         f" {', '.join(consts_over)}.")
            if over_budget:  # what the folded callees read is part of the cone too: named, not shown
                behind_kept, behind_over = cone_constants(tree, list(focus) + callees + over_budget, info.source)
                behind = sorted((set(behind_kept) | set(behind_over)) - set(consts) - set(consts_over))
                if behind:
                    note += f" Constants behind that budget: {', '.join(behind)}."
        if over_budget:
            note += (f" Callees kept as signatures (over the {CALLEE_TOKEN_BUDGET:,}-token callee budget;"
                     f" add them to focus to see them): {', '.join(over_budget)}.")
        tops = {f for f in list(focus) + callees if "." not in f}
        covers = (bool(focus) and set(symbol_names(info.source)) <= tops
                  and len(body_src) >= 0.9 * len(info.source))  # nothing folded (data ballast)
        if fold_history and (covers or len(fm) + len(note) > len(info.source)):
            # The focus already covers the whole module, or the full header
            # would outweigh the file: a minimal header (the slice itself unchanged,
            # or the source verbatim when the slice is the module). Exports,
            # preserved symbols and invariants are in the code shown or the
            # payload's Locked invariants list, and all still enforced at the gates.
            mini = {k: meta[k] for k in ("node_id", "path", "status", "locked", "deps", "attestation") if k in meta}
            if not mini.get("deps"):
                mini.pop("deps", None)
            if not (mini.get("attestation") or {}).get("count"):
                mini.pop("attestation", None)  # nothing attested yet
            src = info.source if covers else body_src
            src = src if src.endswith("\n") else src + "\n"
            what = ("full source (the focus covers the module)" if covers
                    else f"focus {list(focus)!r}, rest as skeletons" if focus else "pure skeleton")
            return (f"---\n{yaml.safe_dump(mini, sort_keys=False, default_flow_style=False)}---\n\n"
                    f"# {info.node_id}\n\n`{info.path}`, compact header: {what}.\n\n```{fence}\n{src}```\n")
    body = (
        f"# {info.node_id}\n\n"
        f"Compacted OKF frame for `{info.path}` — "
        f"{len(info.exports)} exports, {len(info.deps)} deps.{note}{scoped}\n\n"
        f"```{fence}\n{body_src}```\n"
    )
    return f"---\n{fm}---\n\n{body}"


def covers_module(source: str, focus: list[str], tree: ast.Module | None) -> bool:
    """Whether a focus (with its same-file causal cone) reaches every top-level
    symbol of the module — nothing would be elided to `...`."""
    if not focus:
        return False
    cone = list(focus) + (callee_closure(tree, list(focus), source)[0] if tree is not None else [])
    return set(symbol_names(source)) <= {f for f in cone if "." not in f}


def pragma_frame(info: ModuleInfo, status: str, locked: bool, invariants: int, body: str | None = None, *,
                 callees: list[str] | tuple[str, ...] = (), deps_elided: list[str] | tuple[str, ...] = ()) -> str:
    """The zero-bloat frame: one pragma comment line — node, state, how many
    invariants are enforced, the same-file callees expanded with the focus and, when
    the dependency interfaces did not fit, the deps whose signatures the payload's
    `dependency_signatures` field carries — then `body` (the focused slice, or the
    raw source when omitted) in a code fence. What a focused checkout serves when
    the OKF frame would cost more than the file; everything counted is enforced."""
    lead = "#" if language(info.path) == "python" else "//"
    fence = _FENCES.get(language(info.path), "python")
    state = f"{status}, locked" if locked else status
    extra = (f" | callees: {', '.join(callees)}" if callees else "") + (
        f" | deps: {', '.join(deps_elided)} (signatures in dependency_signatures)" if deps_elided else "")
    src = info.source if body is None else body
    src = src if src.endswith("\n") else src + "\n"
    return f"{lead} [stepcheck: {info.node_id} | {state} | invariants: {invariants} enforced{extra}]\n```{fence}\n{src}```\n"


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


def _frame_describes_disk(okf_dir: Path, nid: str, node, root: Path) -> bool:
    """True when the frame already on disk is VERIFIED with an attestation that
    hashes to the tracked file's current bytes while this session's own view of
    the node does not — a stale session must not overwrite the truth about the
    tree with its rejection or its older attestation."""
    import hashlib

    try:
        disk = hashlib.sha256((root / node.info.path).read_bytes()).hexdigest()
        mine = node.verified[-1]["payload"]["sha256"] if node.verified else None
        if mine == disk:
            return False
        text = (okf_dir / f"{nid}.md").read_text(encoding="utf-8")
    except (OSError, KeyError, TypeError):
        return False
    front = text.split("---\n")[1] if text.startswith("---\n") else ""
    status = re.search(r"^status: (\S+)$", front, re.M)
    shas = re.findall(r"^\s+sha256: ([0-9a-f]{64})$", front, re.M)
    return bool(status and status.group(1) == "VERIFIED" and shas and shas[-1] == disk)


def write_frames(
    okf_dir: Path, nodes: dict[str, "object"], written: dict[str, str] | None = None, *,
    root: Path | None = None,
) -> dict[str, str]:
    """Write one frame per node plus index.md. Returns {node_id | '__index__':
    sha256 of the frame text}; pass that back as `written` on the next call and
    frames whose text did not change are left alone (no disk write). Frames of
    nodes this session does not track (left by an older session that named them
    differently) are removed: the directory mirrors exactly one node set. With
    `root`, a frame that is VERIFIED on disk and attests the file's current bytes
    is left alone by a session whose view of that node is behind (its rejected
    sync, its older attestation): the shared frame keeps describing the tree."""
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
        if previous.get(key) != digest:
            if key != "__index__" and root is not None and _frame_describes_disk(okf_dir, key, nodes[key], root):
                continue  # not ours to rewrite; re-evaluated on the next flush
            name = "index.md" if key == "__index__" else f"{key}.md"
            (okf_dir / name).write_text(text, encoding="utf-8")
        shas[key] = digest
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
    attrs = []
    if focus_members and lines is not None:  # class-level state a focused method reads: verbatim
        attrs = [_segment(lines, s) for s in node.body if isinstance(s, (ast.Assign, ast.AnnAssign))]
        out.extend(attrs)
    members = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    shown = [m for m in members if keep_methods is None or m.name in keep_methods or m.name in focus_members]
    hidden = len(members) - len(shown)
    if not shown and not attrs and not (text and doc):
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
    The causal cone rides along verbatim: same-file callees and bare decorators,
    a focused method's `__init__` / `__post_init__` and class-level attributes,
    and the module constants the cone reads (see callee_closure, cone_constants).
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
    if focus:
        focus = list(focus) + callee_closure(tree, focus, source)[0]
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
    consts = set(cone_constants(tree, focus, source)[0]) if focused else set()
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
            return "const" if _bound_names(stmt) & consts else "assign"
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
        prev, last = last, kind
        if kind == "const":  # a constant the cone reads: verbatim, not folded
            out.append(("\n\n" if prev in ("def", "stub") else "") + _segment(lines, stmt))
        elif kind == "assign":
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


def mine_guard_invariants(tree: ast.Module, covered: set | None = None) -> list[str]:
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
                    if covered is not None:  # (function, guard test) this call: invariant exercises
                        covered.add((fn.name, ast.unparse(stmt.test)))
            tested_before |= tested_here
    return out


# ------------------------------------------- structural Python guard mining

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _py_symbols(body: list[ast.stmt], prefix: str = ""):
    """(dotted symbol, def node) for every function and method, nested scopes
    included and chained by name: `Outer.Inner.m`, and a class or helper defined
    inside a function as `fn.Inner.m` / `fn.helper` (flask's
    attach_enctype_error_multidict keeps its guards in such a class)."""
    for stmt in _scopes_in(body):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield f"{prefix}{stmt.name}", stmt
            yield from _py_symbols(stmt.body, f"{prefix}{stmt.name}.")
        elif isinstance(stmt, ast.ClassDef):
            yield from _py_symbols(stmt.body, f"{prefix}{stmt.name}.")


def _own_nodes(stmts: list[ast.stmt]):
    """Every AST node under `stmts` that belongs to this scope: nested defs,
    classes and lambdas are their own symbols (or anonymous) and are skipped."""
    stack = list(reversed(stmts))
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed([c for c in ast.iter_child_nodes(node) if not isinstance(c, _SCOPES)]))


def _scopes_in(stmts: list[ast.stmt]):
    """The defs and classes directly owned by this scope, in source order — also
    those under `if` / `try` / `with` blocks — without entering them."""
    stack = list(reversed(stmts))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node
        elif not isinstance(node, ast.Lambda):
            stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _raised(stmt: ast.Raise) -> str:
    exc = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
    return ast.unparse(exc) if exc is not None else "<re-raise>"


def _early_value(stmt: ast.Return) -> str | None:
    """The normalized value of a constant / None / empty-container return, else None."""
    v = stmt.value
    if v is None:
        return "None"
    if isinstance(v, ast.Constant) or (
        isinstance(v, (ast.List, ast.Tuple, ast.Set)) and not v.elts
    ) or (isinstance(v, ast.Dict) and not v.keys):
        return ast.unparse(v)
    return None


def _py_guards(fn: ast.FunctionDef | ast.AsyncFunctionDef, mining: bool) -> list[str]:
    """The guard clauses of one def, normalized (`ast.unparse`: whitespace, quotes,
    parentheses and messages never matter):
      `if <cond> raises <Exc>`   — any `if` whose branch ends in `raise`, at any depth;
      `assert <cond>`            — any assert;
      `if <cond> returns <v>`    — an early return of a constant / None / empty
                                   container;
      `if <cond> returns early`  — an early return of a computed value: the condition
                                   is held, the expression may be refactored;
      `else raises <Exc>`        — an if / elif chain whose final `else` raises (one
                                   clause per chain, so branches may be added);
      `except <T> raises <Exc>`  — a handler that raises (`<re-raise>` for bare raise);
      `<obj>.get(<key>) has default` — a two-argument `.get(key, default)` lookup
                                   (any key, any default), which must not become a
                                   bare `<obj>[<key>]` subscript.
    The `returns` clauses are mined from the `if` statements that are direct branches
    of the def — not from those inside a loop, `with` or `try`, which are control
    flow rather than guards. `mining=False` lists what is present (Gate C's side):
    any if-with-return at any depth counts, also as `returns early`, and a `.get(key)`
    with or without a default keeps the lookup guarded."""
    out: list[str] = []
    seen: dict[str, int] = {}

    def add(g: str) -> None:
        # A clause that repeats (two handlers both `except ImportError raises …`) is
        # numbered, so losing one copy is still a missing invariant.
        seen[g] = seen.get(g, 0) + 1
        out.append(g if seen[g] == 1 else f"{g} #{seen[g]}")

    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
        body = body[1:]
    direct = {id(stmt) for stmt in body if isinstance(stmt, ast.If)}
    elifs = {id(n.orelse[0]) for n in _own_nodes(body)
             if isinstance(n, ast.If) and len(n.orelse) == 1 and isinstance(n.orelse[0], ast.If)}
    for node in _own_nodes(body):
        if isinstance(node, ast.If) and node.body:
            last = node.body[-1]
            if isinstance(last, ast.Raise):
                add(f"if {ast.unparse(node.test)} raises {_raised(last)}")
            elif isinstance(last, ast.Return) and (not mining or id(node) in direct):
                cond, value = ast.unparse(node.test), _early_value(last)
                if value is not None:
                    add(f"if {cond} returns {value}")
                if value is None or not mining:
                    add(f"if {cond} returns early")
            if id(node) not in elifs:  # the root of an if / elif chain: does its final else raise?
                tail = node
                while len(tail.orelse) == 1 and isinstance(tail.orelse[0], ast.If):
                    tail = tail.orelse[0]
                if tail.orelse and isinstance(tail.orelse[-1], ast.Raise):
                    add(f"else raises {_raised(tail.orelse[-1])}")
        elif isinstance(node, ast.Assert):
            add(f"assert {ast.unparse(node.test)}")
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
              and not node.keywords and (len(node.args) == 2 or (not mining and len(node.args) == 1))):
            add(f"{ast.unparse(node.func.value)}.get({ast.unparse(node.args[0])}) has default")
        elif isinstance(node, ast.ExceptHandler):
            caught = ast.unparse(node.type) if node.type is not None else "*"
            for sub in _own_nodes(node.body):
                if isinstance(sub, ast.Raise):
                    add(f"except {caught} raises {_raised(sub)}")
    return out


def mine_structural_guards(tree: ast.Module) -> list[str]:
    """`guard:<Symbol>:<clause>` for every guard clause (see `_py_guards`) of every
    top-level function and class method — no runtime argument synthesis, so
    methods, external types (`isinstance(x, CookieJar)`), asserts and non-leading
    checks are covered. Gate C requires each one to stay structurally present
    in its symbol's body unless the commit declares the deletion. A leading guard
    the runtime miner already exercises (`call:fn(…) raises Exc`) is left to that
    semantic check, so an equivalent rewrite of its condition still passes."""
    covered: set = set()
    mine_guard_invariants(tree, covered)
    return [f"guard:{sym}:{g}" for sym, fn in _py_symbols(tree.body) for g in _py_guards(fn, True)
            if not any(sym == name and g.startswith(f"if {test} raises ") for name, test in covered)]


def present_structural_guards(tree: ast.Module) -> set[str]:
    """Every Python `guard:` clause present anywhere in each symbol's body."""
    return {f"guard:{sym}:{g}" for sym, fn in _py_symbols(tree.body) for g in _py_guards(fn, False)}


# ------------------------------------- deterministic branch invariant mining

_SAMPLES = {"str": "x", "int": 100, "float": 2.5, "bool": True}
_PURE_BUILTINS = frozenset({
    "abs", "all", "any", "bool", "dict", "divmod", "enumerate", "float", "frozenset", "int",
    "isinstance", "len", "list", "max", "min", "range", "repr", "reversed", "round", "set",
    "sorted", "str", "sum", "tuple", "zip", "True", "False", "None",
})


def _exception_builtins() -> frozenset[str]:
    import builtins

    return frozenset(
        n for n in dir(builtins)
        if isinstance(getattr(builtins, n), type) and issubclass(getattr(builtins, n), BaseException)
    )


def _plain_literal(value) -> bool:
    """A value whose repr is a Python literal that evaluates back to it."""
    if value is None or isinstance(value, (bool, int, str)):
        return True
    if isinstance(value, float):
        return value == value and value not in (float("inf"), float("-inf"))
    if isinstance(value, (list, tuple)):
        return all(_plain_literal(v) for v in value)
    if isinstance(value, dict):
        return all(_plain_literal(k) and _plain_literal(v) for k, v in value.items())
    return False


def _branch_facts(fn: ast.FunctionDef, params: set[str]) -> list[tuple[str, object]]:
    """(param, literal) pairs from the function's leading branch prefix: each
    `if <param> == <literal>: return …` or `if <param> in (<literal>, …): return …`.
    The prefix is the run of single-statement `if … : return/raise` blocks at the
    top of the body; the first other statement ends it (past it, state the
    miner cannot see may decide the branch)."""
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
        body = body[1:]
    facts: list[tuple[str, object]] = []
    for stmt in body:
        if not (isinstance(stmt, ast.If) and not stmt.orelse and len(stmt.body) == 1
                and isinstance(stmt.body[0], (ast.Return, ast.Raise))):
            break
        test = stmt.test
        if not (isinstance(stmt.body[0], ast.Return) and isinstance(test, ast.Compare) and len(test.ops) == 1
                and isinstance(test.left, ast.Name) and test.left.id in params):
            continue
        op, right = test.ops[0], test.comparators[0]
        if isinstance(op, ast.Eq):
            candidates = [right]
        elif isinstance(op, ast.In) and isinstance(right, (ast.Tuple, ast.List, ast.Set)):
            candidates = list(right.elts)
        else:
            continue
        for lit in candidates:
            try:
                value = ast.literal_eval(lit)
            except ValueError:
                continue
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                fact = (test.left.id, value)
                if fact not in facts:
                    facts.append(fact)
    return facts


def _same_file_calls(fn: ast.FunctionDef, funcs: set[str]) -> set[str]:
    return {n.func.id for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in funcs}


def _is_pure(fn: ast.FunctionDef, allowed: set[str]) -> bool:
    """Statically self-contained: no decorators, no async / generators, no
    imports or global / nonlocal rebinding, and every name it reads is a
    parameter, a local, or in `allowed` (same-file pure functions, literal
    module constants, side-effect-free builtins and exception types)."""
    if fn.decorator_list or isinstance(fn, ast.AsyncFunctionDef):
        return False
    local: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await, ast.Global, ast.Nonlocal,
                             ast.Import, ast.ImportFrom)):
            return False
        if isinstance(node, ast.arg):
            local.add(node.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            local.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not fn:
            local.add(node.name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            local.add(node.name)
    # Annotations are never evaluated (the closure is compiled with
    # `from __future__ import annotations`), so the names they mention do not count.
    hints = [fn.returns] + [p.annotation for p in ast.walk(fn) if isinstance(p, ast.arg)]
    hints += [n.annotation for n in ast.walk(fn) if isinstance(n, ast.AnnAssign)]
    skip = {id(n) for h in hints if h is not None for n in ast.walk(h)}
    reads = {n.id for n in ast.walk(fn)
             if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and id(n) not in skip}
    return reads <= (local | allowed)


def mine_branch_invariants(tree: ast.Module) -> list[str]:
    """Characterize deterministic value-returning branches as executable
    invariants `call:fn(param=<literal>, …) == <result>`.

    For every top-level function whose leading prefix branches on a parameter
    against a literal (`_branch_facts`), the function itself and every
    same-file function that reaches it through direct calls and takes a
    parameter of the same name are called with that literal (other required
    parameters get typed samples) — but only when the whole call closure is
    statically pure (`_is_pure`) — and the result, if it is a plain literal and
    the same on a second run, becomes the expected value. Execution happens in
    a namespace holding just the closure's defs, the module's literal
    constants and a builtin allowlist, under the Gate C step budget; anything
    that raises, overruns or returns a non-literal is skipped."""
    from . import _sandbox

    fns = {s.name: s for s in tree.body if isinstance(s, ast.FunctionDef)}
    if not fns:
        return []
    facts = {name: _branch_facts(fn, {a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs})
             for name, fn in fns.items()}
    if not any(facts.values()):
        return []

    constants: dict[str, object] = {}
    for stmt in tree.body:
        if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)):
            try:
                value = ast.literal_eval(stmt.value)
            except ValueError:
                constants.pop(stmt.targets[0].id, None)
                continue
            if _plain_literal(value):
                constants[stmt.targets[0].id] = value
    calls = {name: _same_file_calls(fn, set(fns)) for name, fn in fns.items()}

    def closure(name: str) -> set[str]:
        seen, stack = {name}, [name]
        while stack:
            for callee in calls[stack.pop()]:
                if callee not in seen:
                    seen.add(callee)
                    stack.append(callee)
        return seen

    exceptions = _exception_builtins()
    pure: dict[str, bool] = {}
    for name in fns:
        allowed = set(fns) | set(constants) | _PURE_BUILTINS | exceptions
        pure[name] = _is_pure(fns[name], allowed)

    targets: list[tuple[str, str, object]] = []
    for helper, pairs in facts.items():
        for param, value in pairs:
            for name, fn in fns.items():
                a = fn.args
                takes = {p.arg for p in a.posonlyargs + a.args + a.kwonlyargs}
                if (name == helper or helper in closure(name)) and param in takes:
                    if (name, param, value) not in targets:
                        targets.append((name, param, value))
    if not targets:
        return []

    import builtins
    import __future__

    out: list[str] = []
    for name, param, value in targets:
        group = closure(name)
        if not all(pure[g] for g in group):
            continue
        a = fns[name].args
        positional = a.posonlyargs + a.args
        required = {p.arg for p in positional[: len(positional) - len(a.defaults)]}
        required |= {p.arg for p, d in zip(a.kwonlyargs, a.kw_defaults) if d is None}
        pos_args: list[object] = []
        kw_args: dict[str, object] = {}
        ok = True
        for p in positional + a.kwonlyargs:
            if p.arg == param:
                v = value
            elif p.arg in required:
                sample = _annotation_name(p)
                if sample not in _SAMPLES:
                    ok = False
                    break
                v = _SAMPLES[sample]
            else:
                continue
            if p in a.posonlyargs:
                pos_args.append(v)
            else:
                kw_args[p.arg] = v
        if not ok:
            continue
        module = ast.Module(body=[fns[g] for g in fns if g in group], type_ignores=[])
        try:
            code = compile(ast.unparse(module), "<okf-branch>", "exec",
                           flags=__future__.annotations.compiler_flag, dont_inherit=True)
            ns: dict = {"__builtins__": {n: getattr(builtins, n) for n in (_PURE_BUILTINS | exceptions)
                                         if hasattr(builtins, n)}, **constants}
            results = []
            for _ in range(2):
                run = dict(ns)
                exec(code, run)  # noqa: S102 — defs only; the closure is statically pure
                results.append(_sandbox.guarded(lambda run=run: run[name](*pos_args, **kw_args)))
        except (Exception, _sandbox.ExecutionBudgetExceeded):  # noqa: BLE001 — not characterizable
            continue
        result = results[0]
        if not (_plain_literal(result) and results[1] == result):
            continue
        try:
            if ast.literal_eval(repr(result)) != result:
                continue
        except (ValueError, SyntaxError):
            continue
        args = [repr(v) for v in pos_args] + [f"{k}={v!r}" for k, v in kw_args.items()]
        inv = f"call:{name}({', '.join(args)}) == {result!r}"
        if inv not in out:
            out.append(inv)
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
    local binding) for every import resolving to another project module — at any
    nesting depth: function-scoped (lazy) imports, `if TYPE_CHECKING:` blocks and
    `try: … except ImportError:` fallbacks are dependencies too.
    Relative imports resolve against the importing file's package."""
    package = _package_of(path)
    out: list[tuple[str, str | None, str | None]] = []

    def add(nid: str | None, name: str | None, local: str | None) -> None:
        if nid is not None and nid != node_id and (nid, name, local) not in out:
            out.append((nid, name, local))

    for stmt in ast.walk(tree):
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


_DECL_NAME = re.compile(
    r"\b(?:function\*?|func|fn|class|interface|type|enum|struct|trait|const|let|var|record)\s+"
    r"(?:\([^)]*\)\s*)?([A-Za-z_$][\w$]*)"
)
_CALLABLE_NAME = re.compile(r"([A-Za-z_$][\w$]*)\s*(?:<[^()]*>)?\s*\(")


def export_signature_map(exports: list[str]) -> dict[str, str]:
    """Export name -> signature for a TS / Go / Rust / Java module's `exports`
    (`function add(a: number): number`, `func (r *T) Close() error { ... }`,
    `pub fn add(..)`, `Lib.public static int add(int a)`): the declared name
    after its keyword (a Go receiver skipped), else the identifier before the
    parameter list. A `Class.` prefix is kept (`Lib.add`). A signature with no
    recognisable name maps under "*", which callers treat as touching every
    importer."""
    out: dict[str, str] = {}
    for sig in exports:
        owner, rest = "", sig
        m = re.match(r"([A-Za-z_$][\w$]*)\.(?=\S)", sig)
        if m and not re.match(r"(?:pub|public|export)\b", sig):
            owner, rest = m.group(1) + ".", sig[m.end():]
        head = rest.split("{")[0]
        name_m = _DECL_NAME.search(head) or _CALLABLE_NAME.search(head)
        name = owner + name_m.group(1) if name_m and not re.search(r"\bdefault\b", head) else "*"
        out[name] = sig if name not in out else out[name] + " | " + sig  # overloads
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


CALLEE_TOKEN_BUDGET = 1000  # verbatim same-file callee bodies a focused checkout may add


def callee_closure(tree: ast.Module, focus: list[str], source: str | None = None,
                   budget: int = CALLEE_TOKEN_BUDGET) -> tuple[list[str], list[str]]:
    """Same-file functions and methods the focused symbols call, transitively:
    `name(...)` resolves to a top-level def; `self.m(...)` / `cls.m(...)` to a
    method of the class the calling method lives in; `Class.m(...)` to that
    class's method. Receivers the AST cannot pin down (`cart.total()`) are not
    guessed. Breadth-first from the focus, so the nearest helpers come first,
    and within one call depth the smallest first (small helpers are where
    business rules hide; the budget buys the most of them); a visited set
    makes recursion and call cycles terminate. With `source`, callees whose
    bodies would push the total past `budget` tokens are left out — returned
    second so the frame can name them — but still followed: what they call is
    part of the cone too, expanded when it fits and named when it does not, so
    a helper behind the budget wall never hides the rest of the chain.
    Returns (expanded, over_budget), both sorted."""
    import heapq

    from . import _tokens

    funcs = {s.name for s in tree.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))}
    methods = {
        s.name: {m.name for m in s.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for s in tree.body if isinstance(s, ast.ClassDef)
    }
    lines = source.splitlines(keepends=True) if source is not None else None

    def cost_of(group: list[ast.stmt]) -> int:
        if lines is None:
            return 0
        start, end = _group_span(lines, group)
        return _tokens.count("".join(lines[start - 1:end]))

    focus_set = set(focus)
    covered = {f for f in focus if "." not in f}  # a focused class already shows every method
    seen: set[str] = set(focus)
    heap: list[tuple[int, int, str]] = [(0, 0, f) for f in focus]
    heapq.heapify(heap)
    expanded: list[str] = []
    skipped: list[str] = []
    spent = 0
    while heap:
        depth, cost, sym = heapq.heappop(heap)
        _body, group = _resolve_symbol(tree, sym)
        if not group:
            continue
        if sym not in focus_set:
            if lines is not None and spent + cost > budget:
                skipped.append(sym)  # named, not expanded — and still walked below
            else:
                spent += cost
                expanded.append(sym)
        owner_default = sym.split(".")[0] if "." in sym else None
        targets: list[str] = []
        if owner_default is not None and owner_default not in covered:
            # A method's class state: `__init__` / `__post_init__` declare the
            # `self.<attr>` it reads, and the class's own same-file decorators wrap it.
            targets += [f"{owner_default}.{m}" for m in _STATE_METHODS if m in methods.get(owner_default, ())]
            owner_cls = next((s for s in tree.body if isinstance(s, ast.ClassDef) and s.name == owner_default), None)
            if owner_cls is not None:
                targets += [d.id for d in owner_cls.decorator_list if isinstance(d, ast.Name) and d.id in funcs]
        for node in group:
            owner = node.name if isinstance(node, ast.ClassDef) else owner_default
            for sub in ast.walk(node):
                # A bare `@decorator` is an ast.Name, not a call: follow it too.
                targets += [d.id for d in getattr(sub, "decorator_list", ())
                            if isinstance(d, ast.Name) and d.id in funcs]
                if not isinstance(sub, ast.Call):
                    continue
                fn = sub.func
                if isinstance(fn, ast.Name) and fn.id in funcs:
                    targets.append(fn.id)
                elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                    recv = fn.value.id
                    cls = owner if recv in ("self", "cls") else recv
                    if cls in methods and fn.attr in methods[cls] and (recv in ("self", "cls") or recv in methods):
                        targets.append(f"{cls}.{fn.attr}")
        for target in targets:
            if target in seen or target.split(".")[0] in covered:
                continue
            seen.add(target)
            callee_group = _resolve_symbol(tree, target)[1]
            if callee_group:
                heapq.heappush(heap, (depth + 1, cost_of(callee_group), target))
    return sorted(expanded), sorted(skipped)


_STATE_METHODS = ("__init__", "__post_init__")
CONST_TOKEN_BUDGET = 600  # verbatim module-level constants a focused checkout may add


def _bound_names(stmt: ast.stmt) -> set[str]:
    """Plain names an Assign / AnnAssign binds (tuple targets unpacked)."""
    targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
    return {n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)}


def _loads(nodes) -> set[str]:
    return {n.id for node in nodes for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def cone_constants(tree: ast.Module, cone: list[str], source: str | None = None,
                   budget: int = CONST_TOKEN_BUDGET) -> tuple[list[str], list[str]]:
    """Module-level constants (`ast.Assign` / `ast.AnnAssign`) the causal cone
    reads by bare name — the focused symbols plus their expanded callees, and the
    class-level attributes of a focused method's class — followed transitively
    through constants built from other constants. With `source`, a constant whose
    statement would push the total past `budget` tokens stays folded.
    Returns (verbatim, over_budget) bound names, both sorted."""
    from . import _tokens

    read: set[str] = set()
    for sym in cone:
        read |= _loads(_resolve_symbol(tree, sym)[1])
        if "." in sym:
            owner = next((s for s in tree.body if isinstance(s, ast.ClassDef) and s.name == sym.split(".")[0]), None)
            if owner is not None:
                read |= _loads(s for s in owner.body if isinstance(s, (ast.Assign, ast.AnnAssign)))
    lines = source.splitlines(keepends=True) if source is not None else None
    assigns = [s for s in tree.body if isinstance(s, (ast.Assign, ast.AnnAssign))]
    kept: set[str] = set()
    skipped: set[str] = set()
    done: set[int] = set()
    spent = 0
    changed = True
    while changed:
        changed = False
        for i, stmt in enumerate(assigns):
            names = _bound_names(stmt)
            if i in done or not names & read:
                continue
            done.add(i)
            cost = _tokens.count(_segment(lines, stmt)) if lines is not None else 0
            if lines is not None and spent + cost > budget:
                skipped |= names
                continue
            spent += cost
            kept |= names
            read |= _loads([stmt.value] if stmt.value is not None else [])
            changed = True
    return sorted(kept), sorted(skipped - kept)


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
    if mod is None:
        try:
            return present_structural_guards(ast.parse(source))
        except SyntaxError:
            return set()
    return set(mod.present_guards(source)) if hasattr(mod, "present_guards") else set()
