"""Rust OKF support. Private to StateKernel, zero dependencies, deterministic.

Items: `fn`, `struct`, `enum`, `trait`, `impl` blocks (methods addressable as
`Type.method`, trait-impl methods count as exported), `type`, `const`,
`static`; `#[…]` attributes travel with their item; `use crate::…` /
`use super::…` / `mod x;` become edges; exported = `pub`. Gate C mines leading
`if cond { panic!(…) }` / `if cond { return Err(…) }` guards as structural
`guard:` invariants. Lifetimes (`'a`) are told apart from char literals
(`'{'`), raw strings (`r#"…"#`) are masked. Macros (`macro_rules!`) and
inline `mod x { … }` bodies are opaque statements (documented limitation).
"""
from __future__ import annotations

import posixpath
import re

from . import _cstyle as C

FENCE = "rust"
SUFFIXES = (".rs",)
EXCLUDED_DIRS = frozenset({"target"})
SPEC = C.Spec("rust", FENCE, lifetimes=True, rust_raw=True)
RULE = C.GuardRule(paren_condition=False, effects=(("panic !", "panics"), ("return Err", "returns Err"), ("return", "returns"),
                                                   ("bail !", "bails"), ("unreachable !", "panics"), ("todo !", "panics")),
                   assert_macros=("assert", "assert_eq", "assert_ne", "debug_assert", "debug_assert_eq", "debug_assert_ne"))
_MODIFIERS = frozenset({"pub", "async", "unsafe", "const", "extern", "default"})
_KINDS = frozenset({"fn", "struct", "enum", "trait", "impl", "type", "const", "static", "union", "mod"})


def looks_like(source: str) -> bool:
    if re.search(r"^\s*package\s+\w+\s*$", source, re.M):
        return False
    return bool(re.search(r"\bfn\s+\w+\s*[<(]|^\s*(pub(\([^)]*\))?\s+)?(struct|enum|trait|impl|mod|use)\b", source, re.M)) and (
        "::" in source or "#[" in source or "->" in source or "let " in source)


def syntax_problem(source: str) -> str | None:
    return C.syntax_problem(source, SPEC)


def _skip_generics(sig: list[C.Tok], k: int) -> int:
    """Index after a `<…>` generic list starting at sig[k] (balanced on < >)."""
    if k < len(sig) and sig[k].kind == "punct" and sig[k].text == "<":
        depth = 0
        while k < len(sig):
            if sig[k].text == "<":
                depth += 1
            elif sig[k].text == ">":
                depth -= 1
                if depth == 0:
                    return k + 1
            elif sig[k].text == ">>":
                depth -= 2
                if depth <= 0:
                    return k + 1
            k += 1
    return k


def _item(src: str, sig: list[C.Tok], i: int, depth: int, owner: str | None, trait_impl: bool) -> tuple[C.Decl | None, int]:
    """One item starting at sig[i] (attributes included). Returns (decl, end_idx)."""
    j = i
    attrs: list[str] = []
    while j < len(sig) and sig[j].kind == "punct" and sig[j].text == "#" and sig[j].depth == depth:
        k = j + 1
        if k < len(sig) and sig[k].text == "!":
            k += 1
        if k < len(sig) and sig[k].text == "[":
            close = k + 1
            while close < len(sig) and not (sig[close].depth == depth + 1 and sig[close].kind == "punct" and sig[close].text == "]"):
                close += 1
            attrs.append(C.squash(src[sig[j].start: sig[close].end]))
            j = close + 1
        else:
            break
    k = j
    exported = False
    while k < len(sig) and sig[k].kind == "id" and sig[k].text in _MODIFIERS and sig[k].depth == depth:
        if sig[k].text == "const" and not (k + 1 < len(sig) and sig[k + 1].text in ("fn", "unsafe", "extern")):
            break  # `const NAME: T = …;` is an item (see _KINDS), not the `const fn` modifier
        if sig[k].text == "pub":
            exported = True
            if k + 1 < len(sig) and sig[k + 1].text == "(":
                k += 1
                while k < len(sig) and not (sig[k].depth == depth + 1 and sig[k].text == ")"):
                    k += 1
        if sig[k].text == "extern" and k + 1 < len(sig) and sig[k + 1].kind == "string":
            k += 1
        k += 1
    if k >= len(sig) or sig[k].kind != "id" or sig[k].text not in _KINDS or sig[k].depth != depth:
        return None, C.statement_end(sig, j, depth)
    kind = sig[k].text
    if kind == "const" and k + 1 < len(sig) and sig[k + 1].text == "fn":
        k += 1
        kind = "fn"
    end_idx = C.statement_end(sig, j, depth)  # from the first modifier: an attribute line is not a statement end
    name = ""
    if kind == "impl":
        m = _skip_generics(sig, k + 1)
        first = sig[m].text if m < len(sig) and sig[m].kind == "id" else ""
        q = m
        while q < end_idx and not (sig[q].depth == depth and sig[q].text == "{"):
            if sig[q].kind == "id" and sig[q].text == "for" and sig[q].depth == depth:
                q += 1
                name = sig[q].text if sig[q].kind == "id" else name
                trait_impl_here = True
                break
            q += 1
        else:
            trait_impl_here = False
        if not name:
            name = first
        if any(t.kind == "id" and t.text == "for" and t.depth == depth for t in sig[k:end_idx]):
            trait_impl_here = True
    else:
        m = k + 1
        name = sig[m].text if m < len(sig) and sig[m].kind == "id" else ""
        trait_impl_here = False
    open_idx, close_idx = C.body_bounds(sig, i, end_idx)
    body_open = sig[open_idx].start if open_idx is not None else None
    body_close = sig[close_idx].start if close_idx is not None else None
    header = C.squash(src[sig[j].start: body_open]) if body_open is not None else C.squash(src[sig[j].start: sig[end_idx].end])
    if body_open is None and len(header) > 80 and kind in ("const", "static", "type"):
        eq = header.find("=")
        if eq > 0:
            header = header[: eq + 1] + " ..."
    is_fn = kind == "fn"
    d = C.Decl(name, "method" if (is_fn and owner) else kind, exported or trait_impl, C.leading_start(src, sig[j].start) if not attrs else sig[i].start,
               sig[end_idx].end, header, attrs, body_open, body_close, [], owner, is_fn, C.indent_of(src, sig[i].start))
    if kind in ("impl", "trait") and open_idx is not None and close_idx is not None:
        member_owner = name
        q = open_idx + 1
        while q < close_idx:
            if sig[q].depth != depth + 1 or (sig[q].kind == "punct" and sig[q].text == ";"):
                q += 1
                continue
            member, e = _item(src, sig, q, depth + 1, member_owner, trait_impl_here and kind == "impl")
            if member is not None:
                d.members.append(member)
            q = e + 1
        if kind == "impl" and any(m.exported for m in d.members):
            d.exported = True  # an impl block is part of the public surface when it holds pub methods
    return d, end_idx


def parse(src: str) -> tuple[list[C.Decl], list[C.Stmt]]:
    toks = C.tokenize(src, SPEC)
    sig = [t for t in toks if t.kind != "comment"]
    decls: list[C.Decl] = []
    stmts: list[C.Stmt] = []
    i, n = 0, len(sig)
    while i < n:
        t = sig[i]
        if t.depth != 0 or (t.kind == "punct" and t.text == ";"):
            i += 1
            continue
        if t.kind == "id" and t.text in ("use", "mod", "extern", "pub"):
            end_idx = C.statement_end(sig, i, 0)
            text = C.squash(src[t.start: sig[end_idx].end])
            if _USE_RE.match(text) or _MOD_RE.match(text) or re.match(r"(?:pub(?:\([^)]*\))?\s+)?extern\s+crate\b", text):
                stmts.append(C.Stmt("import", t.start, sig[end_idx].end, src[t.start: sig[end_idx].end]))
                i = end_idx + 1
                continue
        d, end_idx = _item(src, sig, i, 0, None, False)
        if d is None:
            stmts.append(C.Stmt("other", t.start, sig[end_idx].end, src[t.start: sig[end_idx].end]))
        else:
            decls.append(d)
        i = end_idx + 1
    return decls, stmts


def _stmt_line(s: C.Stmt) -> str:
    if s.kind == "import":
        return s.text.rstrip() + "\n"
    return "// " + C.squash(s.text)[:60] + " …\n"


def _member_line(m: C.Decl) -> str:
    return "".join(f"{m.indent}{a}\n" for a in m.attrs) + f"{m.indent}{C.header_line(m)}\n"


def skeleton(src: str, focus: list[str]) -> str:
    return C.skeleton(src, focus, parse, _stmt_line, _member_line)


def interface_skeleton(src: str) -> str:
    return C.interface_skeleton(parse(src)[0], _member_line)


def symbol_names(src: str) -> list[str]:
    return C.symbol_names(parse(src)[0])


def statement_count(src: str) -> int:
    return C.statement_count(*parse(src))


def bound_names(src: str) -> set[str]:
    return C.bound_names(parse(src)[0])


def apply_patch(src: str, patch: list[dict]) -> str:
    return C.apply_patch(src, patch, parse)


_USE_RE = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?use\s+(?P<path>[\w:]+?)(?:::\{(?P<group>[^}]*)\}|::(?P<last>\w+|\*))?\s*;")
_MOD_RE = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;")


def resolve_imports(node_id: str, path: str, source: str, modules: dict[str, str]) -> dict[str, set]:
    """`use crate::a::b::{X, Y}` -> the file whose importable name ends with `a.b`
    (names X, Y); `use super::x::Z` relative to the parent directory; `mod x;` ->
    `x.rs` or `x/mod.rs` next to this file (or under `<stem>/` for a non-root file)."""
    out: dict[str, set] = {}
    p = path.replace("\\", "/")
    directory = posixpath.dirname(p)
    stem = posixpath.basename(p).rsplit(".", 1)[0]
    own_dir = directory if stem in ("lib", "main", "mod") else (posixpath.join(directory, stem) if directory else stem)

    def resolve_dotted(dotted: str) -> str | None:
        return C.match_module(modules, dotted, node_id) or C.match_module(modules, dotted + ".mod", node_id)

    _, stmts = parse(source)
    for s in stmts:
        if s.kind != "import":
            continue
        text = C.squash(s.text)
        m = _MOD_RE.match(text)
        if m:
            for cand in (posixpath.join(own_dir, m.group(1)), posixpath.join(own_dir, m.group(1), "mod")):
                nid = C.match_module(modules, cand.replace("/", "."), node_id)
                if nid:
                    out.setdefault(nid, set()).add(None)
                    break
            continue
        m = _USE_RE.match(text)
        if not m:
            continue
        segs = m.group("path").split("::")
        names: set = set()
        if m.group("group"):
            for part in m.group("group").split(","):
                bits = part.strip().split()
                if bits:
                    names.add(bits[0] if bits[0] != "self" else None)
        elif m.group("last"):
            names.add(None if m.group("last") == "*" else m.group("last"))
        else:
            names.add(segs[-1])
            segs = segs[:-1]
        if not segs:
            continue
        if segs[0] == "crate":
            dotted = ".".join(segs[1:])
            nid = resolve_dotted(dotted) if dotted else None
        elif segs[0] == "super":
            parent = posixpath.dirname(directory) if stem in ("lib", "main", "mod") else directory
            rest = [x for x in segs[1:] if x != "super"]
            dotted = ".".join(([parent.replace("/", ".")] if parent else []) + rest)
            nid = resolve_dotted(dotted) if rest else None
        elif segs[0] == "self":
            dotted = ".".join(([own_dir.replace("/", ".")] if own_dir else []) + segs[1:])
            nid = resolve_dotted(dotted)
        else:
            nid = resolve_dotted(".".join(segs))
        if nid is not None:
            out.setdefault(nid, set()).update(names)
    return out


def mine_guards(src: str) -> list[str]:
    decls, _ = parse(src)
    sig = [t for t in C.tokenize(src, SPEC) if t.kind != "comment"]
    return C.mine_guards(sig, decls, RULE, leading_only=False, mining=True)


def present_guards(src: str) -> set[str]:
    decls, _ = parse(src)
    sig = [t for t in C.tokenize(src, SPEC) if t.kind != "comment"]
    return set(C.mine_guards(sig, decls, RULE, leading_only=False))


def analyze(node_id: str, path: str, source: str, project_modules: dict[str, str] | set[str]):
    from . import _okf

    modules = project_modules if isinstance(project_modules, dict) else {m: m for m in project_modules}
    decls, _ = parse(source)
    deps = sorted(resolve_imports(node_id, path, source, modules))
    return C.module_info(_okf, node_id, path, source, deps, decls, mine_guards(source))


def gate_a(node_id: str, locked: bool, source: str, nodes) -> None:
    C.gate_a(node_id, locked, source, nodes, syntax_problem_fn=syntax_problem, bound_names_fn=bound_names,
             resolve_imports_fn=resolve_imports, lang="Rust")
