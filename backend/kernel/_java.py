"""Java OKF support. Private to StateKernel, zero dependencies, deterministic.

Top-level `class` / `interface` / `enum` / `record` / `@interface` with their
members (methods and constructors addressable as `Class.method`, fields,
one level of nested types); annotations travel with their declaration;
`import a.b.C;` / `import a.b.*;` become edges against the tracked files;
exported = `public`. Gate C mines leading `if (cond) { throw new X(…); }`
guards as structural `guard:` invariants. Text blocks (`\"\"\"`) are masked.
Same-package references need no import in Java, so the type name of another
tracked file in this file's directory, used as an identifier here, is an edge too.
"""
from __future__ import annotations

import re

from . import _cstyle as C

FENCE = "java"
SUFFIXES = (".java",)
EXCLUDED_DIRS = frozenset({"build", "target", ".gradle"})
SPEC = C.Spec("java", FENCE, text_blocks=True, ops=("...", "::", "->", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/="))
RULE = C.GuardRule(paren_condition=True, effects=(("throw", ""),))
_MODIFIERS = frozenset({"public", "protected", "private", "static", "final", "abstract", "sealed", "non-sealed", "strictfp",
                        "synchronized", "native", "default", "transient", "volatile"})
_TYPE_KINDS = frozenset({"class", "interface", "enum", "record"})
_STMT_WORDS = frozenset({"if", "for", "while", "switch", "catch", "return", "new", "synchronized", "try", "do", "else", "throw", "super", "this"})


def looks_like(source: str) -> bool:
    return bool(re.search(r"^\s*(package\s+[\w.]+|import\s+(static\s+)?[\w.*]+)\s*;", source, re.M)
                or re.search(r"\b(public|private|protected)\s+(static\s+|final\s+|abstract\s+)*(class|interface|enum|record)\s+\w+", source))


def syntax_problem(source: str) -> str | None:
    return C.syntax_problem(source, SPEC)


def _annotations(src: str, sig: list[C.Tok], i: int, depth: int) -> tuple[list[str], int]:
    attrs: list[str] = []
    j = i
    while j < len(sig) and sig[j].kind == "punct" and sig[j].text == "@" and sig[j].depth == depth:
        if j + 1 < len(sig) and sig[j + 1].text == "interface":
            break  # annotation type declaration
        k = j + 1
        if k < len(sig) and sig[k].kind == "id":
            k += 1
            while k + 1 < len(sig) and sig[k].text == "." and sig[k + 1].kind == "id":  # dotted name only
                k += 2
        if k < len(sig) and sig[k].text == "(" and sig[k].depth == depth:
            k += 1
            while k < len(sig) and not (sig[k].depth == depth + 1 and sig[k].text == ")"):
                k += 1
            k += 1
        attrs.append(C.squash(src[sig[j].start: sig[k - 1].end]))
        j = k
    return attrs, j


def _decl(src: str, sig: list[C.Tok], i: int, depth: int, owner: str | None, enum_body: bool) -> tuple[C.Decl | None, int]:
    attrs, j = _annotations(src, sig, i, depth)
    k = j
    exported = False
    while k < len(sig) and sig[k].kind == "id" and sig[k].text in _MODIFIERS and sig[k].depth == depth:
        exported = exported or sig[k].text == "public"
        k += 1
    end_idx = C.statement_end(sig, j, depth)  # from the first modifier: an annotation line is not a statement end
    if k >= len(sig) or sig[k].depth != depth:
        return None, end_idx
    is_annotation_type = sig[k].text == "@" and k + 1 < len(sig) and sig[k + 1].text == "interface"
    if is_annotation_type:
        k += 1
    kind = sig[k].text if sig[k].kind == "id" and sig[k].text in _TYPE_KINDS else None
    open_idx, close_idx = C.body_bounds(sig, i, end_idx)
    body_open = sig[open_idx].start if open_idx is not None else None
    body_close = sig[close_idx].start if close_idx is not None else None
    name = ""
    is_fn = False
    if kind is not None:
        name = sig[k + 1].text if k + 1 < len(sig) and sig[k + 1].kind == "id" else ""
        kind = "annotation" if is_annotation_type else kind
    elif owner is not None and not enum_body:
        # a member: method `Type name(` / constructor `Name(` / field `Type name =`
        limit = open_idx if open_idx is not None else end_idx
        paren = next((q for q in range(k, limit + 1) if sig[q].depth == depth and sig[q].text == "("), None)
        eq = next((q for q in range(k, limit + 1) if sig[q].depth == depth and sig[q].text == "="), None)
        if paren is not None and (eq is None or paren < eq) and sig[paren - 1].kind == "id" and sig[paren - 1].text not in _STMT_WORDS:
            name, kind, is_fn = sig[paren - 1].text, "method", True
        elif paren is None or (eq is not None and eq < paren):
            stop = eq if eq is not None else end_idx
            ids = [t for t in sig[k:stop] if t.kind == "id" and t.depth == depth]
            if ids:
                name, kind = ids[-1].text, "field"
    if not name:
        return None, end_idx
    header = C.squash(src[sig[j].start: body_open]) if body_open is not None else C.squash(src[sig[j].start: sig[end_idx].end])
    if kind == "field" and len(header) > 80:
        eq_pos = header.find("=")
        if eq_pos > 0:
            header = header[: eq_pos + 1] + " ..."
    d = C.Decl(name, kind, exported, sig[i].start if attrs else C.leading_start(src, sig[j].start), sig[end_idx].end, header, attrs,
               body_open, body_close, [], owner, is_fn, C.indent_of(src, sig[i].start))
    if kind in _TYPE_KINDS | {"annotation"} and open_idx is not None and close_idx is not None and depth == 0:
        q = open_idx + 1
        seen_semicolon = kind != "enum"
        while q < close_idx:
            t = sig[q]
            if t.depth != depth + 1 or (t.kind == "punct" and t.text in (";", ",")):
                if t.depth == depth + 1 and t.text == ";":
                    seen_semicolon = True
                q += 1
                continue
            member, e = _decl(src, sig, q, depth + 1, name, not seen_semicolon)
            if member is not None:
                d.members.append(member)
            q = e + 1
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
        if t.kind == "id" and t.text in ("package", "import"):
            end_idx = C.statement_end(sig, i, 0)
            stmts.append(C.Stmt(t.text, t.start, sig[end_idx].end, src[t.start: sig[end_idx].end]))
            i = end_idx + 1
            continue
        d, end_idx = _decl(src, sig, i, 0, None, False)
        if d is None:
            stmts.append(C.Stmt("other", t.start, sig[end_idx].end, src[t.start: sig[end_idx].end]))
        else:
            decls.append(d)
        i = end_idx + 1
    return decls, stmts


def _stmt_line(s: C.Stmt) -> str:
    if s.kind in ("package", "import"):
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


_IMPORT_RE = re.compile(r"^import\s+(?P<static>static\s+)?(?P<path>[\w.]+?)(?:\.(?P<last>\w+|\*))\s*;")


def resolve_imports(node_id: str, path: str, source: str, modules: dict[str, str]) -> dict[str, set]:
    """`import a.b.C;` -> the file whose importable name ends with `a.b.C` (name C);
    `import a.b.*;` -> every file under a package ending with `a.b` (module object)."""
    out: dict[str, set] = {}
    _, stmts = parse(source)
    for s in stmts:
        if s.kind != "import":
            continue
        m = _IMPORT_RE.match(C.squash(s.text))
        if not m:
            continue
        pkg, last = m.group("path"), m.group("last")
        if last == "*":
            for key, nid in modules.items():
                key_dir = key.rsplit(".", 1)[0] if "." in key else ""
                if key_dir and (key_dir == pkg or key_dir.endswith("." + pkg)) and nid != node_id:
                    out.setdefault(nid, set()).add(None)
            continue
        if m.group("static"):
            nid = C.match_module(modules, pkg, node_id)
            if nid:
                out.setdefault(nid, set()).add(None)
            continue
        nid = C.match_module(modules, f"{pkg}.{last}", node_id)
        if nid:
            out.setdefault(nid, set()).add(last)
    # Same-package siblings: `Account` used inside `Ledger.java` next to
    # `Account.java` is a dependency on the name `Account`, import or not.
    parts = path.replace("\\", "/").split("/")
    stem, directory = parts[-1].rsplit(".", 1)[0], ".".join(parts[:-1])
    ids = {t.text for t in C.tokenize(source, SPEC) if t.kind == "id"}
    for key, nid in modules.items():
        other = key.rsplit(".", 1)[-1]
        if nid != node_id and other != stem and other in ids and ".".join(key.split(".")[:-1]) == directory:
            out.setdefault(nid, set()).add(other)
    return out


def mine_guards(src: str) -> list[str]:
    decls, _ = parse(src)
    sig = [t for t in C.tokenize(src, SPEC) if t.kind != "comment"]
    return C.mine_guards(sig, decls, RULE, leading_only=True)


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
             resolve_imports_fn=resolve_imports, lang="Java")
