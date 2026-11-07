"""Go OKF support. Private to StateKernel, zero dependencies, deterministic.

Top-level `func`, methods (`func (r T) M` — addressable as `T.M`), `type`,
`const` / `var` (grouped or not) and `//go:` directives; import edges by
package path suffix against the tracked files; exported = capitalised name;
Gate C mines leading `if cond { return … }` / `if cond { panic(…) }` guards as
structural `guard:` invariants. Same-package references without an import
are not edges (documented limitation).
"""
from __future__ import annotations

import re

from . import _cstyle as C

FENCE = "go"
SUFFIXES = (".go",)
EXCLUDED_DIRS = frozenset({"vendor", "testdata"})
SPEC = C.Spec("go", FENCE, backtick_raw=True)
RULE = C.GuardRule(paren_condition=False, effects=(("return", "returns"), ("panic", "panics"), ("log . Fatal", "fatal"), ("log . Fatalf", "fatal")))
_KINDS = frozenset({"func", "type", "const", "var", "import", "package"})


def looks_like(source: str) -> bool:
    return bool(re.search(r"^\s*package\s+\w+\s*$", source, re.M)) and ("func " in source or "import" in source)


def syntax_problem(source: str) -> str | None:
    return C.syntax_problem(source, SPEC)


def _directives(src: str, start: int) -> list[str]:
    lines = src[:start].rstrip("\n").split("\n")
    out: list[str] = []
    for ln in reversed(lines):
        s = ln.strip()
        if s.startswith("//go:"):
            out.insert(0, s)
        elif s.startswith("//"):
            continue
        else:
            break
    return out


def parse(src: str) -> tuple[list[C.Decl], list[C.Stmt]]:
    toks = C.tokenize(src, SPEC)
    sig = [t for t in toks if t.kind != "comment"]
    decls: list[C.Decl] = []
    stmts: list[C.Stmt] = []
    methods: list[C.Decl] = []
    i, n = 0, len(sig)
    while i < n:
        t = sig[i]
        if t.depth != 0 or (t.kind == "punct" and t.text == ";"):
            i += 1
            continue
        end_idx = C.statement_end(sig, i, 0)
        end = sig[end_idx].end
        text = src[t.start:end]
        if t.kind == "id" and t.text in ("package", "import"):
            stmts.append(C.Stmt(t.text, t.start, end, text))
            i = end_idx + 1
            continue
        if t.kind == "id" and t.text == "func":
            d = _func(src, sig, i, end_idx)
            if d.owner:
                methods.append(d)
            else:
                decls.append(d)
            i = end_idx + 1
            continue
        if t.kind == "id" and t.text in ("type", "const", "var"):
            group = i + 1 < n and sig[i + 1].kind == "punct" and sig[i + 1].text == "("
            if group:
                decls.extend(_group(src, sig, i, end_idx, t.text))
            else:
                d = _simple(src, sig, i, end_idx, t.text)
                if d is not None:
                    decls.append(d)
            i = end_idx + 1
            continue
        stmts.append(C.Stmt("other", t.start, end, text))
        i = end_idx + 1
    by_name = {d.name: d for d in decls if d.kind in ("type",)}
    for m in methods:
        owner = by_name.get(m.owner or "")
        if owner is not None:
            owner.members.append(m)
        else:
            decls.append(m)
    decls.sort(key=lambda d: d.start)
    return decls, stmts


def _func(src: str, sig: list[C.Tok], i: int, end_idx: int) -> C.Decl:
    j = i + 1
    owner = None
    if j < len(sig) and sig[j].kind == "punct" and sig[j].text == "(":
        k = j + 1
        recv: list[str] = []
        while k < len(sig) and not (sig[k].depth == 1 and sig[k].kind == "punct" and sig[k].text == ")"):
            if sig[k].kind == "id":
                recv.append(sig[k].text)
            k += 1
        owner = recv[-1] if recv else None
        j = k + 1
    name = sig[j].text if j < len(sig) and sig[j].kind == "id" else ""
    open_idx, close_idx = C.body_bounds(sig, i, end_idx)
    body_open = sig[open_idx].start if open_idx is not None else None
    body_close = sig[close_idx].start if close_idx is not None else None
    header = C.squash(src[sig[i].start: body_open]) if body_open is not None else C.squash(src[sig[i].start: sig[end_idx].end])
    start = C.leading_start(src, sig[i].start)
    exported = bool(name) and name[0].isupper()
    return C.Decl(name, "method" if owner else "func", exported, start, sig[end_idx].end, header, _directives(src, sig[i].start),
                  body_open, body_close, [], owner, True, C.indent_of(src, sig[i].start))


def _simple(src: str, sig: list[C.Tok], i: int, end_idx: int, kind: str) -> C.Decl | None:
    j = i + 1
    if j >= len(sig) or sig[j].kind != "id":
        return None
    name = sig[j].text
    open_idx, close_idx = C.body_bounds(sig, i, end_idx)
    body_open = sig[open_idx].start if open_idx is not None else None
    body_close = sig[close_idx].start if close_idx is not None else None
    header = C.squash(src[sig[i].start: body_open]) if body_open is not None else C.squash(src[sig[i].start: sig[end_idx].end])
    if body_open is None and len(header) > 80:
        eq = header.find("=")
        if eq > 0:
            header = header[: eq + 1] + " ..."
    return C.Decl(name, kind, name[0].isupper(), C.leading_start(src, sig[i].start), sig[end_idx].end, header,
                  _directives(src, sig[i].start), body_open, body_close, [], None, False, "")


def _group(src: str, sig: list[C.Tok], i: int, end_idx: int, kind: str) -> list[C.Decl]:
    """`type ( … )`, `const ( … )`, `var ( … )`: one declaration per entry."""
    out: list[C.Decl] = []
    j = i + 2
    while j < end_idx:
        t = sig[j]
        if t.depth != 1 or t.kind != "id":
            j += 1
            continue
        e = C.statement_end(sig, j, 1)
        name = t.text
        open_idx, close_idx = C.body_bounds(sig, j, e)
        body_open = sig[open_idx].start if open_idx is not None else None
        body_close = sig[close_idx].start if close_idx is not None else None
        header = f"{kind} " + (C.squash(src[t.start: body_open]) if body_open is not None else C.squash(src[t.start: sig[e].end]))
        out.append(C.Decl(name, kind, name[0].isupper(), C.leading_start(src, t.start), sig[e].end, header, [], body_open, body_close,
                          [], None, False, C.indent_of(src, t.start)))
        j = e + 1
    return out


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


_IMPORT_SPEC = re.compile(r'(?:(?P<alias>[\w.]+)\s+)?"(?P<spec>[^"]+)"')


def resolve_imports(node_id: str, path: str, source: str, modules: dict[str, str]) -> dict[str, set]:
    """Imported package path -> the tracked files of the package whose directory
    is a suffix of that path (`example.com/mod/pkg/util` -> `pkg/util/*.go`);
    names = the identifiers read off the package alias (`util.Normalize`)."""
    out: dict[str, set] = {}
    _, stmts = parse(source)
    for s in stmts:
        if s.kind != "import":
            continue
        for m in _IMPORT_SPEC.finditer(s.text):
            spec = m.group("spec")
            alias = m.group("alias")
            if alias in (None, "import"):  # `import "x/pkg"`: the keyword is not an alias
                alias = spec.rsplit("/", 1)[-1]
            dotted = spec.replace("/", ".")
            best_len = -1
            targets: list[str] = []
            for key, nid in modules.items():
                key_dir = key.rsplit(".", 1)[0] if "." in key else ""
                if key_dir and (dotted == key_dir or dotted.endswith("." + key_dir)) and nid != node_id:
                    if len(key_dir) > best_len:
                        best_len, targets = len(key_dir), [nid]
                    elif len(key_dir) == best_len and nid not in targets:
                        targets.append(nid)
            if not targets:
                continue
            used = set(re.findall(rf"\b{re.escape(alias)}\.([A-Z]\w*)", source))
            for nid in targets:
                out.setdefault(nid, set()).update(used or {None})
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
             resolve_imports_fn=resolve_imports, lang="Go")
