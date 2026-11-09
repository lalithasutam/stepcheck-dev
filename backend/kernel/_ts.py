"""TypeScript / JavaScript OKF support. Private to StateKernel, zero dependencies.

`_okf` and `_gates` dispatch here for `.ts` / `.tsx` / `.js` / `.jsx` modules.
A conservative lexer tracks strings, template literals (with `${}` nesting),
comments, regex literals and `{}()[]` depth; top-level declarations are read
at depth 0. Deterministic by construction: no parser state survives a call.
No invariants are mined or executed for these modules (Gate C is a no-op);
Gates A and B and the DSSE attestation work exactly as for Python.
"""
from __future__ import annotations

import ast
import posixpath
import re
from dataclasses import dataclass, field

SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
EXCLUDED_DIRS = frozenset({"node_modules", "dist", "build", "out", "coverage", ".git", ".stepcheck"})
_DECL_KINDS = ("function", "class", "interface", "type", "enum", "const", "let", "var", "namespace")
_BODY_KINDS = frozenset({"function", "class", "interface", "enum", "namespace"})
_MODIFIERS = frozenset({"export", "default", "declare", "abstract", "async"})
# `<` and `>` are left out on purpose: in JSX `</div>` the slash closes a tag.
_REGEX_AFTER_PUNCT = frozenset("(,=:[!&|?{};+-*%~^") | {"=>", "&&", "||", "??", "==", "===", "!=", "!=="}
_REGEX_AFTER_WORDS = frozenset({"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
                                "case", "do", "else", "yield", "await"})
_STRING_AFTER_WORDS = _REGEX_AFTER_WORDS | {"from", "import", "export", "default", "as", "require", "extends",
                                            "implements", "satisfies", "module", "declare"}
_CONTINUATION_START = frozenset({".", "?.", ",", ")", "]", "}", ":", "&&", "||", "??", "?", "=", "=>", "+", "-", "*", "/",
                                 "%", "<", ">", "==", "===", "!=", "!==", "<=", ">=", "&", "|", "^", "(", "[", "`"})
_CONTINUATION_START_WORDS = frozenset({"as", "extends", "implements", "else", "catch", "finally", "satisfies", "in", "of", "instanceof"})
_CONTINUATION_END = frozenset({".", "?.", ",", "(", "[", "{", "=", "=>", ":", "?", "+", "-", "*", "/", "%", "<", ">",
                               "&&", "||", "??", "&", "|", "^", "==", "===", "!=", "!==", "<=", ">=", "..."})
_CONTINUATION_END_WORDS = frozenset({"return", "typeof", "new", "extends", "implements", "in", "of", "instanceof", "as", "case", "throw", "yield", "await"})
_OPS = ("...", "===", "!==", "=>", "?.", "??", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "**", "*=", "/=")


# ----------------------------------------------------------------- language


def is_ts_path(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    return p.endswith(SUFFIXES) and not p.endswith(".d.ts")


def looks_like_typescript(source: str) -> bool:
    """The language-agnostic entry points (`skeleton`, `apply_patch`, …) take a
    source without a path: a source Python cannot parse is TypeScript/JavaScript.
    A Python module that fails to parse never reaches them (Gate A rejects it)."""
    if not source.strip():
        return False
    try:
        ast.parse(source)
    except (SyntaxError, ValueError):
        return True
    return False


# --------------------------------------------------------------------- lexer


@dataclass(frozen=True)
class Tok:
    kind: str  # id | num | punct | string | template | regex | comment
    text: str
    start: int
    end: int
    line: int
    depth: int  # delimiter depth before this token


def _template_end(src: str, i: int) -> int:
    j, n = i + 1, len(src)
    while j < n:
        ch = src[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "`":
            return j + 1
        if src.startswith("${", j):
            j = _expr_end(src, j + 2)
            continue
        j += 1
    return n


def _expr_end(src: str, j: int) -> int:
    depth, n = 1, len(src)
    while j < n:
        ch = src[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "`":
            j = _template_end(src, j)
            continue
        if ch in "'\"":
            k = j + 1
            while k < n and src[k] != ch and src[k] != "\n":
                if src[k] == "\\":
                    k += 1
                k += 1
            j = k + 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return n


def _regex_end(src: str, i: int) -> int | None:
    j, n, in_class = i + 1, len(src), False
    while j < n:
        ch = src[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "\n":
            return None
        if in_class:
            if ch == "]":
                in_class = False
        elif ch == "[":
            in_class = True
        elif ch == "/":
            j += 1
            while j < n and (src[j].isalpha()):
                j += 1
            return j
        j += 1
    return None


def tokenize(src: str) -> list[Tok]:
    """Significant tokens with the delimiter depth in force before each one."""
    toks: list[Tok] = []
    i, n, line, depth = 0, len(src), 1, 0

    def prev_sig() -> Tok | None:
        for t in reversed(toks):
            if t.kind != "comment":
                return t
        return None

    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in " \t\r\f\v":
            i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            toks.append(Tok("comment", src[i:j], i, j, line, depth))
            i = j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            toks.append(Tok("comment", src[i:j], i, j, line, depth))
            line += src.count("\n", i, j)
            i = j
            continue
        if c in "'\"":
            p = prev_sig()
            # In JSX text an apostrophe follows a word or `>`; a real string follows
            # punctuation, a keyword, or the start of the file.
            if p is None or (p.kind == "punct" and p.text not in (">", ")", "]", "}")) or (p.kind == "id" and p.text in _STRING_AFTER_WORDS):
                j = i + 1
                while j < n and src[j] != c and src[j] != "\n":
                    if src[j] == "\\":
                        j += 1
                    j += 1
                j = min(j + 1, n)
                toks.append(Tok("string", src[i:j], i, j, line, depth))
                i = j
                continue
            i += 1
            continue
        if c == "`":
            j = _template_end(src, i)
            toks.append(Tok("template", src[i:j], i, j, line, depth))
            line += src.count("\n", i, j)
            i = j
            continue
        if c == "/":
            p = prev_sig()
            if p is None or (p.kind == "punct" and p.text in _REGEX_AFTER_PUNCT) or (p.kind == "id" and p.text in _REGEX_AFTER_WORDS):
                j = _regex_end(src, i)
                if j is not None:
                    toks.append(Tok("regex", src[i:j], i, j, line, depth))
                    i = j
                    continue
        if c.isalpha() or c in "_$":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            toks.append(Tok("id", src[i:j], i, j, line, depth))
            i = j
            continue
        if c.isdigit():
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            toks.append(Tok("num", src[i:j], i, j, line, depth))
            i = j
            continue
        for op in _OPS:
            if src.startswith(op, i):
                toks.append(Tok("punct", op, i, i + len(op), line, depth))
                i += len(op)
                break
        else:
            toks.append(Tok("punct", c, i, i + 1, line, depth))
            if c in "{([":
                depth += 1
            elif c in "})]":
                depth -= 1
            i += 1
    return toks


def syntax_problem(source: str) -> str | None:
    """Gate A's mechanical check for TypeScript: balanced delimiters, terminated
    strings, comments and template literals. None when the source is sound."""
    n = len(source)
    toks = tokenize(source)
    stack: list[Tok] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for t in toks:
        if t.kind == "comment" and t.text.startswith("/*") and not t.text.endswith("*/"):
            return f"unterminated block comment (line {t.line})"
        if t.kind == "template" and (t.end >= n and not t.text.endswith("`")):
            return f"unterminated template literal (line {t.line})"
        if t.kind == "string" and (len(t.text) < 2 or t.text[-1] != t.text[0]):
            return f"unterminated string literal (line {t.line})"
        if t.kind != "punct":
            continue
        if t.text in "{([":
            stack.append(t)
        elif t.text in "})]":
            if not stack or stack[-1].text != pairs[t.text]:
                return f"unexpected '{t.text}' (line {t.line})"
            stack.pop()
    if stack:
        t = stack[-1]
        return f"unclosed '{t.text}' opened at line {t.line}"
    return None


# ------------------------------------------------------------- declarations


@dataclass
class Decl:
    name: str
    kind: str  # function | class | interface | type | enum | const | let | var | namespace | method | field
    exported: bool
    is_default: bool
    start: int  # char offset of the first leading comment / decorator / modifier
    end: int  # char offset just past the statement
    header: str  # signature text (no body), single-spaced
    decorators: list[str] = field(default_factory=list)
    body_open: int | None = None  # char offset of the body `{`, if any
    members: list["Decl"] = field(default_factory=list)  # class members (methods, fields)
    owner: str | None = None  # the class a member belongs to
    indent: str = ""  # a member's own indentation

    @property
    def is_function(self) -> bool:
        return self.kind in ("function", "method") or "=>" in self.header

    @property
    def dotted(self) -> str:
        return f"{self.owner}.{self.name}" if self.owner else self.name

    @property
    def attrs(self) -> list[str]:
        return self.decorators


@dataclass
class Stmt:
    """A top-level statement that is not a declaration (imports, exports, calls)."""
    kind: str  # import | export | other
    start: int
    end: int
    text: str


def _statement_end(toks: list[Tok], i: int, body_kind: bool) -> int:
    """Index of the last token of the statement starting at toks[i]."""
    n = len(toks)
    last = i
    j = i
    while j < n:
        t = toks[j]
        if t.kind == "comment":
            j += 1
            continue
        if t.depth == 0 and t.kind == "punct" and t.text == ";" and j > i:
            return j
        if j > i and t.depth == 0:
            prev = toks[last]
            if t.line > prev.line:
                starts_cont = (t.kind == "punct" and t.text in _CONTINUATION_START) or (t.kind == "id" and t.text in _CONTINUATION_START_WORDS) or t.kind == "template"
                ends_cont = (prev.kind == "punct" and prev.text in _CONTINUATION_END) or (prev.kind == "id" and prev.text in _CONTINUATION_END_WORDS)
                closed_body = prev.kind == "punct" and prev.text == "}" and body_kind
                if closed_body or not (starts_cont or ends_cont):
                    return last
        last = j
        j += 1
    return last


def _leading_start(src: str, start: int) -> int:
    """Pull directly-attached comment lines above `start` into the span."""
    lines = src[:start].split("\n")
    k = len(lines) - 1  # the line holding `start` (partial)
    while k - 1 >= 0 and lines[k - 1].strip().startswith(("//", "/*", "*")):
        k -= 1
    if k == len(lines) - 1:
        return start
    return len("\n".join(lines[:k])) + (1 if k > 0 else 0)


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def parse(src: str) -> tuple[list[Decl], list[Stmt]]:
    """Top-level declarations and the remaining top-level statements, in order."""
    toks = tokenize(src)
    sig = [t for t in toks if t.kind != "comment"]
    decls: list[Decl] = []
    stmts: list[Stmt] = []
    i, n = 0, len(sig)
    while i < n:
        t = sig[i]
        if t.depth != 0:
            i += 1
            continue
        if t.kind == "punct" and t.text == ";":
            i += 1
            continue
        # decorators
        decorators: list[str] = []
        span_start = t.start
        j = i
        while j < n and sig[j].kind == "punct" and sig[j].text == "@" and sig[j].depth == 0:
            k = j + 1
            while k < n:
                tk = sig[k]
                if tk.depth == 0 and ((tk.kind == "id" and tk.text in _MODIFIERS | set(_DECL_KINDS))
                                      or (tk.kind == "punct" and tk.text == "@")):
                    break
                k += 1
            decorators.append(_squash(src[sig[j].start: sig[k - 1].end]))
            j = k
        # modifiers + kind
        k = j
        exported = is_default = False
        while k < n and sig[k].kind == "id" and sig[k].text in _MODIFIERS:
            if sig[k].text == "export":
                exported = True
            elif sig[k].text == "default":
                is_default = True
            k += 1
        kind = sig[k].text if k < n and sig[k].kind == "id" and sig[k].text in _DECL_KINDS else None
        if kind is None:
            end_idx = _statement_end(sig, i, False)
            text = src[sig[i].start: sig[end_idx].end]
            head = sig[i].text
            skind = "import" if head == "import" else ("export" if head == "export" else "other")
            stmts.append(Stmt(skind, sig[i].start, sig[end_idx].end, text))
            i = end_idx + 1
            continue
        m = k + 1
        if kind == "function" and m < n and sig[m].kind == "punct" and sig[m].text == "*":
            m += 1
        name = "default" if is_default else ""
        if m < n and sig[m].kind == "id" and sig[m].text not in ("extends", "implements"):
            name = sig[m].text
        if not name:
            end_idx = _statement_end(sig, i, kind in _BODY_KINDS)
            stmts.append(Stmt("other", sig[i].start, sig[end_idx].end, src[sig[i].start: sig[end_idx].end]))
            i = end_idx + 1
            continue
        body_kind = kind in _BODY_KINDS
        end_idx = _statement_end(sig, i, body_kind)
        end = sig[end_idx].end
        # The body is the depth-0 `{ … }` that closes the statement (a trailing `;`
        # aside): a `{` in a parameter list or a `: { … }` return type closes earlier.
        body_open = None
        close_idx = end_idx
        if sig[close_idx].kind == "punct" and sig[close_idx].text == ";" and close_idx > k:
            close_idx -= 1
        closer = sig[close_idx]
        if closer.kind == "punct" and closer.text == "}" and closer.depth == 1:
            for q in range(close_idx - 1, k, -1):
                tq = sig[q]
                if tq.depth == 0 and tq.kind == "punct" and tq.text == "{":
                    body_open = tq.start
                    break
        if body_open is not None:
            header = _squash(src[sig[j].start: body_open])
        else:
            header = _squash(src[sig[j].start: end])
            if len(header) > 80 and kind in ("const", "let", "var", "type"):
                arrow, eq = header.find("=>"), header.find("=")
                if arrow > 0:
                    header = header[: arrow + 2] + " ..."
                elif eq > 0:
                    header = header[: eq + 1] + " ..."
        decl = Decl(name, kind, exported, is_default, _leading_start(src, span_start), end, header, decorators, body_open)
        if kind == "class" and body_open is not None:
            decl.members = _class_members(src, sig, decl)
        decls.append(decl)
        i = end_idx + 1
    return decls, stmts


def _public_header(d: Decl) -> str:
    h = d.header
    for mod in ("export", "default", "declare"):
        if h.startswith(mod + " "):
            h = h[len(mod) + 1:]
    return h


# ------------------------------------------------------------------ frames


def skeleton(src: str, focus: list[str]) -> str:
    """Imports and export statements verbatim, focused declarations verbatim,
    every other declaration as its signature with the body elided (`{ ... }`).
    A dotted focus `Class.method` keeps the class as a brace-elided skeleton
    with its member signatures and emits only that member verbatim."""
    from . import _cstyle as C

    decls, stmts = parse(src)
    keep = {f for f in focus if "." not in f}
    members: dict[str, set[str]] = {}
    for f in focus:
        if "." in f:
            owner, _, member = f.rpartition(".")
            members.setdefault(owner, set()).add(member)
    items: list[tuple[int, str]] = []
    for s in stmts:
        if s.kind in ("import", "export"):
            items.append((s.start, s.text.rstrip() + "\n"))
        else:
            items.append((s.start, "// " + _squash(s.text)[:60] + " …\n"))
    for d in decls:
        if d.name in keep:
            items.append((d.start, src[d.start: d.end].rstrip() + "\n"))
        elif d.members and d.name in members:
            items.append((d.start, C.render_container(src, d, members[d.name], _member_line)))
        else:
            items.append((d.start, "".join(f"{dec}\n" for dec in d.decorators) + _header_line(d) + "\n"))
    items.sort(key=lambda it: it[0])
    out: list[str] = []
    for _, text in items:
        if text.startswith(("import", "export {", "export *", "// ")) or not out:
            out.append(text)
        else:
            out.append("\n" + text)
    return "".join(out)


def _header_line(d: Decl) -> str:
    if d.body_open is not None:
        return d.header + " { ... }"
    return d.header


def interface_skeleton(src: str) -> str:
    """Dependency view: exported declarations as signatures, bodies elided."""
    decls, stmts = parse(src)
    parts = [_header_line(d) for d in decls if d.exported]
    parts += [s.text.rstrip() for s in stmts if s.kind == "export"]
    return "\n".join(parts) + ("\n" if parts else "")


def symbol_names(src: str) -> list[str]:
    return [d.name for d in parse(src)[0]]


def statement_count(src: str) -> int:
    decls, stmts = parse(src)
    return len(decls) + len(stmts)


def bound_names(src: str) -> set[str]:
    decls, stmts = parse(src)
    names = {d.name for d in decls}
    for s in stmts:
        if s.kind == "export":
            if re.match(r"export\s+default\b", s.text):
                names.add("default")
            m = re.match(r"export\s*\{([^}]*)\}", s.text)
            if m:
                for part in m.group(1).split(","):
                    bits = part.strip().split()
                    if bits:
                        names.add(bits[-1])
    if any(d.is_default for d in decls):
        names.add("default")
    return names


# ------------------------------------------------------------------ patches


def _span_lines(src: str, d: Decl) -> tuple[int, int]:
    """1-based inclusive line range of a declaration (leading comments, decorators)."""
    start_line = src.count("\n", 0, d.start) + 1
    end_line = src.count("\n", 0, max(d.end - 1, 0)) + 1
    return start_line, end_line


def apply_patch(src: str, patch: list[dict]) -> str:
    """`append` / `replace_symbol` / `delete_symbol` by declaration name — dotted
    `Class.method` addresses a member (unindented code is re-indented) — splicing
    exact line spans so everything else survives byte-for-byte."""
    from . import _cstyle as C

    return C.apply_patch(src, patch, parse)


# ------------------------------------------------------------------ imports


_IMPORT_RE = re.compile(
    r"^(?:import|export)\s+(?P<clause>type\s+)?(?P<body>[\s\S]*?)\s*from\s*['\"](?P<spec>[^'\"]+)['\"]"
    r"|^import\s*['\"](?P<side>[^'\"]+)['\"]"
)
_REQUIRE_RE = re.compile(r"\b(?:require|import)\(\s*['\"](\.{1,2}/[^'\"]+)['\"]\s*\)")


def _names_from_clause(body: str) -> set[str | None]:
    names: set[str | None] = set()
    body = body.strip()
    if not body or body == "*":
        return {None}
    for part in re.split(r",(?![^{]*\})", body):
        part = part.strip()
        if not part:
            continue
        if part.startswith("*"):
            names.add(None)
        elif part.startswith("{"):
            for item in part.strip("{} ").split(","):
                bits = item.replace("type ", "").strip().split()
                if bits:
                    names.add(bits[0])
        else:
            names.add("default")
    return names


def resolve_imports(node_id: str, path: str, source: str, modules: dict[str, str]) -> dict[str, set]:
    """Dependency node_id -> names imported from it (`None` = the module object)
    for relative `import … from './x'`, `export … from './x'`, `require('./x')`
    and dynamic `import('./x')`. Bare specifiers (packages) are not project
    modules and resolve to nothing."""
    from . import _okf

    base = posixpath.dirname(path.replace("\\", "/"))
    out: dict[str, set] = {}

    def target(spec: str) -> str | None:
        if not spec.startswith("."):
            return None
        joined = posixpath.normpath(posixpath.join(base, spec)) if base else posixpath.normpath(spec)
        for candidate in (joined, joined + "/index"):
            nid = modules.get(_okf.rooted_name(candidate))
            if nid is not None and nid != node_id:
                return nid
        return None

    _, stmts = parse(source)
    for s in stmts:
        text = _squash(s.text)
        m = _IMPORT_RE.match(text)
        if not m:
            continue
        spec = m.group("spec") or m.group("side")
        nid = target(spec)
        if nid is None:
            continue
        names = {None} if m.group("side") else _names_from_clause(m.group("body"))
        out.setdefault(nid, set()).update(names)
    for m in _REQUIRE_RE.finditer(source):
        nid = target(m.group(1))
        if nid is not None:
            out.setdefault(nid, set()).add(None)
    return out


# ------------------------------------------------------------------ analyze


def analyze(node_id: str, path: str, source: str, project_modules: dict[str, str] | set[str]):
    """OKF facts for a TypeScript/JavaScript module: exported signatures, relative
    import edges, preserved symbols (every declaration, decorators per module,
    per symbol and per `Class.member`), and the structural `guard:` invariants
    mined from leading `if (cond) throw …` clauses."""
    from . import _okf

    modules = project_modules if isinstance(project_modules, dict) else {m: m for m in project_modules}
    # Indexing never raises on a lexer verdict (the lexer is conservative);
    # Gate A reports unbalanced delimiters when the module is next staged.
    decls, _ = parse(source)
    exports = [_public_header(d) for d in decls if d.exported]
    preserved: list[str] = []
    for d in decls:
        preserved.append(f"{d.kind} {d.name}")
        for dec in d.decorators:
            name = dec.lstrip("@").split("(")[0]
            for sym in (f"@{name}", f"@{name} on {d.name}"):
                if sym not in preserved:
                    preserved.append(sym)
        for m in d.members:
            for dec in m.decorators:
                name = dec.lstrip("@").split("(")[0]
                sym = f"@{name} on {d.name}.{m.name}"
                if sym not in preserved:
                    preserved.append(sym)
    deps = sorted(resolve_imports(node_id, path, source, modules))
    guards = mine_guards(source)
    return _okf.ModuleInfo(
        node_id=node_id, path=path, source=source, exports=exports, deps=deps,
        preserved_symbols=preserved, invariants=list(guards), mined_invariants=list(guards),
    )


# ------------------------------------------------------------------- gate A


def gate_a(node_id: str, locked: bool, source: str, nodes) -> None:
    """Mechanical protection for a TypeScript module: locked, balanced syntax,
    and every name a dependent imports from it still declared."""
    from . import MechanicalError, _okf

    if locked:
        raise MechanicalError(f"node '{node_id}' is LOCKED — mutations are rejected at Gate A")
    problem = syntax_problem(source)
    if problem:
        raise MechanicalError(f"invalid TypeScript syntax in '{node_id}': {problem}")
    paths = {nid: n.path for nid, n in nodes.items()}
    modules = _okf.module_map(paths)
    bound = bound_names(source)
    for dep_id, dep_node in nodes.items():
        if dep_id == node_id or node_id not in dep_node.deps:
            continue
        required = resolve_imports(dep_id, dep_node.path, dep_node.source, modules).get(node_id, set())
        missing = sorted(n for n in required if n is not None and n not in bound)
        if missing:
            raise MechanicalError(
                f"export '{missing[0]}' of '{node_id}' is required by dependent "
                f"'{dep_id}' and is missing from the staged source"
            )


_MEMBER_MODIFIERS = frozenset({"public", "private", "protected", "static", "readonly", "abstract", "async", "override",
                               "declare", "accessor", "get", "set"})


def _class_members(src: str, sig: list[Tok], decl: Decl) -> list[Decl]:
    """Methods and fields of a class body (depth-1 statements): decorators,
    modifiers, `#private`, `constructor`, getters/setters, generic methods."""
    from . import _cstyle as C

    index = {t.start: i for i, t in enumerate(sig)}
    oi = index.get(decl.body_open)
    if oi is None:
        return []
    ci = C.matching_close(sig, oi)
    if ci is None:
        return []
    out: list[Decl] = []
    q = oi + 1
    while q < ci:
        t = sig[q]
        if t.depth != 1 or (t.kind == "punct" and t.text in (";", ",")):
            q += 1
            continue
        decorators: list[str] = []
        j = q
        while j < ci and sig[j].kind == "punct" and sig[j].text == "@" and sig[j].depth == 1:
            k = j + 1
            if k < ci and sig[k].kind == "id":
                k += 1
                while k + 1 < ci and sig[k].text == "." and sig[k + 1].kind == "id":  # dotted decorator name only
                    k += 2
            if k < ci and sig[k].text == "(" and sig[k].depth == 1:
                k += 1
                while k < ci and not (sig[k].depth == 2 and sig[k].text == ")"):
                    k += 1
                k += 1
            decorators.append(_squash(src[sig[j].start: sig[k - 1].end]))
            j = k
        e = C.statement_end(sig, j, 1)
        k = j
        exported = True
        while k <= e and sig[k].kind == "id" and sig[k].text in _MEMBER_MODIFIERS and not (k + 1 <= e and sig[k + 1].text in ("(", "<", ":", "=", ";")):
            if sig[k].text in ("private", "protected"):
                exported = False
            k += 1
        name = None
        if k <= e:
            tk = sig[k]
            if tk.kind == "id":
                name = tk.text
            elif tk.kind == "punct" and tk.text == "#" and k + 1 <= e and sig[k + 1].kind == "id":
                name, exported = "#" + sig[k + 1].text, False
                k += 1
            elif tk.kind == "string":
                name = tk.text[1:-1]
        if not name:
            q = e + 1
            continue
        nxt = sig[k + 1] if k + 1 <= e else None
        is_method = nxt is not None and nxt.kind == "punct" and nxt.text in ("(", "<")
        open_idx, _close_idx = C.body_bounds(sig, j, e)
        body_open = sig[open_idx].start if open_idx is not None else None
        header = _squash(src[sig[j].start: body_open]) if body_open is not None else _squash(src[sig[j].start: sig[e].end])
        if body_open is None and len(header) > 80:
            eq = header.find("=")
            if eq > 0:
                header = header[: eq + 1] + " ..."
        out.append(Decl(name, "method" if is_method else "field", exported, False, _leading_start(src, sig[q].start), sig[e].end,
                        header, decorators, body_open, [], decl.name, C.indent_of(src, sig[q].start)))
        q = e + 1
    return out


def _member_line(m: Decl) -> str:
    return "".join(f"{m.indent}{dec}\n" for dec in m.decorators) + f"{m.indent}{_header_line(m)}\n"


def _guard_rule():
    from . import _cstyle as C

    return C.GuardRule(paren_condition=True, effects=(("throw", ""), ("return", "returns")))


def mine_guards(src: str) -> list[str]:
    """`guard:<symbol>:<cond> throws <Error>` for every leading `if (cond) { throw … }`
    / `if (cond) throw …;` of a top-level function, arrow const or class method.
    `if (!x) return …` is not a guard."""
    from . import _cstyle as C

    decls, _ = parse(src)
    sig = [t for t in tokenize(src) if t.kind != "comment"]
    return C.mine_guards(sig, decls, _guard_rule(), leading_only=False, mining=True)


def present_guards(src: str) -> set[str]:
    """The guards structurally present anywhere in each symbol's body."""
    from . import _cstyle as C

    decls, _ = parse(src)
    sig = [t for t in tokenize(src) if t.kind != "comment"]
    return set(C.mine_guards(sig, decls, _guard_rule(), leading_only=False))
