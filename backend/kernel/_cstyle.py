"""Shared scanner and OKF machinery for the brace languages (Go, Rust, Java; the
TypeScript module reuses the member/guard helpers). Private, zero dependencies,
deterministic: no state survives a call.

One tokenizer parameterised by a `Spec` masks strings, char literals, raw
strings, comments and tracks `{}()[]` depth; declarations are read from the
depth-0 tokens by each language module, container members from the depth-1
tokens of a body. Everything below works on a `Tok` list (the TypeScript
tokenizer produces the same shape), so the language modules stay thin.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# ----------------------------------------------------------------- tokens


@dataclass(frozen=True)
class Tok:
    kind: str  # id | num | punct | string | char | comment | lifetime | attr
    text: str
    start: int
    end: int
    line: int
    depth: int  # delimiter depth before this token


@dataclass(frozen=True)
class Spec:
    name: str  # go | rust | java
    fence: str
    char_literals: bool = True  # 'x' is a char/rune, not a string
    lifetimes: bool = False  # Rust: 'a is a lifetime when no closing quote follows
    backtick_raw: bool = False  # Go raw strings
    rust_raw: bool = False  # r"…", r#"…"#, b"…", br"…"
    text_blocks: bool = False  # Java """…"""
    ops: tuple[str, ...] = ("...", "::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/=", ":=", "<-", "..=", "..")


_IDENT_START = re.compile(r"[A-Za-z_$]")
_IDENT = re.compile(r"[A-Za-z0-9_$]")


def tokenize(src: str, spec: Spec) -> list[Tok]:
    """Significant tokens with the delimiter depth in force before each one."""
    toks: list[Tok] = []
    i, n, line, depth = 0, len(src), 1, 0
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
        if spec.text_blocks and src.startswith('"""', i):
            j = i + 3
            while True:  # an escaped \""" is content; only a bare """ closes the block
                j = src.find('"""', j)
                if j < 0 or src[j - 1] != "\\":
                    break
                j += 1
            j = n if j < 0 else j + 3
            toks.append(Tok("string", src[i:j], i, j, line, depth))
            line += src.count("\n", i, j)
            i = j
            continue
        if spec.rust_raw and c in "rbc" and _rust_raw_start(src, i):
            j = _rust_raw_end(src, i)
            toks.append(Tok("string", src[i:j], i, j, line, depth))
            line += src.count("\n", i, j)
            i = j
            continue
        if c == '"':
            j = i + 1
            while j < n and src[j] != '"' and src[j] != "\n":
                if src[j] == "\\":
                    j += 1
                j += 1
            j = min(j + 1, n)
            toks.append(Tok("string", src[i:j], i, j, line, depth))
            i = j
            continue
        if c == "`" and spec.backtick_raw:
            j = src.find("`", i + 1)
            j = n if j < 0 else j + 1
            toks.append(Tok("string", src[i:j], i, j, line, depth))
            line += src.count("\n", i, j)
            i = j
            continue
        if c == "'":
            if spec.lifetimes:
                m = re.match(r"'([A-Za-z_][A-Za-z0-9_]*)(?!')", src[i:i + 64])
                if m and not (i + 1 + len(m.group(1)) < n and src[i + 1 + len(m.group(1))] == "'"):
                    j = i + 1 + len(m.group(1))
                    toks.append(Tok("lifetime", src[i:j], i, j, line, depth))
                    i = j
                    continue
            j = i + 1
            while j < n and src[j] != "'" and src[j] != "\n":
                if src[j] == "\\":
                    j += 1
                j += 1
            j = min(j + 1, n)
            toks.append(Tok("char" if spec.char_literals else "string", src[i:j], i, j, line, depth))
            i = j
            continue
        if _IDENT_START.match(c):
            j = i + 1
            while j < n and _IDENT.match(src[j]):
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
        for op in spec.ops:
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


def _rust_raw_start(src: str, i: int) -> bool:
    m = re.match(r"(?:b|c|br|cr|r|rb)#*\"", src[i:i + 16])
    return bool(m) and "r" in m.group(0)[:3]


def _rust_raw_end(src: str, i: int) -> int:
    m = re.match(r"(?:b|c|br|cr|r|rb)(#*)\"", src[i:i + 16])
    hashes = m.group(1)
    j = src.find('"' + hashes, i + len(m.group(0)))
    return len(src) if j < 0 else j + 1 + len(hashes)


def syntax_problem(src: str, spec: Spec) -> str | None:
    """Balanced delimiters and terminated literals; None when sound."""
    toks = tokenize(src, spec)
    stack: list[Tok] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for t in toks:
        if t.kind == "comment" and t.text.startswith("/*") and not t.text.endswith("*/"):
            return f"unterminated block comment (line {t.line})"
        if t.kind in ("string", "char") and (len(t.text) < 2 or (t.text[-1] != t.text[0] and not t.text.startswith(("r", "b", "c")))):
            return f"unterminated {'char' if t.kind == 'char' else 'string'} literal (line {t.line})"
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


# ---------------------------------------------------------- declarations


@dataclass
class Decl:
    name: str
    kind: str  # func | method | type | struct | enum | trait | impl | interface | class | record | const | var | static | field
    exported: bool
    start: int  # char offset including leading comments / attributes
    end: int  # char offset just past the declaration
    header: str  # signature, single-spaced, no body
    attrs: list[str] = field(default_factory=list)
    body_open: int | None = None  # char offset of the body `{`
    body_close: int | None = None  # char offset of the matching `}`
    members: list["Decl"] = field(default_factory=list)
    owner: str | None = None
    is_function: bool = False
    indent: str = ""

    @property
    def dotted(self) -> str:
        return f"{self.owner}.{self.name}" if self.owner else self.name


@dataclass
class Stmt:
    kind: str  # import | package | other
    start: int
    end: int
    text: str


_CONT_END = frozenset({",", "(", "[", "{", "=", ":", "+", "-", "*", "/", "%", "<", ">", "&&", "||", "&", "|", "^", "==", "!=",
                       "<=", ">=", "->", "=>", "::", ".", "?", ":="})
_CONT_START = frozenset({".", ",", ")", "]", "&&", "||", "?", "=", "=>", "+", "-", "*", "/", "%", "==", "!=", "<=", ">=", "&", "|",
                         "::", "->", "{"})
_CONT_START_WORDS = frozenset({"else", "catch", "finally", "where", "implements", "extends", "throws", "for"})


def squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def leading_start(src: str, start: int) -> int:
    """Pull directly-attached comment / attribute / annotation lines above `start` into the span."""
    lines = src[:start].split("\n")
    k = len(lines) - 1
    while k - 1 >= 0 and lines[k - 1].strip().startswith(("//", "/*", "*", "#[", "@", "///", "//!")) and not lines[k - 1].strip().startswith("@interface"):
        k -= 1
    if k == len(lines) - 1:
        return start
    return len("\n".join(lines[:k])) + (1 if k > 0 else 0)


def statement_end(sig: list[Tok], i: int, depth: int) -> int:
    """Index of the last token of the statement starting at sig[i] at `depth`:
    a `;` at that depth, or the `}` that closes a block opened at that depth
    (`} else {`, `} catch`, `};` continue the statement)."""
    n = len(sig)
    last = i
    j = i
    saw_block = False
    while j < n:
        t = sig[j]
        if t.depth < depth:
            return last
        if t.depth == depth:
            if t.kind == "punct" and t.text == ";" and j > i:
                return j
            if j > i:
                prev = sig[last]
                if prev.kind == "punct" and prev.text == "}" and prev.depth == depth + 1:
                    if t.kind == "punct" and t.text == ";":
                        return j
                    if (t.kind == "id" and t.text in _CONT_START_WORDS) or (t.kind == "punct" and t.text in (".", ")", ",")):
                        pass
                    else:
                        return last
                elif t.line > prev.line and not saw_block:
                    starts_cont = (t.kind == "punct" and t.text in _CONT_START) or (t.kind == "id" and t.text in _CONT_START_WORDS)
                    ends_cont = (prev.kind == "punct" and prev.text in _CONT_END) or (prev.kind == "id" and prev.text in ("return", "throw", "in", "of", "as", "extends", "implements", "where", "throws", "new"))
                    if not (starts_cont or ends_cont):
                        return last
            if t.kind == "punct" and t.text == "{":
                saw_block = True
        last = j
        j += 1
    return last


def matching_close(sig: list[Tok], open_idx: int) -> int | None:
    """Index of the `}` matching the `{` at sig[open_idx]."""
    depth = sig[open_idx].depth + 1  # tokens inside the block, the closer included, sit one deeper
    for q in range(open_idx + 1, len(sig)):
        t = sig[q]
        if t.depth < depth:
            return None
        if t.depth == depth and t.kind == "punct" and t.text == "}":
            return q
    return None


def body_bounds(sig: list[Tok], i: int, end_idx: int) -> tuple[int | None, int | None]:
    """(open_idx, close_idx) of the statement's outermost `{ … }` at the statement depth, if any."""
    depth = sig[i].depth
    close_idx = end_idx
    if sig[close_idx].kind == "punct" and sig[close_idx].text == ";" and close_idx > i:
        close_idx -= 1
    closer = sig[close_idx]
    if closer.kind == "punct" and closer.text == "}" and closer.depth == depth + 1:
        for q in range(close_idx - 1, i - 1, -1):
            if sig[q].depth == depth and sig[q].kind == "punct" and sig[q].text == "{":
                return q, close_idx
    return None, None


def span_lines(src: str, start: int, end: int) -> tuple[int, int]:
    """1-based inclusive line range of a char span."""
    return src.count("\n", 0, start) + 1, src.count("\n", 0, max(end - 1, 0)) + 1


def indent_of(src: str, start: int) -> str:
    line_start = src.rfind("\n", 0, start) + 1
    m = re.match(r"[ \t]*", src[line_start:start + 1])
    return m.group(0) if m else ""


# ----------------------------------------------------------- generic ops


def find_symbol(decls: list[Decl], dotted: str) -> Decl | None:
    """A top-level declaration by name, or a member by `Owner.member` (every
    declaration named `Owner` is searched: a Rust type and each of its `impl`
    blocks share the name; a Go method whose receiver type lives elsewhere is a
    top-level declaration with an owner)."""
    owner, _, member = dotted.rpartition(".")
    if owner:
        for d in decls:
            if d.dotted == dotted:
                return d
            if d.name == owner:
                for m in d.members:
                    if m.name == member:
                        return m
        return None
    return next((d for d in decls if d.name == dotted and d.owner is None), None)


def apply_patch(src: str, patch: list[dict], parse) -> str:
    """`append` / `replace_symbol` / `delete_symbol` by (dotted) declaration name,
    splicing exact line spans; member code without indentation is re-indented."""
    for op in patch:
        kind = op.get("op")
        if kind == "append":
            code = op["code"].rstrip("\n") + "\n"
            src = (src.rstrip("\n") + "\n\n" + code) if src.strip() else code
            continue
        if kind not in ("replace_symbol", "delete_symbol"):
            raise ValueError(f"unknown patch op {kind!r}")
        decls, _ = parse(src)
        target = find_symbol(decls, op["name"])
        if target is None:
            raise ValueError(f"patch targets unknown top-level symbol {op['name']!r}")
        lines = src.splitlines(keepends=True)
        start, end = span_lines(src, target.start, target.end)
        head, tail = "".join(lines[: start - 1]), "".join(lines[end:])
        indent = target.indent
        if kind == "replace_symbol":
            code = op["code"].rstrip("\n") + "\n"
            if indent and not code.startswith((" ", "\t")):
                code = "".join(indent + ln if ln.strip() else ln for ln in code.splitlines(keepends=True))
            src = head + code + tail
        else:
            if indent:
                src = head + tail
            else:
                head, tail = head.rstrip("\n"), tail.lstrip("\n")
                src = (head + "\n\n" + tail) if head and tail else (head + "\n" if head else tail)
    return src


def header_line(d: Decl) -> str:
    return d.header + " { ... }" if d.body_open is not None else d.header


def render_container(src: str, d: Decl, focus_members: set[str], render_member) -> str:
    """Container header + members: focused ones verbatim, the rest as signatures."""
    out = ["".join(f"{a}\n" for a in d.attrs) + d.header + " {\n"]
    for m in d.members:
        if m.name in focus_members:
            line_start = src.rfind("\n", 0, m.start) + 1  # keep the member's own indentation
            out.append(src[line_start: m.end].rstrip("\n") + "\n")
        else:
            out.append(render_member(m))
    out.append("}\n")
    return "".join(out)


def skeleton(src: str, focus: list[str], parse, stmt_line, member_line) -> str:
    """Imports / package lines verbatim, focused declarations (or members) verbatim,
    every other declaration as its signature with the body elided."""
    decls, stmts = parse(src)
    keep = {f for f in focus if "." not in f}
    members: dict[str, set[str]] = {}
    for f in focus:
        if "." in f:
            owner, _, member = f.rpartition(".")
            members.setdefault(owner, set()).add(member)
    items: list[tuple[int, str]] = []
    for s in stmts:
        items.append((s.start, stmt_line(s)))
    for d in decls:
        if d.name in keep:
            items.append((d.start, src[d.start: d.end].rstrip() + "\n"))
        elif d.members and d.name in members:
            items.append((d.start, render_container(src, d, members[d.name], member_line)))
        else:
            items.append((d.start, "".join(f"{a}\n" for a in d.attrs) + header_line(d) + "\n"))
    items.sort(key=lambda it: it[0])
    out: list[str] = []
    for _, text in items:
        if not out or text.startswith(("import", "package", "use ", "mod ", "// ")):
            out.append(text)
        else:
            out.append("\n" + text)
    return "".join(out)


def interface_skeleton(decls: list[Decl], member_line) -> str:
    parts: list[str] = []
    for d in decls:
        pub_members = [m for m in d.members if m.exported]
        if not d.exported and not pub_members:
            continue
        if pub_members:
            parts.append(d.header + " {\n" + "".join(member_line(m) for m in pub_members) + "}")
        else:
            parts.append(header_line(d))
    return "\n".join(parts) + ("\n" if parts else "")


def symbol_names(decls: list[Decl]) -> list[str]:
    out: list[str] = []
    for d in decls:
        out.append(d.name)
        out.extend(m.dotted for m in d.members)
    return out


def statement_count(decls: list[Decl], stmts: list[Stmt]) -> int:
    return len(decls) + sum(len(d.members) for d in decls) + len(stmts)


def bound_names(decls: list[Decl]) -> set[str]:
    names = {d.name for d in decls}
    for d in decls:
        names.update(m.name for m in d.members)
    return names


def preserved_symbols(decls: list[Decl]) -> list[str]:
    out: list[str] = []

    def keep_attrs(d: Decl, label: str) -> None:
        for a in d.attrs:
            tag = attr_tag(a)
            for sym in (tag, f"{tag} on {label}"):
                if sym not in out:
                    out.append(sym)

    for d in decls:
        out.append(f"{d.kind} {d.name}")
        keep_attrs(d, d.name)
        for m in d.members:
            out.append(f"{m.kind} {m.dotted}")
            keep_attrs(m, m.dotted)
    return out


def attr_tag(attr: str) -> str:
    """`#[derive(Debug, Clone)]` -> `#[derive]`, `@Transactional(readOnly = true)` -> `@Transactional`,
    `//go:embed static` -> `//go:embed`."""
    a = squash(attr)
    if a.startswith("#["):
        inner = a[2:].rstrip("]")
        return "#[" + re.split(r"[(\s=]", inner, 1)[0] + "]"
    if a.startswith("@"):
        return "@" + re.split(r"[(\s]", a[1:], 1)[0]
    if a.startswith("//go:"):
        return a.split()[0]
    return a.split("(")[0]


# ------------------------------------------------------------- guards


@dataclass(frozen=True)
class GuardRule:
    paren_condition: bool  # Java / TS: `if (cond)`; Go / Rust: `if cond {`
    effects: tuple[tuple[str, str], ...]  # (first token(s) of the consequence, effect label); "" label = use next identifier
    assert_keyword: bool = False  # Java: `assert cond;` / `assert cond : message;`
    assert_macros: tuple[str, ...] = ()  # Rust: `assert!(…)`, `assert_eq!(…)`, …


def _consequence(sig: list[Tok], k: int, depth: int) -> tuple[list[Tok], int]:
    """Tokens of the consequence statement starting at sig[k] (inside a block or bare)."""
    if sig[k].kind == "punct" and sig[k].text == "{":
        close = matching_close(sig, k)
        if close is None:
            return [], len(sig)
        inner = [t for t in sig[k + 1: close] if t.depth == depth + 1]
        if not inner:
            return [], close + 1
        end = statement_end(sig, k + 1, depth + 1)
        return sig[k + 1: end + 1], close + 1
    end = statement_end(sig, k, depth)
    return sig[k: end + 1], end + 1


def _effect(cons: list[Tok], rule: GuardRule) -> str | None:
    if not cons:
        return None
    head = cons[0].text
    if cons[0].kind != "id":
        return None
    for key, label in rule.effects:
        parts = key.split()
        if [t.text for t in cons[: len(parts)]] != parts:
            continue
        if label:
            return label
        # `throws <Error>`: the identifier after `new`, or the first identifier / literal kind
        rest = cons[len(parts):]
        if rest and rest[0].kind == "id" and rest[0].text == "new":
            rest = rest[1:]
        if rest and rest[0].kind == "id":
            name = rest[0].text
            q = 1
            while q + 1 < len(rest) and rest[q].kind == "punct" and rest[q].text == "." and rest[q + 1].kind == "id":
                name += "." + rest[q + 1].text
                q += 2
            return f"throws {name}"
        if rest and rest[0].kind in ("string", "template"):
            return "throws string"
        return "throws"
    return None if head else None


def guards_in(sig: list[Tok], open_idx: int, close_idx: int, rule: GuardRule, leading_only: bool,
              *, mining: bool = False, top_depth: int | None = None) -> list[str]:
    """`<cond> <effect>` strings for guard clauses in a body: the leading run of
    `if` statements (leading_only) or every guard at any depth — the same definition
    Python's miner uses: an abort (`throw`, `panic`, `return Err`, an assertion) is a
    guard wherever it sits; an early `return` is one only as a direct branch of the
    function body when `mining` (inside a loop it is control flow), while the
    presence check (`mining=False`) counts a return anywhere."""
    out: list[str] = []
    depth = sig[open_idx].depth + 1
    if top_depth is None:
        top_depth = depth
    j = open_idx + 1
    while j < close_idx:
        t = sig[j]
        if t.depth < depth:
            break
        if t.depth == depth:
            if t.kind == "id" and t.text == "if":
                g, nxt = _guard_at(sig, j, depth, rule)
                if g is not None and mining and depth != top_depth and g.rsplit(" ", 1)[-1].startswith("returns") \
                        and not g.endswith(" Err"):
                    g = None  # a nested early return is control flow, not a guard
                if g is not None:
                    out.append(g)
                    j = max(nxt, j + 1)
                    continue
                if leading_only:
                    break
            elif t.kind == "id" and ((rule.assert_keyword and t.text == "assert")
                                     or (t.text in rule.assert_macros and j + 1 < len(sig) and sig[j + 1].text == "!")):
                g, nxt = _assert_at(sig, j, depth, rule)
                if g is not None:
                    out.append(g)
                    j = max(nxt, j + 1)
                    continue
                if leading_only:
                    break
            elif leading_only:
                break
            end = statement_end(sig, j, depth)
            if not leading_only:
                # descend into nested blocks of this statement
                for q in range(j, end + 1):
                    if sig[q].kind == "punct" and sig[q].text == "{" and sig[q].depth >= depth:
                        close = matching_close(sig, q)
                        if close is not None and close <= end:
                            out.extend(guards_in(sig, q, close, rule, False, mining=mining, top_depth=top_depth))
            j = end + 1
            continue
        j += 1
    return out


def _assert_at(sig: list[Tok], j: int, depth: int, rule: GuardRule) -> tuple[str | None, int]:
    """`assert <cond>` for a Java `assert cond[: message];` or a Rust `assert!(…)`
    family macro at sig[j]; the normalized condition keeps the macro's spelling."""
    if sig[j].text == "assert" and rule.assert_keyword and not (j + 1 < len(sig) and sig[j + 1].text == "!"):
        end = statement_end(sig, j, depth)
        toks = sig[j + 1: end + 1]
        cond: list[Tok] = []
        for t in toks:
            if t.depth == depth and t.kind == "punct" and t.text in (":", ";"):
                break
            cond.append(t)
        if not cond:
            return None, j
        return "assert " + "".join(t.text for t in cond if t.kind != "comment"), end + 1
    # Rust: `name ! ( … )`
    k = j + 2
    if k >= len(sig) or sig[k].text != "(":
        return None, j
    close = None
    for q in range(k + 1, len(sig)):
        if sig[q].depth == depth + 1 and sig[q].kind == "punct" and sig[q].text == ")":
            close = q
            break
        if sig[q].depth <= depth:
            break
    if close is None:
        return None, j
    inner = "".join(t.text for t in sig[k + 1: close] if t.kind != "comment")
    end = statement_end(sig, j, depth)
    return f"{sig[j].text}!({inner})", max(end + 1, close + 1)


def _guard_at(sig: list[Tok], j: int, depth: int, rule: GuardRule) -> tuple[str | None, int]:
    """Guard string for the `if` at sig[j], or (None, j)."""
    k = j + 1
    if rule.paren_condition:
        if k >= len(sig) or sig[k].text != "(":
            return None, j
        close_paren = None
        for q in range(k + 1, len(sig)):
            if sig[q].depth == depth + 1 and sig[q].kind == "punct" and sig[q].text == ")":
                close_paren = q
                break
            if sig[q].depth <= depth:
                break
        if close_paren is None:
            return None, j
        cond = sig[k + 1: close_paren]
        k = close_paren + 1
    else:
        q = k
        while q < len(sig) and not (sig[q].depth == depth and sig[q].kind == "punct" and sig[q].text == "{"):
            if sig[q].depth < depth:
                return None, j
            q += 1
        if q >= len(sig):
            return None, j
        cond = sig[k:q]
        # Go's short statement `if v, ok := m[k]; !ok {`: the condition follows the last `;`
        semis = [i for i, t in enumerate(cond) if t.depth == depth and t.kind == "punct" and t.text == ";"]
        if semis:
            cond = cond[semis[-1] + 1:]
        k = q
    if k >= len(sig):
        return None, j
    cons, nxt = _consequence(sig, k, depth)
    effect = _effect([t for t in cons if t.kind != "comment"], rule)
    if effect is None:
        return None, j
    # skip an attached `else` chain
    while nxt < len(sig) and sig[nxt].depth == depth and sig[nxt].kind == "id" and sig[nxt].text == "else":
        nxt = statement_end(sig, nxt, depth) + 1
    cond_norm = "".join(t.text for t in cond if t.kind != "comment")
    return f"{cond_norm} {effect}", nxt


def mine_guards(sig: list[Tok], decls: list[Decl], rule: GuardRule, *, leading_only: bool, mining: bool = False) -> list[str]:
    """`guard:<symbol>:<cond> <effect>` for every function-like declaration and member.
    `mining=True` is the miner's side (nested early returns are control flow);
    the default is the presence check, which counts every guard anywhere."""
    index = {t.start: i for i, t in enumerate(sig)}
    out: list[str] = []

    def visit(d: Decl) -> None:
        if d.is_function and d.body_open is not None and d.body_open in index:
            oi = index[d.body_open]
            ci = matching_close(sig, oi)
            if ci is not None:
                for g in guards_in(sig, oi, ci, rule, leading_only, mining=mining):
                    inv = f"guard:{d.dotted}:{g}"
                    if inv not in out:
                        out.append(inv)
        for m in d.members:
            visit(m)

    for d in decls:
        visit(d)
    return out


# ------------------------------------------------------- import matching


def match_module(modules: dict[str, str], dotted: str, node_id: str) -> str | None:
    """The node whose importable name is `dotted` or ends with `.dotted` (longest key wins)."""
    best: tuple[int, str] | None = None
    for key, nid in modules.items():
        if nid == node_id:
            continue
        if key == dotted or key.endswith("." + dotted):
            if best is None or len(key) > best[0]:
                best = (len(key), nid)
    return best[1] if best else None


def siblings(modules: dict[str, str], path: str, node_id: str) -> list[str]:
    """Node ids of other tracked files in the same directory (Go packages, Java packages)."""
    directory = "/".join(path.replace("\\", "/").split("/")[:-1])
    out: list[str] = []
    for key, nid in modules.items():
        if nid == node_id or nid in out:
            continue
        key_dir = ".".join(key.split(".")[:-1])
        if key_dir == directory.replace("/", "."):
            out.append(nid)
    return out


def gate_a(node_id: str, locked: bool, source: str, nodes, *, syntax_problem_fn, bound_names_fn, resolve_imports_fn, lang: str) -> None:
    """Mechanical protection: locked, balanced syntax, exports a dependent imports still declared."""
    from . import MechanicalError, _okf

    if locked:
        raise MechanicalError(f"node '{node_id}' is LOCKED — mutations are rejected at Gate A")
    problem = syntax_problem_fn(source)
    if problem:
        raise MechanicalError(f"invalid {lang} syntax in '{node_id}': {problem}")
    paths = {nid: n.path for nid, n in nodes.items()}
    modules = _okf.module_map(paths)
    bound = bound_names_fn(source)
    for dep_id, dep_node in nodes.items():
        if dep_id == node_id or node_id not in dep_node.deps:
            continue
        required = resolve_imports_fn(dep_id, dep_node.path, dep_node.source, modules).get(node_id, set())
        missing = sorted(n for n in required if n is not None and n not in bound)
        if missing:
            raise MechanicalError(
                f"export '{missing[0]}' of '{node_id}' is required by dependent "
                f"'{dep_id}' and is missing from the staged source"
            )


def module_info(okf, node_id: str, path: str, source: str, deps: list[str], decls: list[Decl], guards: list[str]):
    exports = [header_line(d) if not d.members else d.header for d in decls if d.exported]
    for d in decls:
        exports.extend(f"{d.name}.{m.header}" for m in d.members if m.exported and (d.exported or d.kind == "impl"))
    return okf.ModuleInfo(
        node_id=node_id, path=path, source=source, exports=exports, deps=deps,
        preserved_symbols=preserved_symbols(decls), invariants=list(guards), mined_invariants=list(guards),
    )


def sibling_files(root: Path, path: Path) -> list[Path]:
    return sorted(p for p in path.parent.iterdir() if p.is_file() and p != path)
