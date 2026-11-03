"""Slice 25 — permanent regression tests from the overnight adversarial fuzzer
(`.stepcheck/discovery/overnight_fuzzer.py`): braces inside strings, comments,
regex / template / raw / char literals never corrupt skeleton slicing or Gate A
in any tracked language; identity patches round-trip byte-exactly; leading-guard
deletion is a Gate C rejection; Rust `const` items are declarations (Seam 1)."""
import hashlib
from pathlib import Path

import pytest

from kernel import StateKernel

TS = '''\
import { helper } from "./util";
// comment with { brace
/* block } comment */
const re = /\\{/;
const re2 = /[}]/g;
export function parse(s: string): number {
  if (!s) { throw new Error("{"); }
  const t = `x ${foo({a: 1})} }`;
  return s.length + helper();
}
export class Box {
  w = 1;
  @dec({x: "{"}) area(): number { return this.w * this.w; }
  set width(v: number) { if (v <= 0) throw new RangeError("}"); this.w = v; }
}
export const arrow = (x: number) => { const s = '{'; return x + 1; };
const tmpl = `a ${ `b ${1 + 1} }` } c`;
'''
TSX = TS + '''\
const jsx = <div data-x="{" title='}'>{"}"}</div>;
export function View(props: { n: number }) {
  return <ul>{[1, 2].map((i) => <li key={i}>{`{${i}}`}</li>)}</ul>;
}
'''
GO = '''\
package main

import "fmt"

// comment { brace
const raw = `{ not closed`
var s = "}"
var r = '{'

type Box struct{ W int }

func (b Box) Area() int { return b.W * b.W }

func Parse(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("{")
	}
	if len(s) > 10 { panic("}") }
	return len(s), nil
}

func closure() func() int { return func() int { return 1 } }
'''
RUST = '''\
use std::fmt;
// comment { brace
const C: char = '{';
pub const R: &str = r#"{ raw"#;
static S: &str = "}";
pub struct Box<'a> { w: &'a str }
impl<'a> Box<'a> {
    pub fn area(&self) -> usize { self.w.len() }
}
pub fn parse(s: &str) -> Result<usize, String> {
    if s.is_empty() { return Err("{".to_string()); }
    if s.len() > 10 { panic!("}"); }
    Ok(s.len())
}
#[derive(Debug)]
pub enum E { A, B }
pub fn fmt_it(n: u8) -> String { format!("{{{}}}", n) }
pub fn m(x: u8) -> u8 { match x { 1 => 1, _ => { 0 } } }
pub fn lt<'a>(x: &'a str) -> &'a str { x }
'''
JAVA = '''\
package demo;
import java.util.List;
// comment { brace
public class Box {
    private static final char C = '{';
    private static final String T = """
        { text block }
        """;
    @Override
    public int area() { return 1; }
    public int parse(String s) {
        if (s == null) { throw new IllegalArgumentException("{"); }
        if (s.isEmpty()) throw new IllegalStateException("}");
        return s.length();
    }
    public java.util.function.Function<Integer, Integer> lam() { return (x) -> { return x + 1; }; }
}
'''
PY = '''\
import json


def dec(*args, **kw):
    return lambda f: f


# comment { brace
C = "}"


def f(s: str) -> int:
    if not s:
        raise ValueError("{")
    t = f"{s} {{ }} {len(s)!r}"
    return len(t)


@dec({"x": "{"})
class K:
    """Doc { with } braces."""

    def area(self) -> int:
        return 1

    @property
    def w(self) -> str:
        return '{'
'''

SAMPLES = {
    "typescript": ("mod.ts", TS, ["parse", "Box", "Box.area", "Box.width", "arrow", "re", "tmpl"]),
    "tsx": ("mod.tsx", TSX, ["parse", "Box", "View", "jsx"]),
    "go": ("mod.go", GO, ["Parse", "Box", "Box.Area", "closure", "raw"]),
    "rust": ("mod.rs", RUST, ["parse", "Box", "Box.area", "E", "fmt_it", "m", "lt", "C", "R", "S"]),
    "java": ("mod.java", JAVA, ["Box", "Box.parse", "Box.area", "Box.lam", "Box.C", "Box.T"]),
    "python": ("mod.py", PY, ["f", "K", "K.area", "K.w"]),
}
UNBALANCED = {"typescript": "\nfunction oops( {\n", "tsx": "\n{\n", "go": "\n{\n", "rust": "\n{\n", "java": "\n{\n", "python": "\nx = {\n"}


def _project(tmp_path: Path, lang: str) -> tuple[Path, str]:
    name, src, _ = SAMPLES[lang]
    (tmp_path / name).write_text(src, encoding="utf-8", newline="\n")
    if lang in ("typescript", "tsx"):
        (tmp_path / "util.ts").write_text("export function helper(): number { return 1; }\n", encoding="utf-8", newline="\n")
    return tmp_path / name, "mod"


def _node(kernel, sid, nid) -> dict:
    return next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == nid)


def _symbol_text(lang: str, src: str, name: str) -> str:
    """The symbol's own lines, the way a focused checkout shows them."""
    import ast

    from kernel import _cstyle, _okf, _ts

    lines = src.splitlines(keepends=True)
    if lang == "python":
        for s in ast.parse(src).body:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if s.name == name:
                    a, b = _okf._symbol_span(lines, s)
                    return "".join(lines[a - 1:b])
                if isinstance(s, ast.ClassDef) and name.startswith(s.name + "."):
                    member = name.split(".", 1)[1]
                    m = next(x for x in s.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) and x.name == member)
                    a, b = _okf._symbol_span(lines, m)
                    return "".join(lines[a - 1:b])
        raise KeyError(name)
    mod = _okf.foreign_module(src)
    decls, _ = mod.parse(src)
    if mod is _ts:
        owner, _, member = name.rpartition(".")
        d = next((d for d in decls if d.name == (owner or name) and d.owner is None), None)
        if owner:
            d = next(m for m in d.members if m.name == member)
        a, b = _ts._span_lines(src, d)
    else:
        d = _cstyle.find_symbol(decls, name)
        a, b = _cstyle.span_lines(src, d.start, d.end)
    return "".join(lines[a - 1:b])


# ------------------------------------------------- braces in literals vs Gate A


@pytest.mark.parametrize("lang", list(SAMPLES))
def test_braces_inside_literals_and_comments_never_unbalance_gate_a(kernel, tmp_path, lang):
    path, node = _project(tmp_path, lang)
    sid = kernel.init_session(tmp_path)
    src = path.read_text(encoding="utf-8")
    same = kernel.commit(sid, node, source=src)
    assert same.accepted, same.error  # every brace sits inside a string, comment, regex, template, char or raw literal
    bad = kernel.commit(sid, node, source=src + UNBALANCED[lang])
    assert not bad.accepted and bad.gate == "A", bad.error  # a brace outside any literal is still caught


@pytest.mark.parametrize("lang", list(SAMPLES))
def test_skeleton_keeps_every_declared_name(kernel, tmp_path, lang):
    _, node = _project(tmp_path, lang)
    sid = kernel.init_session(tmp_path)
    body = kernel.checkout(sid, node, focus=[]).rendered()
    for name in SAMPLES[lang][2]:
        assert name.split(".")[0] in body, name


# -------------------------------------------- identity patches round-trip bytes


@pytest.mark.parametrize("lang", list(SAMPLES))
def test_identity_replace_symbol_round_trips_every_symbol_byte_exactly(kernel, tmp_path, lang):
    path, node = _project(tmp_path, lang)
    sid = kernel.init_session(tmp_path)
    src = path.read_text(encoding="utf-8")
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    for name in SAMPLES[lang][2]:
        text = _symbol_text(lang, src, name)
        v = kernel.commit(sid, node, patch=[{"op": "replace_symbol", "name": name, "code": text}])
        assert v.accepted, (name, v.error)
        assert v.attestation["payload"]["sha256"] == before, name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before, name


# ---------------------------------------------- Rust const items (fuzzer find)


def test_rust_const_items_are_declarations_not_statements(kernel, tmp_path):
    # Before the fix the `const` modifier (meant for `const fn`) swallowed every
    # `const NAME: T = …;` item: none was addressable, none appeared as a symbol.
    (tmp_path / "lib.rs").write_text(RUST, encoding="utf-8", newline="\n")
    sid = kernel.init_session(tmp_path)
    node = _node(kernel, sid, "lib")
    assert "const R" in " ".join(node["exports"])  # `pub const` is exported
    v = kernel.commit(sid, "lib", patch=[{"op": "replace_symbol", "name": "C", "code": "const C: char = '}';"}])
    assert v.accepted, v.error
    text = (tmp_path / "lib.rs").read_text(encoding="utf-8")
    assert "const C: char = '}';" in text and 'pub const R: &str = r#"{ raw"#;' in text
    kept = kernel.commit(sid, "lib", patch=[{"op": "delete_symbol", "name": "S"}])
    assert not kept.accepted and kept.gate == "B"  # a const / static is a preserved symbol: Gate B wants the deletion declared
    gone = kernel.commit(sid, "lib", patch=[{"op": "delete_symbol", "name": "S"}], allow_deletion=True)
    assert gone.accepted, gone.error
    assert "static S" not in (tmp_path / "lib.rs").read_text(encoding="utf-8")
    # still a `const fn`-aware parser
    fn = kernel.commit(sid, "lib", patch=[{"op": "append", "code": "pub const fn five() -> u8 { 5 }\n"}])
    assert fn.accepted, fn.error
    assert "five" in [n.split("(")[0].split()[-1] for n in _node(kernel, sid, "lib")["exports"]]


# ------------------------------------- Java text block with an escaped """ (fuzzer find)


def test_java_text_block_with_escaped_triple_quote_does_not_end_the_literal(kernel, tmp_path):
    # Before the fix the tokenizer closed the text block at the escaped \""" and
    # reported an unterminated literal: the whole class vanished from the index.
    src = ('package demo;\npublic class M {\n    static final String T = """\n        a \\""" b {\n        """;\n'
           '    public int f() { return 1; }\n}\n')
    (tmp_path / "M.java").write_text(src, encoding="utf-8", newline="\n")
    sid = kernel.init_session(tmp_path)
    body = kernel.checkout(sid, "M", focus=["M.f"]).rendered()
    assert "public int f() { return 1; }" in body
    v = kernel.commit(sid, "M", patch=[{"op": "replace_symbol", "name": "M.f", "code": "public int f() { return 2; }\n"}])
    assert v.accepted, v.error
    text = (tmp_path / "M.java").read_text(encoding="utf-8")
    assert 'a \\""" b {' in text and "return 2" in text
    bad = kernel.commit(sid, "M", source=src + "\n{\n")
    assert not bad.accepted and bad.gate == "A"


# ------------------------------------------- leading guards survive, deletion is Gate C

GUARDLESS = {
    "typescript": ("parse", "export function parse(s: string): number {\n  const t = `x ${foo({a: 1})} }`;\n  return s.length + helper();\n}\n"),
    "go": ("Parse", "func Parse(s string) (int, error) {\n\treturn len(s), nil\n}\n"),
    "rust": ("parse", "pub fn parse(s: &str) -> Result<usize, String> {\n    Ok(s.len())\n}\n"),
    "java": ("Box.parse", "public int parse(String s) {\n    return s.length();\n}\n"),
}


@pytest.mark.parametrize("lang", list(GUARDLESS))
def test_mined_leading_guard_is_stable_under_comments_and_deleted_guard_is_gate_c(kernel, tmp_path, lang):
    path, node = _project(tmp_path, lang)
    sid = kernel.init_session(tmp_path)
    sym, free = GUARDLESS[lang]
    mined = [inv for inv in _node(kernel, sid, node)["invariants_auto_mined"] if inv.startswith(f"guard:{sym}:")]
    assert len(mined) >= 1, _node(kernel, sid, node)["invariants_auto_mined"]
    src = path.read_text(encoding="utf-8")
    text = _symbol_text(lang, src, sym)
    commented = text.replace("\n", "\n// {\n", 1) if lang != "python" else text
    kept = kernel.commit(sid, node, patch=[{"op": "replace_symbol", "name": sym, "code": commented.replace(" == ", "  ==  ")}])
    assert kept.accepted, kept.error  # a comment line and extra spaces do not change the guard
    assert [inv for inv in _node(kernel, sid, node)["invariants_auto_mined"] if inv.startswith(f"guard:{sym}:")] == mined
    dropped = kernel.commit(sid, node, patch=[{"op": "replace_symbol", "name": sym, "code": free}])
    assert not dropped.accepted and dropped.gate == "C", dropped.error
    assert mined[0] in str(dropped.error)
