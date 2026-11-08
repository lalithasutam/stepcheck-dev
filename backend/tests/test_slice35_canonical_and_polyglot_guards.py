"""Slice 35 — guard conservation that follows the language, not the spelling.

1. Python: a mined guard condition is compared in a canonical form derived from the
   grammar and Boolean algebra alone — constants on the right with the operator
   mirrored, commuted operands, `isinstance(x, (T,))` == `isinstance(x, T)`, a negated
   comparison as its inverse operator, De Morgan pushed inward — so an equivalent
   rewrite passes strict Gate C while a real weakening or deletion is still rejected.
2. Go / Java / JS-TS / Rust: guards are mined wherever Python mines them — an abort
   (`throw`, `panic`, `return Err`, an assertion) at any depth of the body, an early
   `return` as a direct branch of the function — in braced and braceless forms, with
   Go's `if init; cond {` short statement, Java `assert cond;` and Rust `assert!`.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from kernel import StateKernel


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, src in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(textwrap.dedent(src), encoding="utf-8", newline="\n")
    return root


def _mined(kernel: StateKernel, sid: str, nid: str) -> list[str]:
    return next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == nid)["invariants_auto_mined"]


# ------------------------------------------------- 1. Python canonical conditions

PY = '''\
import numbers


def slot(x, lo, hi, items, kind):
    if x is None:
        raise ValueError("x")
    if x <= 0:
        raise ValueError("positive")
    if lo < hi:
        raise ValueError("order")
    if not isinstance(kind, str):
        raise TypeError(kind)
    if not (lo and hi):
        raise ValueError("bounds")
    if kind == "a":
        raise ValueError("kind")
    if not x == hi:
        raise ValueError("eq")
    assert len(items) > 1
    return x


class Box:
    def put(self, v, limit):
        if v is not None:
            raise ValueError("full")
        if limit >= 10:
            raise ValueError("limit")
        if v in items_of(self):
            raise ValueError("dup")
        self.v = v


def items_of(box):
    return []
'''

EQUIVALENT = {
    "constant moves right, is": ("if x is None:", "if None is x:"),
    "constant moves right, <=": ("if x <= 0:", "if 0 >= x:"),
    "operands commute, <": ("if lo < hi:", "if hi > lo:"),
    "isinstance 1-tuple": ("if not isinstance(kind, str):", "if not isinstance(kind, (str,)):"),
    "De Morgan": ("if not (lo and hi):", "if not lo or not hi:"),
    "constant moves right, ==": ('if kind == "a":', "if 'a' == kind:"),
    "negated comparison": ("if not x == hi:", "if x != hi:"),
    "assert mirrored": ("assert len(items) > 1", "assert 1 < len(items)"),
    "method is not None": ("if v is not None:", "if None is not v:"),
    "method >= mirrored": ("if limit >= 10:", "if 10 <= limit:"),
    "negated membership": ("if v in items_of(self):", "if not (v not in items_of(self)):"),
}

WEAKENED = {
    "<= to <": ("if x <= 0:", "if x < 0:"),
    "is None to is not None": ("if x is None:", "if x is not None:"),
    "commute without mirroring": ("if lo < hi:", "if hi < lo:"),
    "isinstance type changed": ("if not isinstance(kind, str):", "if not isinstance(kind, (bytes,)):"),
    "De Morgan with the wrong connective": ("if not (lo and hi):", "if not lo and not hi:"),
    "assert boundary": ("assert len(items) > 1", "assert len(items) > 0"),
    "guard deleted": ('    if kind == "a":\n        raise ValueError("kind")\n', ""),
}


@pytest.fixture()
def py_session(kernel, tmp_path):
    root = _write(tmp_path, {"m.py": PY})
    return kernel, kernel.init_session(root)


def test_the_guards_are_mined_in_their_written_spelling(py_session):
    kernel, sid = py_session
    mined = _mined(kernel, sid, "m")
    assert "call:slot(x=None, lo=None, hi=None, items=None, kind=None) raises ValueError" in mined  # leading: a runtime probe
    assert "guard:slot:if kind == 'a' raises ValueError" in mined  # structural guards keep the written spelling
    assert "guard:slot:assert len(items) > 1" in mined
    assert "guard:Box.put:if v is not None raises ValueError" in mined


@pytest.mark.parametrize("label", sorted(EQUIVALENT))
def test_an_equivalent_spelling_of_a_guard_is_not_a_weakening(py_session, label):
    kernel, sid = py_session
    old, new = EQUIVALENT[label]
    assert PY.count(old) == 1
    v = kernel.commit(sid, "m", source=PY.replace(old, new))
    assert v.accepted, (label, v.gate, str(v.error))


@pytest.mark.parametrize("label", sorted(WEAKENED))
def test_a_weakened_or_deleted_guard_is_still_gate_c(py_session, label):
    kernel, sid = py_session
    old, new = WEAKENED[label]
    assert PY.count(old) == 1
    v = kernel.commit(sid, "m", source=PY.replace(old, new))
    assert not v.accepted and v.gate == "C", (label, v.gate, str(v.error))


def test_canonical_matching_survives_a_frame_mined_in_the_old_spelling(py_session):
    """The clause stays stored as written; only the comparison is canonical, so a session
    that mined `None is x` before this slice still accepts `x is None` after it."""
    kernel, sid = py_session
    spelled = PY.replace("if x is None:", "if None is x:")
    assert kernel.commit(sid, "m", source=spelled).accepted
    assert "guard:slot:if None is x raises ValueError" in _mined(kernel, sid, "m")
    assert kernel.commit(sid, "m", source=PY).accepted  # back to the canonical spelling: same guard
    assert not kernel.commit(sid, "m", source=PY.replace("if x is None:", "if x is not None:")).accepted


# ----------------------------------------------------------- 2. polyglot parity

GO = '''\
package ledger

import "errors"

// Parse reads a puzzle.
func Parse(src string) (*Puzzle, error) {
\tp := build(src)
\tif p == nil {
\t\treturn nil, errors.New("empty")
\t}
\tif v, ok := p.cache[src]; !ok {
\t\treturn v, nil
\t}
\tfor i := range p.rows {
\t\tif i < 0 {
\t\t\tpanic("negative index")
\t\t}
\t\tif i > 10 {
\t\t\treturn nil, nil
\t\t}
\t}
\treturn p, nil
}

type Puzzle struct {
\trows  []int
\tcache map[string]*Puzzle
}

func build(src string) *Puzzle { return &Puzzle{} }
'''

JAVA = '''\
package com.acme;

public class Cipher {
    public int translate(int a, int b) {
        int inv = a * b;
        if (inv == 1) throw new IllegalArgumentException("not coprime");
        if (b < 0) return -1;
        assert a > 0 : "a";
        for (int i = 0; i < a; i++) {
            if (i == b) { throw new IllegalStateException("hit"); }
        }
        return inv;
    }
}
'''

TS = '''\
export function roll(pins: number, remaining: number): number {
  const total = pins + remaining;
  if (pins < 0) throw new RangeError("negative");
  if (total > 10) return 10;
  for (const p of [pins]) {
    if (p === 11) throw new Error("eleven");
  }
  return total;
}
'''

RS = '''\
pub struct Game {
    frames: Vec<u16>,
}

impl Game {
    pub fn roll(&mut self, pins: u16) -> Result<(), String> {
        let total = self.frames.len();
        if self.frames.len() > 20 {
            return Err("done".to_string());
        }
        if pins > 10 {
            return Err("too many".to_string());
        }
        assert!(total <= 21);
        assert_eq!(pins % 1, 0);
        for f in &self.frames {
            if *f > 10 {
                panic!("corrupt");
            }
        }
        self.frames.push(pins);
        Ok(())
    }
}
'''


def _project(kernel, tmp_path, rel, src):
    root = _write(tmp_path, {rel: src})
    sid = kernel.init_session(root)
    nid = next(n["node_id"] for n in kernel.graph(sid)["nodes"] if n["path"].replace("\\", "/") == rel)
    return sid, nid


def test_go_guards_are_mined_past_the_leading_run_and_from_short_statements(kernel, tmp_path):
    sid, nid = _project(kernel, tmp_path, "ledger/parse.go", GO)
    mined = _mined(kernel, sid, nid)
    assert "guard:Parse:p==nil returns" in mined  # after an assignment: not leading, still a guard
    assert "guard:Parse:!ok returns" in mined  # the short statement's init is not the condition
    assert "guard:Parse:i<0 panics" in mined  # an abort inside a loop
    assert "guard:Parse:i>10 returns" not in mined  # a return inside a loop is control flow, as in Python
    for old, new in (("if p == nil {", "if p != nil {"), ("\tif v, ok := p.cache[src]; !ok {\n\t\treturn v, nil\n\t}\n", ""),
                     ("if i < 0 {", "if i <= 0 {")):
        v = kernel.commit(sid, nid, source=GO.replace(old, new))
        assert not v.accepted and v.gate == "C", (old, v.gate, str(v.error))
    assert kernel.commit(sid, nid, source=GO.replace("if i > 10 {", "if i > 11 {")).accepted


def test_java_guards_include_braceless_ifs_returns_and_asserts(kernel, tmp_path):
    sid, nid = _project(kernel, tmp_path, "src/Cipher.java", JAVA)
    mined = _mined(kernel, sid, nid)
    assert "guard:Cipher.translate:inv==1 throws IllegalArgumentException" in mined  # braceless, not leading
    assert "guard:Cipher.translate:b<0 returns" in mined
    assert "guard:Cipher.translate:assert a>0" in mined
    assert "guard:Cipher.translate:i==b throws IllegalStateException" in mined  # braced, inside a loop
    for old, new in (("if (inv == 1)", "if (inv != 1)"), ("        if (b < 0) return -1;\n", ""),
                     ("assert a > 0 : \"a\";", "assert a >= 0 : \"a\";"), ("if (i == b)", "if (i != b)")):
        v = kernel.commit(sid, nid, source=JAVA.replace(old, new))
        assert not v.accepted and v.gate == "C", (old, v.gate, str(v.error))


def test_ts_guards_include_braceless_returns_and_nested_throws(kernel, tmp_path):
    sid, nid = _project(kernel, tmp_path, "src/roll.ts", TS)
    mined = _mined(kernel, sid, nid)
    assert "guard:roll:pins<0 throws RangeError" in mined
    assert "guard:roll:total>10 returns" in mined
    assert "guard:roll:p===11 throws Error" in mined
    for old, new in (("if (pins < 0)", "if (pins <= 0)"), ("  if (total > 10) return 10;\n", ""), ("if (p === 11)", "if (p === 12)")):
        v = kernel.commit(sid, nid, source=TS.replace(old, new))
        assert not v.accepted and v.gate == "C", (old, v.gate, str(v.error))


def test_rust_guards_include_mid_body_returns_asserts_and_nested_panics(kernel, tmp_path):
    sid, nid = _project(kernel, tmp_path, "src/game.rs", RS)
    mined = _mined(kernel, sid, nid)
    assert "guard:Game.roll:self.frames.len()>20 returns Err" in mined  # after a `let`: not leading
    assert "guard:Game.roll:pins>10 returns Err" in mined
    assert "guard:Game.roll:assert!(total<=21)" in mined
    assert "guard:Game.roll:assert_eq!(pins%1,0)" in mined
    assert "guard:Game.roll:*f>10 panics" in mined
    for old, new in (("if pins > 10 {", "if pins > 11 {"), ("        assert!(total <= 21);\n", ""),
                     ("assert_eq!(pins % 1, 0);", "assert_ne!(pins % 1, 0);"), ("if *f > 10 {", "if *f >= 10 {")):
        v = kernel.commit(sid, nid, source=RS.replace(old, new))
        assert not v.accepted and v.gate == "C", (old, v.gate, str(v.error))
