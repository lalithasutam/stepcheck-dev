"""Slice 33 — closing the six loopholes the red-team audit confirmed at cf99c2b.

1. The causal cone is a transitive closure even past an over-budget helper: callees behind
   it are still reached (expanded when they fit, named when they do not), and so are the
   constants they read.
2. Gate B's skeleton-stub rule covers JS/TS, Go, Rust and Java bodies (`{}`, comment-only,
   `todo!()` / `unimplemented!()`, a lone trivial `return`).
3. Decorator fingerprints are counted per symbol, so one of several `@overload` blocks
   cannot vanish silently.
4. A REJECTED node (bytes a sync refused) blocks finalization; the Stop hook names it and a
   PostToolUse Bash event adopts or flags what the shell wrote.
5. A broken signature propagates through a re-exporting facade to the consumer that imports
   the name from the package.
6. A stale session's rejected sync never overwrites a VERIFIED frame that matches the file
   on disk, so `stepcheck ci` stays green on a correct tree.
"""
from __future__ import annotations

import hashlib
import re
import textwrap
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import cli
from kernel import OmissionError, StateKernel


def _ids(kernel: StateKernel, sid: str) -> dict[str, str]:
    return {n["path"].replace("\\", "/"): n["node_id"] for n in kernel.graph(sid)["nodes"]}


def _status(kernel: StateKernel, sid: str) -> dict[str, str]:
    return {n["path"].replace("\\", "/"): n["status"] for n in kernel.graph(sid)["nodes"]}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, src in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(textwrap.dedent(src), encoding="utf-8", newline="\n")
    return root


# ------------------------------------------------------- 1. transitive cone


def test_callees_behind_an_over_budget_helper_are_still_reached(kernel, tmp_path):
    big = "\n".join(f'    v{i} = data.get("field_{i}", {i}) * 2' for i in range(120))
    src = ("LIMIT = 3\n\n\ndef read(data):\n    return _parse(data)\n\n\ndef _parse(data):\n"
           f"{big}\n    return _line_type(data)\n\n\ndef _line_type(line):\n    return line.strip()[:LIMIT]\n")
    root = _write(tmp_path, {"qdp.py": src})
    sid = kernel.init_session(root)
    frame = kernel.checkout(sid, "qdp", focus=["read"]).frame_markdown
    note = frame.split("```", 1)[0]
    # `_parse` is over the callee budget: kept as a signature and named in the note …
    assert "_parse" in note and 'v119 = data.get("field_119", 119) * 2' not in frame
    # … but what it calls is still part of the cone: `_line_type` fits, so it is verbatim,
    # and the constant it reads rides along.
    assert "def _line_type(line):\n    return line.strip()[:LIMIT]" in frame
    assert "LIMIT = 3" in frame


def test_a_constant_read_only_behind_the_budget_wall_is_named_not_lost(kernel, tmp_path):
    big = "\n".join(f'    v{i} = data.get("field_{i}", {i}) * 2' for i in range(120))
    src = ("WALL_ONLY = 7\n\n\ndef read(data):\n    return _parse(data)\n\n\ndef _parse(data):\n"
           f"{big}\n    return WALL_ONLY\n")
    root = _write(tmp_path, {"m.py": src})
    sid = kernel.init_session(root)
    frame = kernel.checkout(sid, "m", focus=["read"]).frame_markdown
    assert "WALL_ONLY" in frame.split("```", 1)[0]  # accounted for in the note even though `_parse` is folded


# ------------------------------------------------ 2. polyglot body stubs


POLYGLOT = {
    "javascript": ("calc/calc.js", """\
        export function total(items) {
          let sum = 0;
          for (const it of items) { sum += it.price; }
          return sum;
        }

        export function label(n) {
          return `n=${n}`;
        }
        """, "total", ["{}", "{ /* ... */ }"], "{ return items.length; }"),
    "go": ("calc/calc.go", """\
        package calc

        func Total(items []int) int {
        	sum := 0
        	for _, it := range items {
        		sum += it
        	}
        	return sum
        }
        """, "Total", ["{\n\t// ...\n}", "{\n\treturn 0\n}"], "{\n\treturn len(items)\n}"),
    "rust": ("calc/calc.rs", """\
        pub fn total(items: &[i32]) -> i32 {
            let mut sum = 0;
            for it in items {
                sum += it;
            }
            sum
        }
        """, "total", ["{ todo!() }", "{\n    unimplemented!()\n}"], "{ items.len() as i32 }"),
    "java": ("calc/Calc.java", """\
        public class Calc {
            public int total(int[] items) {
                int sum = 0;
                for (int it : items) {
                    sum += it;
                }
                return sum;
            }
        }
        """, "total", ["{}", "{ return 0; }"], "{ return items.length; }"),
}


def _body_span(src: str, name: str) -> tuple[int, int]:
    """Char offsets of the `{` … `}` body of the first function called `name`."""
    m = re.search(rf"\b{name}\s*\([^)]*\)[^{{;]*\{{", src)
    assert m, name
    open_idx = m.end() - 1
    depth = 0
    for i in range(open_idx, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return open_idx, i
    raise AssertionError("unbalanced")


@pytest.mark.parametrize("lang", sorted(POLYGLOT))
def test_a_stubbed_body_is_a_gate_b_omission_in_every_language(kernel, tmp_path, lang):
    rel, src, fn, stubs, real = POLYGLOT[lang]
    src = textwrap.dedent(src)
    root = _write(tmp_path, {rel: src})
    sid = kernel.init_session(root)
    nid = _ids(kernel, sid)[rel]
    a, b = _body_span(src, fn)
    for stub in stubs:
        v = kernel.commit(sid, nid, source=src[:a] + stub + src[b + 1:])
        assert not v.accepted and v.gate == "B", (lang, stub, v)
        assert getattr(v.error, "subtype", None) == "INTRA_NODE_BODY_STUBBED" and fn in str(v.error)
    # A declared stub is fine, and so is a real one-statement rewrite.
    assert kernel.commit(sid, nid, source=src[:a] + stubs[0] + src[b + 1:], allow_deletion=True).accepted
    assert kernel.commit(sid, nid, source=src[:a] + real + src[b + 1:]).accepted


# ----------------------------------------------- 3. overload preservation


OVERLOADS = '''\
import typing as t
from typing import overload


@overload
def locate(x: int) -> int: ...
@overload
def locate(x: str) -> str: ...
def locate(x):
    return x


class Cfg:
    @t.overload
    def __get__(self, obj: None, owner: None) -> "Cfg": ...
    @t.overload
    def __get__(self, obj: object, owner: type) -> int: ...
    def __get__(self, obj, owner=None):
        return 1
'''


def test_dropping_one_of_several_overload_blocks_is_an_omission(kernel, tmp_path):
    root = _write(tmp_path, {"ov.py": OVERLOADS})
    sid = kernel.init_session(root)
    one_fn = OVERLOADS.replace("@overload\ndef locate(x: str) -> str: ...\n", "")
    one_dec = OVERLOADS.replace("@overload\ndef locate(x: str) -> str: ...\n", "def locate(x: str) -> str: ...\n")
    one_meth = OVERLOADS.replace('    @t.overload\n    def __get__(self, obj: None, owner: None) -> "Cfg": ...\n', "")
    for mutant in (one_fn, one_dec, one_meth):
        v = kernel.commit(sid, "ov", source=mutant)
        assert not v.accepted and v.gate == "B" and "overload" in str(v.error), v
    assert kernel.commit(sid, "ov", source=OVERLOADS).accepted  # unchanged: nothing dropped
    assert kernel.commit(sid, "ov", source=one_fn, allow_deletion=True).accepted


# ------------------------------- 4. REJECTED blocks finalization; Bash writes


SVC = '''\
LIMIT = 10


def check(x):
    if x < 0:
        raise ValueError("negative")
    return x


def compute(a, b):
    total = a + b
    if total > LIMIT:
        total = LIMIT
    return total
'''
CLIENT = "from svc import check, compute\n\n\ndef run(v):\n    return compute(check(v), 1)\n"
STUBBED = SVC.replace("    total = a + b\n    if total > LIMIT:\n        total = LIMIT\n    return total\n", "    ...\n")


def test_a_rejected_sync_blocks_finalization_until_the_file_is_fixed(kernel, tmp_path):
    root = _write(tmp_path, {"svc.py": SVC, "client.py": CLIENT})
    sid = kernel.init_session(root)
    assert kernel.omission_report(sid) == {"dirty": [], "rejected": [], "can_finalize": True}
    (root / "svc.py").write_text(STUBBED, encoding="utf-8", newline="\n")  # a shell wrote it
    assert kernel.sync(sid)["rejected"]["svc"].startswith("B:")
    assert kernel.omission_report(sid) == {"dirty": [], "rejected": ["svc"], "can_finalize": False}
    with pytest.raises(OmissionError, match="REJECTED"):
        kernel.finalize_session(sid)
    (root / "svc.py").write_text(SVC, encoding="utf-8", newline="\n")
    assert kernel.sync(sid) == {"synced": [], "rejected": {}}  # the original bytes are what the session holds
    assert kernel.omission_report(sid) == {"dirty": [], "rejected": [], "can_finalize": True}


def test_hooks_flag_a_bash_write_and_the_stop_hook_blocks_on_it(tmp_path):
    import server

    root = _write(tmp_path, {"svc.py": SVC, "client.py": CLIENT})
    with TestClient(server.app) as client:
        sid = client.post("/v1/step/init", json={"project_root": str(root)}).json()["session_id"]
        hook = lambda **ev: client.post("/v1/step/hook", json=ev).json()  # noqa: E731
        bash = dict(tool_name="Bash", cwd=str(root), tool_input={"command": "sed -i ... svc.py"})
        assert hook(hook_event_name="PreToolUse", **bash) == {}  # nothing staged to judge before the shell runs
        (root / "svc.py").write_text(STUBBED, encoding="utf-8", newline="\n")
        post = hook(hook_event_name="PostToolUse", **bash)
        ctx = post["hookSpecificOutput"]["additionalContext"]
        assert "svc.py" in ctx and "Gate B" in ctx and sid in ctx
        stop = hook(hook_event_name="Stop", cwd=str(root))
        assert stop["decision"] == "block" and "svc" in stop["reason"] and "REJECTED" in stop["reason"]
        (root / "svc.py").write_text(SVC, encoding="utf-8", newline="\n")
        assert hook(hook_event_name="PostToolUse", **bash) == {}
        assert hook(hook_event_name="Stop", cwd=str(root)) == {}


# ------------------------------------------- 5. re-export facade contracts


def test_a_signature_break_reaches_the_consumer_through_a_re_export(kernel, tmp_path):
    root = _write(tmp_path, {
        "pkg/__init__.py": 'from .app import bar, foo\n\n__all__ = ["bar", "foo"]\n',
        "pkg/app.py": "def foo(a, b):\n    return a + b\n\n\ndef bar():\n    return 1\n",
        "consumer.py": "from pkg import foo\n\n\ndef use():\n    return foo(1, 2)\n",
        "other.py": "from pkg import bar\n\n\ndef use():\n    return bar()\n",
    })
    sid = kernel.init_session(root)
    ids = _ids(kernel, sid)
    v = kernel.commit(sid, ids["pkg/app.py"], source="def foo(a, b, c):\n    return a + b + c\n\n\ndef bar():\n    return 1\n")
    assert v.accepted
    status = _status(kernel, sid)
    assert status["pkg/__init__.py"] == "DIRTY_OMISSION_RISK" and status["consumer.py"] == "DIRTY_OMISSION_RISK"
    assert status["other.py"] != "DIRTY_OMISSION_RISK"  # imports a name the facade does not forward from app
    assert set(v.dirtied) >= {ids["pkg/__init__.py"], ids["consumer.py"]}
    assert kernel.omission_report(sid)["can_finalize"] is False
    for nid in (ids["pkg/__init__.py"], ids["consumer.py"]):
        kernel.checkout(sid, nid, focus=[])
        assert kernel.commit(sid, nid, source=kernel.node_source(sid, nid)).accepted
    assert kernel.omission_report(sid)["can_finalize"] is True


def test_a_typescript_barrel_forwards_the_break_too(kernel, tmp_path):
    root = _write(tmp_path, {
        "sub.ts": "export function foo(a: number, b: number): number {\n  return a + b;\n}\n",
        "index.ts": "export { foo } from './sub';\n",
        "consumer.ts": "import { foo } from './index';\n\nexport function use(): number {\n  return foo(1, 2);\n}\n",
    })
    sid = kernel.init_session(root)
    ids = _ids(kernel, sid)
    v = kernel.commit(sid, ids["sub.ts"], source="export function foo(a: number, b: number, c: number): number {\n  return a + b + c;\n}\n")
    assert v.accepted
    assert _status(kernel, sid)["consumer.ts"] == "DIRTY_OMISSION_RISK"


# ------------------------------ 6. rejected sync leaves a VERIFIED frame alone


def _frame_meta(root: Path, nid: str) -> tuple[str, str | None]:
    text = (root / ".stepcheck" / "okf" / f"{nid}.md").read_text(encoding="utf-8")
    shas = re.findall(r"^\s+sha256: ([0-9a-f]{64})", text, re.M)
    return re.search(r"^status: (\S+)", text, re.M).group(1), (shas[-1] if shas else None)


def test_a_stale_session_rejection_does_not_overwrite_a_verified_frame(kernel, tmp_path, capsys):
    root = _write(tmp_path, {
        "a.py": "def f(x):\n    if x < 0:\n        raise ValueError(x)\n    return x\n\n\ndef g():\n    return 2\n",
        "b.py": "from a import f, g\n\n\ndef run(v):\n    return f(v) + g()\n",
    })
    old = kernel.init_session(root)
    new = kernel.init_session(root)
    assert kernel.commit(old, "a", source=(root / "a.py").read_text(encoding="utf-8")).accepted  # old attested a.py as it was
    assert kernel.commit(new, "b", source="from a import f\n\n\ndef run(v):\n    return f(v) + 2\n", allow_deletion=True).accepted
    assert kernel.commit(new, "a", source="def f(x):\n    if x < 0:\n        raise ValueError(x)\n    return x\n",
                         allow_deletion=True).accepted
    disk = hashlib.sha256((root / "a.py").read_bytes()).hexdigest()
    assert _frame_meta(root, "a") == ("VERIFIED", disk)
    capsys.readouterr()
    assert cli.main(["ci", str(root)]) == 0

    rejected = kernel.sync(old)["rejected"]  # what the Stop hook does for every registered session
    assert "a" in rejected and rejected["a"].startswith("A:")
    assert _frame_meta(root, "a") == ("VERIFIED", disk)  # the frame still describes the tree
    assert "a" in kernel.omission_report(old)["rejected"]  # the stale session itself knows it is behind
    capsys.readouterr()
    assert cli.main(["ci", str(root)]) == 0
