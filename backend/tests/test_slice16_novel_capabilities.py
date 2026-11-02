"""Slice 16 — capabilities confirmed by the discovery campaign on 16 real
packages and SWE-bench Verified: dotted sub-class method slicing
(`focus=["Class.method"]`, patch ops on `"Class.method"`), contiguous
multi-definition symbol spans (`@overload` stub chains, `@property` +
`@x.setter` pairs), Gate C trace-hook survival under runaway recursion,
in-toto Statement v1 provenance export, and `stepcheck llms` (Seam 1 + CLI)."""
import base64
import hashlib
import json
import time
from pathlib import Path

import pytest

import cli
from kernel import LogicalError, StateKernel

REPO = Path(__file__).resolve().parents[2]


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8", newline="\n")
    return root


def _node(kernel, sid, nid) -> dict:
    return next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == nid)


def _replace(name: str, code: str) -> list[dict]:
    return [{"op": "replace_symbol", "name": name, "code": code}]


# ------------------------------------ 1. dotted sub-class method slicing

CLASSY = '''\
"""A small repository class: the class-rewrite bottleneck in miniature."""


class Repo:
    """Store of non-negative integers."""

    limit = 10

    def __init__(self, items: list) -> None:
        self.items = list(items)

    def add(self, item: int) -> None:
        if item < 0:
            raise ValueError(item)
        self.items.append(item)

    def total(self) -> int:
        return sum(self.items)

    def mean(self) -> float:
        if not self.items:
            return 0.0
        return self.total() / len(self.items)

    def largest(self) -> int:
        return max(self.items) if self.items else 0


def helper() -> int:
    return 1
'''


def test_focus_on_a_dotted_method_emits_only_that_method_verbatim(kernel, tmp_path):
    _write(tmp_path, {"store.py": CLASSY})
    sid = kernel.init_session(tmp_path)

    whole = kernel.checkout(sid, "store", focus=["Repo"])
    sliced = kernel.checkout(sid, "store", focus=["Repo.add"])
    body = sliced.rendered().split("```python\n", 1)[1]

    assert "self.items.append(item)" in body  # the focused method, verbatim
    assert "class Repo:" in body and '"""Store of non-negative integers."""' in body
    assert "def total(self) -> int:" in body and "return sum(self.items)" not in body  # sibling: skeleton
    assert "def helper() -> int:" in body and "return 1" not in body
    assert sliced.token_count < whole.token_count


def test_patch_ops_address_a_dotted_method_and_leave_its_siblings_byte_identical(kernel, tmp_path):
    _write(tmp_path, {"store.py": CLASSY})
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(sid, "store", patch=_replace(
        "Repo.add",
        "def add(self, item: int) -> None:\n"
        "    if item < 0:\n        raise ValueError(item)\n"
        "    if item > self.limit:\n        raise OverflowError(item)\n"
        "    self.items.append(item)\n",
    ))
    assert v.accepted, v.error  # was: Gate A "patch targets unknown top-level symbol 'Repo.add'"
    source = (tmp_path / "store.py").read_text(encoding="utf-8")
    assert "raise OverflowError(item)" in source
    assert hashlib.sha256((tmp_path / "store.py").read_bytes()).hexdigest() == v.attestation["payload"]["sha256"]
    # Everything outside the method's own lines survives verbatim.
    for untouched in ("    def total(self) -> int:\n        return sum(self.items)\n",
                      "    limit = 10\n", "def helper() -> int:\n    return 1\n",
                      '    """Store of non-negative integers."""\n'):
        assert untouched in source

    gone = kernel.commit(sid, "store", patch=[{"op": "delete_symbol", "name": "Repo.largest"}])
    assert gone.accepted, gone.error
    source = (tmp_path / "store.py").read_text(encoding="utf-8")
    assert "def largest" not in source and "def mean(self) -> float:" in source
    assert kernel.checkout(sid, "store", focus=["Repo.mean"]).rendered().count("def mean(") == 1


def test_dotted_method_patch_keeps_the_rest_of_the_frame_skeletal_in_the_telemetry(kernel, tmp_path):
    _write(tmp_path, {"store.py": CLASSY})
    sid = kernel.init_session(tmp_path)
    before = kernel.get_telemetry(sid)
    kernel.checkout(sid, "store", focus=["Repo.total"])
    after = kernel.get_telemetry(sid)
    charged = after.compacted_okf_tokens - before.compacted_okf_tokens
    whole = kernel.checkout(sid, "store", focus=["Repo"]).token_count
    assert 0 < charged < whole


# ------------------------------ 2. contiguous multi-definition symbol spans

OVERLOADS = '''\
from typing import overload


@overload
def parse(value: int) -> int: ...
@overload
def parse(value: str) -> str: ...
def parse(value):
    """Implementation shared by the stubs above."""
    if value is None:
        raise ValueError("none")
    return value


class Box:
    def __init__(self) -> None:
        self._w = 1

    @property
    def width(self) -> int:
        return self._w

    @width.setter
    def width(self, value: int) -> None:
        if value <= 0:
            raise ValueError(value)
        self._w = value

    def area(self) -> int:
        return self._w * self._w


def unrelated() -> int:
    return 0
'''


def test_replace_symbol_on_an_overload_chain_addresses_the_whole_group(kernel, tmp_path):
    _write(tmp_path, {"shapes.py": OVERLOADS})
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(sid, "shapes", patch=_replace(
        "parse",
        "@overload\ndef parse(value: int) -> int: ...\n"
        "@overload\ndef parse(value: str) -> str: ...\n"
        "@overload\ndef parse(value: bytes) -> bytes: ...\n"
        "def parse(value):\n"
        '    """Implementation shared by the stubs above."""\n'
        "    if value is None:\n        raise ValueError(\"none\")\n"
        "    return value\n",
    ))
    assert v.accepted, v.error
    source = (tmp_path / "shapes.py").read_text(encoding="utf-8")
    assert source.count("def parse(") == 4  # was: 5 — only the first stub was replaced, the old group stayed
    assert source.count("@overload") == 3
    assert "def unrelated() -> int:\n    return 0\n" in source


def test_delete_symbol_on_an_overload_chain_removes_every_definition(kernel, tmp_path):
    _write(tmp_path, {"shapes.py": OVERLOADS})
    sid = kernel.init_session(tmp_path)
    v = kernel.commit(sid, "shapes", patch=[{"op": "delete_symbol", "name": "parse"}], allow_deletion=True)
    assert v.accepted, v.error
    source = (tmp_path / "shapes.py").read_text(encoding="utf-8")
    assert "def parse(" not in source and "@overload" not in source  # was: two stubs left behind
    assert "class Box:" in source and "from typing import overload" in source


def test_property_pair_is_one_dotted_symbol_and_its_setter_is_preserved(kernel, tmp_path):
    _write(tmp_path, {"shapes.py": OVERLOADS})
    sid = kernel.init_session(tmp_path)
    preserved = _node(kernel, sid, "shapes")["preserved_symbols"]
    assert any("width.setter" in s and "Box.width" in s for s in preserved), preserved

    pair = kernel.commit(sid, "shapes", patch=_replace(
        "Box.width",
        "@property\ndef width(self) -> int:\n    return self._w\n\n"
        "@width.setter\ndef width(self, value: int) -> None:\n"
        "    if value <= 0:\n        raise ValueError(value)\n"
        "    self._w = int(value)\n",
    ))
    assert pair.accepted, pair.error
    source = (tmp_path / "shapes.py").read_text(encoding="utf-8")
    assert source.count("def width(") == 2 and "self._w = int(value)" in source
    assert "    def area(self) -> int:\n        return self._w * self._w\n" in source

    dropped = kernel.commit(sid, "shapes", patch=_replace(
        "Box.width", "@property\ndef width(self) -> int:\n    return self._w\n"
    ))
    assert not dropped.accepted and dropped.gate == "B", dropped.error
    assert "width.setter" in str(dropped.error)


# -------------------------- 3. Gate C trace hook survives runaway recursion

MUTUAL = '''\
def a(n: int) -> int:
    if n < 0:
        raise ValueError(n)
    return b(n)


def b(n: int) -> int:
    return a(n)


def swallow(n: int) -> int:
    if n < 0:
        raise ValueError(n)
    try:
        return a(n)
    except RecursionError:
        while True:
            pass
'''


def test_runaway_mutual_recursion_is_a_bounded_gate_c_rejection(kernel, tmp_path):
    _write(tmp_path, {"rec.py": MUTUAL})
    sid = kernel.init_session(tmp_path)
    mined = _node(kernel, sid, "rec")["invariants_auto_mined"]
    assert "call:a(n=-1) raises ValueError" in mined and "call:swallow(n=-1) raises ValueError" in mined

    # The guards hold, so a benign append must pass: the invariants call a(-1)
    # and swallow(-1), which raise before recursing.
    ok = kernel.commit(sid, "rec", patch=[{"op": "append", "code": "LIMIT = 1\n"}])
    assert ok.accepted, ok.error

    # Remove a()'s guard: call:a(n=-1) now recurses a -> b -> a without end. The
    # tracer caps the depth itself, RECURSION_HEADROOM frames under CPython's
    # limit, so the trace callback is always entered and the verdict is the
    # budget, not a RecursionError that the staged code could catch.
    started = time.perf_counter()
    v = kernel.commit(sid, "rec", patch=_replace("a", "def a(n: int) -> int:\n    return b(n)\n"))
    elapsed = time.perf_counter() - started
    assert not v.accepted and v.gate == "C" and isinstance(v.error, LogicalError), v.error
    assert "recursion depth" in str(v.error) and elapsed < 10, (v.error, elapsed)

    # The hook is intact afterwards: a plain runaway loop is still cut off.
    v3 = kernel.commit(sid, "rec", patch=_replace("a", "def a(n: int) -> int:\n    while True:\n        pass\n"))
    assert not v3.accepted and "budget" in str(v3.error).lower()


LAUNDER = '''\
def check(n: int) -> int:
    if n < 0:
        raise ValueError(n)
    return n
'''


def test_budget_exception_cannot_be_laundered_into_the_expected_exception(kernel, tmp_path):
    # Pre-fix: the budget was a RuntimeError, so `except Exception: raise ValueError`
    # turned a runaway loop into a *passing* `call:check(n=-1) raises ValueError`.
    _write(tmp_path, {"chk.py": LAUNDER})
    sid = kernel.init_session(tmp_path)
    assert _node(kernel, sid, "chk")["invariants_auto_mined"] == ["call:check(n=-1) raises ValueError"]
    started = time.perf_counter()
    v = kernel.commit(sid, "chk", patch=_replace(
        "check",
        "def check(n: int) -> int:\n"
        "    try:\n        while True:\n            pass\n"
        "    except Exception:\n        raise ValueError(n)\n",
    ))
    assert time.perf_counter() - started < 10
    assert not v.accepted and v.gate == "C" and "budget" in str(v.error).lower(), v.error


# --------------- 3b. miner: a later guard shadowed by an untyped earlier guard

WINDOWED = '''\
def windowed(seq, n, step=1):
    if n < 0:
        raise ValueError("n must be >= 0")
    if step < 1:
        raise ValueError("step must be >= 1")
    return list(seq)[:n:step]
'''


def test_miner_skips_a_guard_its_untyped_predecessor_would_trip_first(kernel, tmp_path):
    # more_itertools.windowed on the real corpus: the mined call for the `step`
    # guard mocked the untyped `n` as None, so `None < 0` raised TypeError in the
    # first guard and every valid edit to the module was rejected at Gate C.
    _write(tmp_path, {"win.py": WINDOWED})
    sid = kernel.init_session(tmp_path)
    assert _node(kernel, sid, "win")["invariants_auto_mined"] == ["call:windowed(seq=None, n=-1) raises ValueError"]
    ok = kernel.commit(sid, "win", patch=[{"op": "append", "code": "LIMIT = 1\n"}])
    assert ok.accepted, ok.error


# ------------------------------- 4. in-toto Statement v1 provenance export


def test_provenance_is_an_in_toto_statement_in_a_dsse_envelope(kernel, project):
    sid = kernel.init_session(project)
    v = kernel.commit(sid, "billing", patch=[{"op": "append", "code": "def _h() -> int:\n    return 1\n"}])
    assert v.accepted

    env = kernel.provenance(sid, "billing")
    assert env["payloadType"] == "application/vnd.in-toto+json"
    statement = json.loads(base64.b64decode(env["payload"]))
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"].startswith("https://")
    [subject] = statement["subject"]
    assert subject["name"].replace("\\", "/").endswith("billing.py")
    assert subject["digest"]["sha256"] == hashlib.sha256((project / "billing.py").read_bytes()).hexdigest()
    pred = statement["predicate"]
    assert pred["gates"] == {"A": "pass", "B": "pass", "C": "pass"}
    assert "@require_auth" in pred["preserved_symbols"] and pred["turn"] == v.attestation["payload"]["turn"]
    assert any(inv.startswith("call:charge(") for inv in pred["invariants_executed"])
    assert env["signatures"][0]["keyid"] and len(env["signatures"][0]["sig"]) == 64


def test_provenance_is_deterministic_across_kernels_and_rehydration(kernel, project):
    sid = kernel.init_session(project)
    assert kernel.commit(sid, "billing", patch=[{"op": "append", "code": "LIMIT = 1\n"}]).accepted
    first = kernel.provenance(sid, "billing")
    again = StateKernel().provenance(sid, "billing")  # rehydrated from disk
    assert again == first
    with pytest.raises(KeyError):
        kernel.provenance(sid, "unrelated_sibling")  # never committed: no attestation to export


# ------------------------------------------- 5. `stepcheck llms` (llmstxt.org)


def test_llms_txt_is_generated_from_repo_facts_only(tmp_path, capsys):
    rc = cli.main(["llms", "--out", str(tmp_path)])
    assert rc == 0, capsys.readouterr().out
    llms = (tmp_path / "llms.txt").read_text(encoding="utf-8")
    full = (tmp_path / "llms-full.txt").read_text(encoding="utf-8")

    lines = llms.splitlines()
    assert lines[0] == "# StepCheck Dev"
    assert any(ln.startswith("> ") for ln in lines[1:4])
    sections = [ln for ln in lines if ln.startswith("## ")]
    assert {"## Kernel seams", "## Benchmarks", "## Quickstart", "## Optional"} <= set(sections)
    assert all("](https://" in ln for ln in lines if ln.startswith("- ["))

    results = json.loads((REPO / "benchmarks" / "results.json").read_text(encoding="utf-8"))["final"]
    assert f"{results['savings_pct']}%" in llms
    assert f"{results['raw_bloated_tokens']:,}" in llms and f"{results['compacted_okf_tokens']:,}" in llms
    assert "# StepCheck Dev" in full and "GLOSSARY" in full and "## Security model" in full


def test_llms_generation_is_byte_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    assert cli.main(["llms", "--out", str(a)]) == 0 and cli.main(["llms", "--out", str(b)]) == 0
    for name in ("llms.txt", "llms-full.txt"):
        assert (a / name).read_bytes() == (b / name).read_bytes()
