"""Slice 15 — hardening from the wild-corpus evaluation (387 files from pytest,
uvicorn, fastapi, pydantic, starlette, click, httpx, anyio): conditional bindings
are exports too, decorators are fingerprinted per symbol, `_private` functions
another module imports are part of its contract, Gate C budgets import time by
wall clock only, and the guard miner handles flexible signatures (Seam 1)."""
import time
from pathlib import Path

import pytest

from kernel import LogicalError, MechanicalError, OmissionError, StateKernel


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return root


def _node(kernel, sid, nid) -> dict:
    return next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == nid)


def _replace(name: str, code: str) -> list[dict]:
    return [{"op": "replace_symbol", "name": name, "code": code}]


APPEND = [{"op": "append", "code": "def _probe() -> int:\n    return 1\n"}]


# -------------------------------- 1. Gate A: names bound inside if / try / with

SHIM = '''\
import contextlib
import sys

try:
    from json import loads as parse
except ImportError:  # pragma: no cover
    def parse(text: str) -> dict:
        return {}

if sys.version_info >= (3, 8):
    def feature() -> str:
        return "new"
else:
    def feature() -> str:
        return "old"

with contextlib.suppress(ImportError):
    from json import dumps as render
'''

USES_SHIM = '''\
from shim import feature, parse, render


def go(text: str) -> str:
    return render(parse(text)) + feature()
'''


def test_version_shims_bound_in_try_if_with_are_exports(kernel, tmp_path):
    _write(tmp_path, {"shim.py": SHIM, "use.py": USES_SHIM})
    sid = kernel.init_session(tmp_path)
    assert _node(kernel, sid, "use")["deps"] == ["shim"]

    ok = kernel.commit(sid, "shim", patch=APPEND)
    assert ok.accepted, ok.error  # was: Gate A "export 'feature' ... missing from the staged source"

    # Still a contract: dropping the whole try block takes `parse` away from `use`.
    gone = kernel.commit(sid, "shim", source=SHIM.split("try:")[0] + SHIM.split("        return {}\n")[1])
    assert not gone.accepted and gone.gate == "A" and isinstance(gone.error, MechanicalError)
    assert "parse" in str(gone.error) and "use" in str(gone.error)


# ------------------------------------- 2. Gate B: decorators per symbol

FIXTURES = '''\
from dataclasses import dataclass


def fixture(fn):
    return fn


@fixture
def db() -> dict:
    return {}


@fixture
def client() -> dict:
    return {"db": db()}


@dataclass
class Point:
    x: int = 0
'''


def test_dropping_a_decorator_another_function_still_carries_is_an_omission(kernel, tmp_path):
    _write(tmp_path, {"conftest_like.py": FIXTURES})
    sid = kernel.init_session(tmp_path)
    preserved = _node(kernel, sid, "conftest_like")["preserved_symbols"]
    assert "@fixture" in preserved  # the module-level fingerprint stays
    assert any("fixture" in s and "client" in s for s in preserved), preserved
    assert any("dataclass" in s and "Point" in s for s in preserved), preserved

    bare = kernel.commit(sid, "conftest_like", patch=_replace(
        "client", 'def client() -> dict:\n    return {"db": db(), "fresh": True}\n'
    ))
    assert not bare.accepted and bare.gate == "B", bare.error  # was: accepted, `db` still carries @fixture
    assert isinstance(bare.error, OmissionError) and bare.error.subtype == "INTRA_NODE_SYMBOL_DROPPED"
    assert "@fixture" in str(bare.error) and "client" in str(bare.error)

    kept = kernel.commit(sid, "conftest_like", patch=_replace(
        "client", '@fixture\ndef client() -> dict:\n    return {"db": db(), "fresh": True}\n'
    ))
    assert kept.accepted, kept.error

    plain_class = kernel.commit(sid, "conftest_like", patch=_replace(
        "Point", "class Point:\n    x: int = 0\n"
    ))
    assert not plain_class.accepted and plain_class.gate == "B" and "Point" in str(plain_class.error)


# ----------------------------- 3. `_private` functions another module imports

CORE = '''\
def _normalize(value: str) -> str:
    return value.strip()


def _unused(value: str) -> str:
    return value


def public(value: str) -> str:
    return _normalize(value)
'''

API = '''\
from core import _normalize


def handle(value: str) -> str:
    return _normalize(value)
'''

OTHER = '''\
from core import public


def go() -> str:
    return public(" x ")
'''


def test_arity_change_of_an_imported_private_function_dirties_its_importer(kernel, tmp_path):
    _write(tmp_path, {"core.py": CORE, "api.py": API, "other.py": OTHER})
    sid = kernel.init_session(tmp_path)

    unrelated = kernel.commit(sid, "core", patch=_replace(
        "_unused", "def _unused(value: str, times: int) -> str:\n    return value * times\n"
    ))
    assert unrelated.accepted and unrelated.dirtied == []  # nobody imports `_unused`

    v = kernel.commit(sid, "core", patch=_replace(
        "_normalize", "def _normalize(value: str, strip: bool) -> str:\n    return value.strip() if strip else value\n"
    ))
    assert v.accepted, v.error
    assert v.dirtied == ["api"]  # was: [] — `_normalize` is not an export, so nobody was dirtied
    assert _node(kernel, sid, "api")["status"] == "DIRTY_OMISSION_RISK"
    assert _node(kernel, sid, "other")["status"] != "DIRTY_OMISSION_RISK"
    with pytest.raises(OmissionError, match="DIRTY_OMISSION_RISK"):
        kernel.finalize_session(sid)

    fixed = kernel.commit(sid, "api", patch=_replace(
        "handle", "def handle(value: str) -> str:\n    return _normalize(value, True)\n"
    ))
    assert fixed.accepted and kernel.finalize_session(sid) is True


# --------------------------- 4a. Gate C: import time is bounded by the clock only

HEAVY = '''\
_TABLE = {}
for _i in range(300_000):
    _TABLE[_i % 7] = _i


def lookup(key: int) -> int:
    if key < 0:
        raise ValueError("negative")
    return _TABLE[key % 7]
'''


def test_import_time_work_beyond_the_step_budget_still_loads_for_invariants(kernel, tmp_path):
    _write(tmp_path, {"heavy.py": HEAVY})
    sid = kernel.init_session(tmp_path)
    assert "call:lookup(key=-1) raises ValueError" in _node(kernel, sid, "heavy")["invariants_auto_mined"]

    ok = kernel.commit(sid, "heavy", patch=APPEND)
    assert ok.accepted, ok.error  # was: "blew the Gate C execution budget while loading"

    # The invariant call itself keeps the 200k-step budget.
    spin = kernel.commit(sid, "heavy", patch=_replace(
        "lookup", "def lookup(key: int) -> int:\n    while True:\n        pass\n    if key < 0:\n        raise ValueError(\"negative\")\n    return 0\n"
    ))
    assert not spin.accepted and spin.gate == "C" and isinstance(spin.error, LogicalError)


def test_runaway_import_is_still_cut_off_by_the_wall_clock(kernel, tmp_path):
    _write(tmp_path, {"spin.py": "def f(x: int) -> int:\n    if x < 0:\n        raise ValueError(x)\n    return x\n"})
    sid = kernel.init_session(tmp_path)
    started = time.perf_counter()
    v = kernel.commit(sid, "spin", source="while True:\n    pass\n\n\ndef f(x: int) -> int:\n    if x < 0:\n        raise ValueError(x)\n    return x\n")
    assert time.perf_counter() - started < 30
    assert not v.accepted and v.gate == "C" and "import" in str(v.error).lower()


# ------------------------- 4b. miner: flexible signatures, `is None`, `not x`

FLEX = '''\
def connect(host: str | None = None, *, timeout: float, **options) -> dict:
    if host is None:
        raise ValueError("host required")
    return {"host": host, "timeout": timeout, **options}


def batch(items: list, *args) -> int:
    if not items:
        raise ValueError("empty")
    return len(items) + len(args)


def cfg(config=None, /, **kwargs) -> dict:
    if config is None:
        raise TypeError("config")
    return dict(config, **kwargs)
'''


def test_guards_on_flexible_signatures_are_mined_and_enforced(kernel, tmp_path):
    _write(tmp_path, {"flex.py": FLEX})
    sid = kernel.init_session(tmp_path)
    mined = _node(kernel, sid, "flex")["invariants_auto_mined"]
    assert mined == [  # was: [] — any *args / **kwargs / keyword-only / positional-only signature was skipped
        "call:connect(host=None, timeout=1.0) raises ValueError",
        "call:batch(items=[]) raises ValueError",
        "call:cfg(None) raises TypeError",
    ]

    assert kernel.commit(sid, "flex", patch=APPEND).accepted

    weakened = kernel.commit(sid, "flex", patch=_replace(
        "connect",
        "def connect(host: str | None = None, *, timeout: float, **options) -> dict:\n"
        '    host = host or "localhost"\n'
        '    return {"host": host, "timeout": timeout, **options}\n',
    ))
    assert not weakened.accepted and weakened.gate == "C"
    assert "call:connect(host=None, timeout=1.0) raises ValueError" in str(weakened.error)

    # A new required keyword-only parameter gets a typed mock, not a TypeError.
    grown = kernel.commit(sid, "flex", patch=_replace(
        "connect",
        "def connect(host: str | None = None, *, timeout: float, retries: int, **options) -> dict:\n"
        "    if host is None:\n        raise ValueError(\"host required\")\n"
        '    return {"host": host, "timeout": timeout, "retries": retries, **options}\n',
    ))
    assert grown.accepted, grown.error


# ------------------- 5. second corpus pass: lazy exports and generator guards

LAZY = '''\
__all__ = ("Strict", "helper")

_dynamic = {"Strict": ".types"}


def helper() -> int:
    return 1


def __getattr__(name: str):
    if name in _dynamic:
        return name
    raise AttributeError(name)
'''

USES_LAZY = '''\
from lazy import Strict, helper


def go() -> tuple:
    return helper(), Strict
'''


def test_names_served_by_module_getattr_and_all_are_exports(kernel, tmp_path):
    # pydantic/__init__.py: `Strict` exists only in `__all__` + a `__getattr__` import map.
    _write(tmp_path, {"lazy.py": LAZY, "use.py": USES_LAZY})
    sid = kernel.init_session(tmp_path)
    ok = kernel.commit(sid, "lazy", patch=APPEND)
    assert ok.accepted, ok.error  # was: Gate A "export 'Strict' of 'lazy' is required by dependent 'use'"


GENERATOR = '''\
def batched(iterable, n: int):
    if n < 1:
        raise ValueError("n must be at least one")
    buf = []
    for item in iterable:
        buf.append(item)
        if len(buf) == n:
            yield tuple(buf)
            buf = []
    if buf:
        yield tuple(buf)


async def abatched(iterable, n: int):
    if n < 1:
        raise ValueError("n must be at least one")
    for item in iterable:
        yield (item,)
'''


def test_leading_guard_of_a_generator_fires_on_its_first_step(kernel, tmp_path):
    # anyio/itertools.py: `batched` is an async generator — calling it returns the
    # generator without running the guard, so the mined invariant never saw a raise.
    _write(tmp_path, {"gen.py": GENERATOR})
    sid = kernel.init_session(tmp_path)
    assert _node(kernel, sid, "gen")["invariants_auto_mined"] == [
        "call:batched(iterable=None, n=0) raises ValueError",
        "call:abatched(iterable=None, n=0) raises ValueError",
    ]

    ok = kernel.commit(sid, "gen", patch=APPEND)
    assert ok.accepted, ok.error  # was: Gate C false positive on every edit to the module

    unguarded = kernel.commit(sid, "gen", patch=_replace(
        "batched",
        "def batched(iterable, n: int):\n    n = max(n, 1)\n    buf = []\n    for item in iterable:\n"
        "        buf.append(item)\n        if len(buf) == n:\n            yield tuple(buf)\n            buf = []\n"
        "    if buf:\n        yield tuple(buf)\n",
    ))
    assert not unguarded.accepted and unguarded.gate == "C"
