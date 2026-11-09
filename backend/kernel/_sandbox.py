"""Isolated module namespace loading for callable invariants. Private.

`load_namespace()` exec-loads one module's staged source into a fresh dict.
Imports of *project* modules resolve to the kernel's canonical sources (never
to the files on disk, which only change once a commit has passed) through a temporary
meta-path finder; everything else imports normally. This is an isolated
namespace, not a security sandbox — invariants run the agent's own code.
"""
from __future__ import annotations

import importlib.abc
import importlib.machinery
import importlib.util
import sys
import types

_PREFIX = "_stepcheck_ns_"


class _CanonicalFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Serves project modules — flat or inside packages — from canonical sources."""

    def __init__(self, sources: dict[str, str], packages: set[str]):
        self.sources = sources
        self.packages = packages

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.sources:
            return importlib.machinery.ModuleSpec(
                fullname, self, origin=f"<okf:{fullname}>", is_package=fullname in self.packages
            )
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        origin = module.__spec__.origin
        module.__file__ = origin
        exec(compile(self.sources[module.__name__], origin, "exec"), module.__dict__)


class _OnDemand(dict):
    """A dict of texts whose values are fetched from `backing` on first access. `extra`
    holds eager entries; `alias` maps this dict's keys (import names) to `backing` keys
    (node ids). Membership and iteration never fetch a value."""

    def __init__(self, backing, extra: dict, alias: dict | None = None) -> None:
        super().__init__()
        self._backing, self._alias = backing, alias
        self._keys = set(alias) if alias is not None else set(backing)
        for k, v in extra.items():
            dict.__setitem__(self, k, v)
            self._keys.add(k)

    def _fetch(self, key):
        src_key = self._alias[key] if self._alias is not None else key
        value = self._backing[src_key]
        dict.__setitem__(self, key, value)
        return value

    def __contains__(self, key) -> bool:
        return key in self._keys

    def __iter__(self):
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)

    def keys(self):
        return iter(self._keys)

    def __getitem__(self, key):
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        if key not in self._keys:
            raise KeyError(key)
        return self._fetch(key)

    def get(self, key, default=None):
        return self[key] if key in self._keys else default

    def setdefault(self, key, default=None):
        if key in self._keys:
            return self[key]
        dict.__setitem__(self, key, default)
        self._keys.add(key)
        return default

    def items(self):
        for k in list(self._keys):
            yield k, self[k]


def load_namespace(
    node_id: str,
    source: str,
    project_sources: dict[str, str],
    project_paths: dict[str, str] | None = None,
) -> dict:
    """Return the module namespace of `source` with project imports resolved.

    `project_paths` (node_id -> file path) turns node ids into import names
    through _okf.module_map, so `pkg/__init__.py` loads as package `pkg`,
    `from . import sibling` inside it resolves to the sibling's canonical
    source, and source-root aliases work too: `from kernel import X` inside
    `backend/server.py` binds the canonical `backend/kernel/__init__.py`, not
    whatever sys.path holds. Parents without their own `__init__.py` become
    empty namespace packages. Without paths every node is a flat top-level
    module named after its id. Real modules that share a name are shadowed
    only while loading and restored afterwards."""
    from . import _okf

    paths = dict(project_paths or {})
    by_node = _OnDemand(project_sources, {node_id: source})  # each module's text is read only when imported
    if paths:
        names = _okf.module_map({nid: p for nid, p in paths.items() if nid in by_node})
    else:
        names = {nid: nid for nid in by_node}
    sources = _OnDemand(by_node, {}, alias=names)
    target = _okf.rooted_name(paths[node_id]) if node_id in paths else node_id
    sources.setdefault(target, source)
    inits = {
        nid for nid, p in paths.items() if p.replace("\\", "/").rsplit("/", 1)[-1] == "__init__.py"
    }
    packages = {name for name, nid in names.items() if nid in inits}
    for mod in list(sources):
        parts = mod.split(".")
        for i in range(1, len(parts)):
            prefix = ".".join(parts[:i])
            packages.add(prefix)
            sources.setdefault(prefix, "")

    def owned(modname: str) -> bool:
        return modname in sources or any(modname.startswith(p + ".") for p in packages)

    finder = _CanonicalFinder(sources, packages)
    shadowed = {n: sys.modules.pop(n) for n in list(sys.modules) if owned(n)}
    sys.meta_path.insert(0, finder)
    try:
        module = importlib.import_module(target)
        return dict(module.__dict__)
    finally:
        sys.meta_path.remove(finder)
        for n in list(sys.modules):
            if owned(n):
                del sys.modules[n]
        sys.modules.update(shadowed)


# -------------------------------------------------------- execution guard

STEP_BUDGET = 200_000      # Python line events
WALL_BUDGET_SECONDS = 0.5  # fallback for work that emits few line events


class ExecutionBudgetExceeded(BaseException):
    """Raised inside the guarded code by the trace hook. A BaseException on
    purpose: the staged code's own `except Exception:` cannot swallow the budget
    and keep running."""


def guarded(fn, *, steps: int | None = STEP_BUDGET, seconds: float = WALL_BUDGET_SECONDS):
    """Run `fn()` under a per-thread trace hook that aborts at `steps` line
    events or `seconds` of wall clock, whichever first. Deterministic on the
    step axis; the clock is a backstop. `steps=None` keeps only the clock —
    the right budget for *loading* a staged module, where a real package
    legitimately executes far more line events than any invariant call.
    Recursion is capped by the hook itself, RECURSION_HEADROOM frames below
    `sys.getrecursionlimit()`: a RecursionError raised while CPython enters the
    trace function makes it drop the hook silently, after which the staged code
    could catch the RecursionError and run unguarded. Thread-local:
    sys.settrace affects this thread only."""
    import time

    deadline = time.monotonic() + seconds
    count = 0
    depth = 0
    frame, base = sys._getframe(), 0
    while frame is not None:
        base += 1
        frame = frame.f_back
    max_depth = max(sys.getrecursionlimit() - RECURSION_HEADROOM - base, RECURSION_HEADROOM)

    def tracer(frame, event, arg):
        nonlocal count, depth
        if event == "call":
            depth += 1
            if depth > max_depth:
                raise ExecutionBudgetExceeded(f"exceeded recursion depth {max_depth:,}")
        elif event == "return":
            depth -= 1
        elif event == "line":
            count += 1
            if steps is not None and count > steps:
                raise ExecutionBudgetExceeded(f"exceeded {steps:,} execution steps")
            if time.monotonic() > deadline:
                raise ExecutionBudgetExceeded(f"exceeded {seconds:.1f}s wall clock")
        return tracer

    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        return fn()
    finally:
        sys.settrace(previous)


IMPORT_WALL_BUDGET_SECONDS = 5.0  # loading a staged module: clock only, no step cap


RECURSION_HEADROOM = 64  # frames kept free under sys.getrecursionlimit() so the tracer itself can always run
