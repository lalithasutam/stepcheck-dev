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
    by_node = dict(project_sources)
    by_node[node_id] = source
    if paths:
        names = _okf.module_map({nid: p for nid, p in paths.items() if nid in by_node})
    else:
        names = {nid: nid for nid in by_node}
    sources = {name: by_node[nid] for name, nid in names.items()}
    target = _okf.module_name(paths[node_id]) if node_id in paths else node_id
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


class ExecutionBudgetExceeded(RuntimeError):
    """Raised inside the guarded code by the trace hook."""


def guarded(fn, *, steps: int = STEP_BUDGET, seconds: float = WALL_BUDGET_SECONDS):
    """Run `fn()` under a per-thread trace hook that aborts at `steps` line
    events or `seconds` of wall clock, whichever first. Deterministic on the
    step axis; the clock is a backstop. Recursion depth is left to Python's
    own RecursionError. Thread-local: sys.settrace affects this thread only."""
    import time

    deadline = time.monotonic() + seconds
    count = 0

    def tracer(frame, event, arg):
        nonlocal count
        if event == "line":
            count += 1
            if count > steps:
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
