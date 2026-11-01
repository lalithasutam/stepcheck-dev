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
    def __init__(self, sources: dict[str, str]):
        self.sources = sources

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.sources:
            return importlib.machinery.ModuleSpec(fullname, self, origin=f"<okf:{fullname}>")
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        exec(compile(self.sources[module.__name__], module.__spec__.origin, "exec"), module.__dict__)


def load_namespace(node_id: str, source: str, project_sources: dict[str, str]) -> dict:
    """Return the module namespace of `source` with project imports resolved."""
    sources = dict(project_sources)
    sources[node_id] = source
    finder = _CanonicalFinder(sources)
    shadowed = {name: sys.modules.pop(name) for name in list(sys.modules) if name in sources}
    sys.meta_path.insert(0, finder)
    try:
        module = types.ModuleType(node_id)
        module.__file__ = f"<okf:{node_id}>"
        sys.modules[node_id] = module
        exec(compile(source, module.__file__, "exec"), module.__dict__)
        return dict(module.__dict__)
    finally:
        sys.meta_path.remove(finder)
        for name in sources:
            sys.modules.pop(name, None)
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
