"""ContextCompactor — assembles the compact checkout payload. Private to StateKernel.

Three concerns, each a deterministic function of the session's canonical sources:

* dependency slicing — an in-package dependency's interface skeleton is scoped to
  the symbols the checked-out module imports from it (``from dep import A`` or
  ``import dep`` + ``dep.Attr``), narrowed further under a non-empty focus to what
  the focused definitions or the module header reference; docstrings are
  stripped, annotations, defaults, return types and decorators kept, and a
  ``# + N unimported symbols elided from <dep>`` line records the rest;
* the scope of a focus — which statements count as "referenced" by it, shared
  with the two-tier body skeleton in ``_okf.skeleton``;
* the token-budget backstop — progressive elision of unreferenced sibling method
  signatures, then of dependency stubs the focus does not reference; never the
  focused symbol, never a top-level public name of an unfocused frame.
"""
from __future__ import annotations

import ast
import re

from . import _okf

ELISION = "# + {n} unimported symbols elided from {dep}\n"
_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SYMBOLS = _DEFS + (ast.ClassDef,)
_METHOD_RE = re.compile(r"(?m)^[ \t]+(?:async )?def ")


def scope_nodes(tree: ast.Module, focus: list[str] | None) -> list[ast.AST] | None:
    """The statements a non-empty focus makes relevant: the module header (every
    top-level statement that is neither an import nor a definition, plus the
    decorators and bases of every top-level definition) and the focused
    definitions themselves (a dotted focus also brings its class header).
    None when nothing narrows the view (focus None or [])."""
    if not focus:
        return None
    nodes: list[ast.AST] = []
    for stmt in tree.body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(stmt, _SYMBOLS):
            nodes.extend(stmt.decorator_list)
            if isinstance(stmt, ast.ClassDef):
                nodes.extend(stmt.bases)
                nodes.extend(k.value for k in stmt.keywords)
        else:
            nodes.append(stmt)
    for name in focus:
        _body, group = _okf._resolve_symbol(tree, name)
        nodes.extend(group)
        if "." in name:
            owner = next((s for s in tree.body if isinstance(s, ast.ClassDef) and s.name == name.split(".")[0]), None)
            if owner is not None:
                nodes.extend(owner.decorator_list)
                nodes.extend(owner.bases)
    return nodes


def interface_for(source: str, keep: set[str], dep: str) -> tuple[str, int]:
    """Signature-only view of the top-level definitions in `keep` (decorators,
    annotations, defaults and return types kept; docstrings stripped) followed by
    one elision line for the definitions left out. Returns (text, elided)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return "", 0
    parts: list[str] = []
    elided = 0
    for stmt in tree.body:
        if not isinstance(stmt, _SYMBOLS):
            continue
        if stmt.name not in keep:
            elided += 1
            continue
        if isinstance(stmt, ast.ClassDef):
            # a dependency's interface is its public surface: `_private` methods
            # (dunders excepted) are implementation and stay out
            public = {m.name for m in stmt.body if isinstance(m, _DEFS)
                      and (not m.name.startswith("_") or m.name.startswith("__"))}
            parts.append(_okf._skeleton_class(stmt, doc=None, method_doc=None, keep_methods=public))
        else:
            parts.append(_okf._skeleton_def(stmt, doc=None))
    text = "\n".join(parts)
    if elided:
        if text and not text.endswith("\n"):
            text += "\n"
        text += ELISION.format(n=elided, dep=dep)
    return text, elided


def _symbol_count(source: str) -> int:
    try:
        return sum(1 for s in ast.parse(source).body if isinstance(s, _SYMBOLS))
    except SyntaxError:
        return 0


class ContextCompactor:
    """Payload assembly for one checkout: dependency skeletons scoped to the
    importing module (and its focus), and the budget backstop. Scoping and the
    backstop read the Python AST; a TypeScript/JavaScript module (or dependency)
    gets its language-aware interface skeleton unscoped instead."""

    def __init__(self, info, deps: dict[str, object], modules: dict[str, str], focus: list[str] | None):
        self.info = info
        self.deps = deps
        self.focus = focus
        self.python = _okf.language(info.path) == "python"
        if self.python:
            self.tree = ast.parse(info.source)
            self.records = _okf._import_records(info.node_id, info.path, self.tree, modules)
            self.scope = scope_nodes(self.tree, focus)
        else:
            self.tree = None
            self.records = []
            self.scope = None
        self.kept: dict[str, set[str]] = {}
        self.elided_counts: dict[str, int] = {}

    def keep_for(self, dep: str) -> set[str]:
        """Symbols of `dep` the payload must show: the names this module imports
        from it by name, plus attributes read off a module-object import; under a
        non-empty focus, only those the focused definitions or header use."""
        nodes = self.scope if self.scope is not None else [self.tree]
        used = _okf._names_in(nodes)
        keep: set[str] = set()
        aliases: set[str] = set()
        for nid, name, local in self.records:
            if nid != dep:
                continue
            if name is None:
                if local:
                    aliases.add(local)
            elif self.scope is None or (local or name) in used:
                keep.add(name)
        if aliases:
            for node in nodes:
                for n in ast.walk(node):
                    if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in aliases:
                        keep.add(n.attr)
        return keep

    def dependency_skeletons(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for dep in self.info.deps:
            if dep not in self.deps:
                continue
            dep_info = self.deps[dep]
            if not self.python or _okf.language(dep_info.path) != "python":
                out[dep] = _okf.interface_skeleton(dep_info.source)  # language-aware, unscoped
                self.kept[dep] = set()
                self.elided_counts[dep] = 0
                continue
            keep = self.keep_for(dep)
            self.kept[dep] = keep
            text, n = interface_for(dep_info.source, keep, dep)
            self.elided_counts[dep] = n
            out[dep] = text
        return out

    def fit(self, frame: str, dep_skeletons: dict[str, str], invariants: list[str], budget: int,
            count, render, focus: list[str] | None = None) -> tuple[str, dict[str, str], list[str]]:
        """Bring the payload under `budget`: first drop the unreferenced sibling
        method signatures (the focused symbol, `__init__` and methods the focus
        uses stay; on an unfocused frame every top-level public name stays), then
        replace the interface stubs of dependencies the focus does not reference
        with their elision line, largest first. Returns the new frame, the new
        dependency skeletons and a list naming what was elided (empty when nothing
        had to go). A TypeScript frame is returned as is."""
        focus = self.focus if focus is None else focus
        elided: list[str] = []
        if focus is None or not self.python:
            return frame, dep_skeletons, elided
        tokens = count(render(frame, dep_skeletons, invariants))
        if tokens < budget:
            return frame, dep_skeletons, elided

        head, rest = frame.split("```python\n", 1)
        old_body, tail = rest.rsplit("```", 1)
        new_body = _okf.skeleton(self.info.source, focus, elide_methods=True)
        dropped = len(_METHOD_RE.findall(old_body)) - len(_METHOD_RE.findall(new_body))
        if dropped > 0:
            frame = head + "```python\n" + new_body + "```" + tail
            elided.append(f"{dropped} unreferenced method signatures")
            tokens = count(render(frame, dep_skeletons, invariants))

        dep_skeletons = dict(dep_skeletons)
        for dep in sorted(dep_skeletons, key=lambda d: -len(dep_skeletons[d])):
            if tokens < budget:
                break
            if self.scope is not None and self.kept.get(dep):
                continue  # the focus uses this dependency: its stub stays
            if dep in self.deps and _okf.language(self.deps[dep].path) != "python":
                continue  # a TypeScript dependency carries its plain interface
            total = _symbol_count(self.deps[dep].source) if dep in self.deps else 0
            stub = ELISION.format(n=total, dep=dep)
            if dep_skeletons[dep] == stub:
                continue
            dep_skeletons[dep] = stub
            elided.append(f"dependency {dep} interface stub")
            tokens = count(render(frame, dep_skeletons, invariants))

        if elided:
            note = f"Budget backstop ({budget:,} tokens): elided {', '.join(elided)}.\n\n"
            frame = frame.replace("```python\n", note + "```python\n", 1)
        return frame, dep_skeletons, elided
