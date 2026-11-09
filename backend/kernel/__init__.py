"""StateKernel — the deep module behind Seam 1 (see GLOSSARY.md).

Public interface, in full:
    StateKernel().init_session(project_root) -> session_id
    .checkout(session_id, node_id)           -> CheckoutPayload
    .commit(session_id, node_id, source, *, allow_deletion=False) -> CommitVerdict
    .lock_node(session_id, node_id)
    .get_telemetry(session_id)               -> Telemetry

Everything in `_`-prefixed modules is implementation, never interface.
"""
from __future__ import annotations

import ast
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import json

from . import _gates, _okf, _telemetry, _tokens


def _sha256(data: str | bytes) -> str:
    import hashlib

    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


_DSSE_PAYLOAD_TYPE = "application/vnd.stepcheck.okf-commit+json"
_DSSE_KEYID = "stepcheck-deterministic-v1"


def _dsse_envelope(node_id: str, path: str, digest: str, exports: list[str], turn: int) -> dict:
    """Deterministic SHA-256 / DSSE-style attestation (GLOSSARY: Gate C).
    `digest` is the SHA-256 of the exact bytes written to the tracked file."""
    import json

    payload = {
        "node_id": node_id,
        "path": path,
        "sha256": digest,
        "exports": list(exports),
        "turn": turn,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return {
        "payloadType": _DSSE_PAYLOAD_TYPE,
        "payload": payload,
        "signatures": [
            {"keyid": _DSSE_KEYID, "sig": _sha256(f"DSSEv1 {_DSSE_PAYLOAD_TYPE} {canonical}")}
        ],
    }

__all__ = [
    "StateKernel",
    "CheckoutPayload",
    "CommitVerdict",
    "Telemetry",
    "GateError",
    "MechanicalError",
    "OmissionError",
    "LogicalError",
]

CHECKOUT_TOKEN_BUDGET = 4000  # hard cap on any CheckoutPayload (GLOSSARY)

ACTIVE = "ACTIVE"
VERIFIED = "VERIFIED"
LOCKED = "LOCKED"
DIRTY = "DIRTY_OMISSION_RISK"
REJECTED = "REJECTED"


class GateError(Exception):
    """Base of every gate rejection."""


class MechanicalError(GateError):
    """Gate A: syntax, broken exported signatures, or locked-module mutation."""


class OmissionError(GateError):
    """Gate B: silent omission detected."""

    def __init__(self, message: str, subtype: str):
        super().__init__(message)
        self.subtype = subtype


class LogicalError(GateError):
    """Gate C: a frame invariant no longer holds. `subtype` is "ENVIRONMENT" when the
    staged module could not be loaded for want of a package this interpreter lacks
    (the probes could not run here; `stepcheck ci` reports such a node apart)."""

    def __init__(self, message: str, subtype: str | None = None):
        super().__init__(message)
        self.subtype = subtype


@dataclass(frozen=True)
class CheckoutPayload:
    session_id: str
    node_id: str
    frame_markdown: str
    dependency_signatures: dict[str, list[str]]
    locked_invariants: list[str]
    token_count: int
    dependency_skeletons: dict[str, str] = field(default_factory=dict)
    focus: list[str] | None = None
    auto_skeletonized: bool = False
    elided: list[str] = field(default_factory=list)  # budget backstop: what the payload dropped
    # Zero-bloat floor: the frame is a one-line pragma over the slice (or the bare
    # source), the rendered payload is that plus the dependency interfaces that fit,
    # and the invariant list is the `locked_invariants` field (StateKernel._assemble).
    pragma: bool = False

    def rendered(self) -> str:
        if self.pragma:
            return _render_payload(self.frame_markdown, self.dependency_skeletons, [])
        return _render_payload(
            self.frame_markdown, self.dependency_skeletons, self.locked_invariants
        )


def _scope_guards(node, nodes, invariants: list[str], focus: list[str] | None, tree) -> tuple[list[str], int]:
    """The invariants a checkout lists, and how many structural `guard:` ones it
    leaves out. A full frame (`focus=None`) lists everything. A focused or skeleton
    frame of a Python module lists the `guard:` invariants of the focused symbols
    (a focused class: all its methods) only — the rest are counted, never dropped
    from Gate C — and a locked dependency's Python guards are counted too. When
    the frame shows the whole module (compact header), every guard is listed."""
    if focus and tree is not None:
        cone = list(focus) + _okf.callee_closure(tree, list(focus), node.info.source)[0]
        if set(_okf.symbol_names(node.info.source)) <= {f for f in cone if "." not in f}:
            focus = None
    if focus is None or _okf.lang_module(node.info.path) is not None:
        return invariants, 0
    effective = list(focus)  # the focus itself: its callees' guards are counted, not listed
    own = set(node.info.invariants)

    def relevant(inv: str) -> bool:
        sym = inv.split(":", 2)[1]
        return any(sym == f or sym.startswith(f + ".") for f in effective)

    kept = [inv for inv in invariants
            if not inv.startswith("guard:") or (inv in own and relevant(inv))]
    return kept, len(invariants) - len(kept)


def _render_payload(frame: str, dep_skeletons: dict[str, str], invariants: list[str]) -> str:
    parts = [frame]
    sections = [
        f"### {dep}\n```python\n{sk}```\n"
        for dep, sk in sorted(dep_skeletons.items())
        # skipped: nothing imported from it is in scope (it is listed under deps: already)
        if not all(line.lstrip().startswith("#") for line in sk.splitlines() if line.strip())
    ]
    if sections:  # empty headings are pure overhead on small, dependency-free modules
        parts += ["\n## Verified dependency interfaces (AST skeletons)\n", *sections]
    if invariants:
        parts.append("\n## Locked invariants\n")
        parts.extend(f"- {inv}\n" for inv in invariants)
    return "".join(parts)


@dataclass(frozen=True)
class CommitVerdict:
    accepted: bool
    gate: str | None
    error: GateError | None
    attestation: dict | None
    dirtied: list[str]
    # Dependents re-run through Gates A/B/C in memory against this commit and
    # re-attested (untouched bytes, contract intact) instead of being dirtied.
    reverified: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Telemetry:
    raw_bloated_tokens: int
    compacted_okf_tokens: int
    tokens_saved: int
    dollars_saved: float
    omissions_blocked: int
    turns: int


class _Node:
    """One tracked module. `info` (the analysis) is built on first use when the node was
    registered lazily — a large repository indexes paths, hashes and import edges only,
    and analyses a module the first time a checkout, a commit or a dependent needs it.
    `path`, `node_id` and `deps` are always available without analysis."""

    __slots__ = ("_info", "_source", "status", "locked", "verified", "disk_sha256", "node_id", "path", "deps",
                 "loader", "source_loader", "unparsable")

    def __init__(self, info: "_okf.ModuleInfo | None" = None, status: str = ACTIVE, locked: bool = False,
                 verified: list[dict] | None = None, disk_sha256: str = "", *, node_id: str = "", path: str = "",
                 deps: list[str] | None = None) -> None:
        self._info = info
        self._source: str | None = None
        self.status = status
        self.locked = locked
        self.verified = list(verified or [])
        self.disk_sha256 = disk_sha256  # SHA-256 of the tracked file as the kernel last saw it
        self.node_id = info.node_id if info is not None else node_id
        self.path = info.path if info is not None else path
        self.deps = list(info.deps) if info is not None else list(deps or [])
        self.loader = None  # () -> ModuleInfo, bound by the kernel for a lazy node
        self.source_loader = None  # () -> str, the held source of a lazy node
        self.unparsable = False

    @property
    def materialized(self) -> bool:
        return self._info is not None

    @property
    def info(self) -> "_okf.ModuleInfo":
        if self._info is None:
            if self.loader is None:
                raise KeyError(f"node '{self.node_id}' is not materialized and has no loader")
            self.info = self.loader()
        return self._info

    @info.setter
    def info(self, value: "_okf.ModuleInfo") -> None:
        self._info = value
        self._source = None
        self.node_id, self.path, self.deps = value.node_id, value.path, list(value.deps)

    @property
    def source(self) -> str:
        """The held source without forcing an analysis."""
        if self._info is not None:
            return self._info.source
        if self._source is None:
            if self.source_loader is None:
                return self.info.source
            self._source = self.source_loader()
        return self._source


LAZY_THRESHOLD = 200  # files; a larger tree is indexed lazily (STEPCHECK_LAZY_THRESHOLD overrides)
LAZY_BYTES = 524_288  # or more tracked source bytes than this (STEPCHECK_LAZY_BYTES overrides)


@dataclass
class _Session:
    session_id: str
    root: Path
    nodes: dict[str, _Node]
    events: list[dict] = field(default_factory=list)
    omissions_blocked: int = 0
    scratchpad: list[dict] = field(default_factory=list)
    # Not persisted: sha256 of what this process last wrote, so unchanged
    # frames / session files are not rewritten.
    frame_shas: dict[str, str] = field(default_factory=dict)
    persisted_sha: str = ""
    # Not persisted either: assembled checkout payloads per (node, focus),
    # cleared by every mutating call (see StateKernel._flush).
    payload_cache: dict = field(default_factory=dict)
    # Not persisted: node -> sha256 of on-disk bytes `sync` already refused, so
    # the same bad bytes are judged (and counted) once, not on every hook call.
    sync_refused: dict = field(default_factory=dict)
    # Not persisted: node -> the verdict string of that refusal (`refusals`).
    sync_reasons: dict = field(default_factory=dict)
    # The git commit the tree was at when the session opened (a lazy node's baseline bytes
    # can be read back from it when the working tree moved on), or None outside git.
    git_head: str | None = None
    # Whether the tree was indexed lazily (every discovered file is a node, analysed on demand).
    lazy: bool = False
    # Not persisted: ((root package, node count), import map) — see StateKernel._modules.
    modules: tuple | None = None
    # Not persisted: st_mtime_ns of the session file when this process last read
    # or wrote it (`refresh_sessions` reloads a session another process rewrote).
    disk_mtime_ns: int = 0


class StateKernel:
    def __init__(self, *, ephemeral: bool = False) -> None:
        """`ephemeral=True` is verification-only (`stepcheck ci`): gates, attestations
        and the graph work in memory, but nothing is written — no frames, session
        files, registry entries, and no tracked-file write-back."""
        self._sessions: dict[str, _Session] = {}
        self._ephemeral = ephemeral

    # -- Seam 1 -----------------------------------------------------------

    def init_session(self, project_root: str | Path) -> str:
        root = Path(project_root).resolve()
        self._point_cache(root)
        files = _okf.tracked_files(root)
        import os

        raws: dict[Path, bytes] = {}
        for p in files:
            raws[p] = p.read_bytes()
        # Lazy when the tree is large by either measure: many files, or few but big ones (a
        # 117-file, 55k-LOC project analysed eagerly costs seconds a first checkout need not pay).
        lazy = (len(files) > int(os.environ.get("STEPCHECK_LAZY_THRESHOLD") or LAZY_THRESHOLD)
                or sum(len(b) for b in raws.values()) > int(os.environ.get("STEPCHECK_LAZY_BYTES") or LAZY_BYTES))
        loaded: dict[Path, tuple[str, bytes]] = {}
        for p, raw in raws.items():
            try:
                text = _okf.decode_source(raw)
            except UnicodeDecodeError:
                continue  # not UTF-8: leave untracked, write-back could not round-trip it
            if _okf.language(str(p)) == "python" and not lazy:
                try:
                    ast.parse(text)
                except (SyntaxError, ValueError, RecursionError, MemoryError):
                    continue  # a newer grammar, or past the parser's limits: untracked, never fatal to the index
            loaded[p] = (text, raw)
        # A flat stem stays the node id while it is unique in the project; stems
        # that collide (several __init__.py, pkg/models.py + other/models.py)
        # use their dotted relative path instead of overwriting each other.
        stems: dict[str, int] = {}
        for p in loaded:
            stems[p.stem] = stems.get(p.stem, 0) + 1
        rel = {p: str(p.relative_to(root)) for p in loaded}
        ids = {
            p: p.stem
            if stems[p.stem] == 1
            else _okf.strip_suffix(rel[p].replace("\\", "/")).replace("/", ".")
            for p in loaded
        }
        modules = _okf.module_map({ids[p]: rel[p] for p in loaded})
        nodes: dict[str, _Node] = {}
        session_id = f"sk-{uuid.uuid4().hex[:12]}"
        session = _Session(session_id=session_id, root=root, nodes=nodes, git_head=_git_head(root) if lazy else None, lazy=lazy)
        dirty_in_git = _git_dirty_paths(root) if (lazy and session.git_head) else None
        for p, (text, raw) in loaded.items():
            if lazy:
                # Lazy: the path, the bytes' hash and the import edges (a line scan for
                # Python, the language module's import resolver otherwise — no analysis) are
                # enough to answer locate / sync / dependents; the analysis waits for the
                # first checkout, commit or dependent that needs it.
                _mod = _okf.lang_module(rel[p])
                if _mod is None:
                    deps = sorted({nid for nid, _n, _l in _okf._records_from(
                        ids[p], rel[p], _okf.regex_import_statements(text), modules)})
                else:
                    deps = sorted(_mod.resolve_imports(ids[p], rel[p], text, modules))
                node = _Node(node_id=ids[p], path=rel[p], disk_sha256=_sha256(raw), deps=deps)
                node._source = text
                if dirty_in_git is None or rel[p].replace("\\", "/") in dirty_in_git:
                    self._keep_blob(root, raw)  # not recoverable from git later: keep the baseline bytes
                nodes[node.node_id] = node
            else:
                info = _okf.analyze(ids[p], rel[p], text, modules)
                nodes[info.node_id] = _Node(info=info, disk_sha256=_sha256(raw))
        self._bind(session)
        self._sessions[session_id] = session
        self._register(session)
        self._flush(session)
        return session_id

    def _bind(self, s: _Session) -> None:
        """Give every lazy node of `s` its loaders (the analysis, and the held source)."""
        for node in s.nodes.values():
            if not node.materialized:
                if node.loader is None:
                    node.loader = (lambda n=node, s=s: self._materialize(s, n))
                if node.source_loader is None:
                    node.source_loader = (lambda n=node, s=s: self._baseline(s, n))

    def _materialize(self, s: _Session, node: _Node) -> _okf.ModuleInfo:
        """Analyse a lazy node now (content cache first); a file this Python cannot parse
        gets an empty analysis and is flagged, so the gates can say why at commit time."""
        self._point_cache(s.root)
        source = node.source
        try:
            return _okf.analyze(node.node_id, node.path, source, self._modules(s))
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            node.unparsable = True
            return _okf.ModuleInfo(node_id=node.node_id, path=node.path, source=source, deps=list(node.deps))

    def _baseline(self, s: _Session, node: _Node) -> str:
        """The source a lazy node holds: the file on disk while its bytes are the ones the
        session saw, else the attested frame, the kept blob, or the git object the tree
        was at when the session opened. When none of those has it, the disk bytes become
        the baseline and the event is recorded."""
        path = s.root / node.path
        try:
            raw = path.read_bytes()
            if _sha256(raw) == node.disk_sha256:
                return _okf.decode_source(raw)
        except (OSError, UnicodeDecodeError):
            raw = None
        frame = s.root / ".stepcheck" / "okf" / f"{node.node_id}.md"
        if node.verified and frame.is_file():
            text = _okf.frame_source(frame.read_text(encoding="utf-8"))
            if text is not None and _sha256(text.encode("utf-8")) == node.verified[-1]["payload"]["sha256"]:
                return text
        blob = s.root / ".stepcheck" / "cache" / "blobs" / node.disk_sha256
        if blob.is_file():
            try:
                return _okf.decode_source(blob.read_bytes())
            except UnicodeDecodeError:
                pass
        if s.git_head:
            shown = _git_show(s.root, s.git_head, node.path)
            if shown is not None and _sha256(shown) == node.disk_sha256:
                return _okf.decode_source(shown)
        s.events.append({"kind": "baseline_lost", "node_id": node.node_id})
        if raw is not None:
            node.disk_sha256 = _sha256(raw)
            return _okf.decode_source(raw)
        return ""

    def _keep_blob(self, root: Path, raw: bytes) -> None:
        if self._ephemeral:
            return
        blob = root / ".stepcheck" / "cache" / "blobs" / _sha256(raw)
        if not blob.exists():
            try:
                _okf.write_atomic(blob, raw)
            except OSError:
                pass

    def node_paths(self, session_id: str) -> dict[str, str]:
        """node_id -> tracked path, for every node, without analysing any of them."""
        return {nid: n.path for nid, n in self._session(session_id).nodes.items()}

    def index_mode(self, session_id: str) -> str:
        """`"lazy"` when the tree was indexed by path, hash and import edges (every discovered
        file is a node, analysed on first use), `"eager"` when every module was analysed at
        indexing (files this Python cannot parse were left out)."""
        return "lazy" if self._session(session_id).lazy else "eager"

    def verify_node(self, session_id: str, node_id: str) -> CommitVerdict:
        """Read-only verification of the bytes a node holds — what `stepcheck ci` runs on a
        module nothing attests: Gate A (it parses; every name a dependent imports from it is
        bound) and the invariants on record, executed: every invariant of an analysed node,
        the hand-written `# okf-invariant:` lines alone of a lazily indexed one (nothing is
        mined for the check — a module's own guards hold against itself by construction).
        Nothing is mutated, no event is recorded, the verdict carries no attestation."""
        s, node = self._get(session_id, node_id)
        self._point_cache(s.root)
        source = node.source
        try:
            tree = _gates.gate_a(node_id, False, source, s.nodes, modules=self._modules(s))
        except (MechanicalError, SyntaxError, RecursionError, MemoryError) as exc:
            return CommitVerdict(accepted=False, gate="A", error=_as_mechanical(exc, node_id), attestation=None, dirtied=[])
        if node.materialized:
            invariants, mined = list(node.info.invariants), list(node.info.mined_invariants)
        else:  # a lazy node has nothing on record; a Python one still carries its hand-written lines
            invariants, mined = (_okf.harvest_invariants(source) if _okf.lang_module(node.path) is None else []), []
        if invariants:
            try:
                _gates.gate_c(node_id, invariants, source, _LazySources(s.nodes, node_id), mined=mined,
                              project_paths={nid: n.path for nid, n in s.nodes.items()},
                              tree=tree if isinstance(tree, ast.Module) else None)
            except LogicalError as exc:
                return CommitVerdict(accepted=False, gate="C", error=exc, attestation=None, dirtied=[])
        return CommitVerdict(accepted=True, gate=None, error=None, attestation=None, dirtied=[])

    def checkout(
        self,
        session_id: str,
        node_id: str,
        *,
        focus: list[str] | None = None,
        at: float | None = None,
    ) -> CheckoutPayload:
        """`focus=None` → full frame. `focus=[names…]` → those defs verbatim,
        the rest of the target as an AST skeleton. `focus=[]` → pure skeleton.
        Read-only on the session: the checkout is charged to telemetry in
        memory and written out by the next mutating call (`commit`, `lock_node`,
        `init_session`) or an explicit `flush()`; the assembled payload is
        memoized per (node, focus) until the session mutates — the warm path a
        lifecycle hook needs on every Read."""
        s, node = self._get(session_id, node_id)
        key = (node_id, None if focus is None else tuple(focus))
        cached = s.payload_cache.get(key)
        if cached is None:
            cached = self._assemble(s, node, focus)
            s.payload_cache[key] = cached
        frame, dep_sigs, invariants, dep_skeletons, tokens, auto, elided, pragma = cached
        s.events.append(
            {
                "kind": "checkout",
                "node_id": node_id,
                "tokens": tokens,
                "full_tokens": _tokens.count(node.info.source),
                "at": at,
            }
        )
        return CheckoutPayload(
            session_id=session_id,
            node_id=node_id,
            frame_markdown=frame,
            dependency_signatures=dict(dep_sigs),
            locked_invariants=list(invariants),
            token_count=tokens,
            dependency_skeletons=dict(dep_skeletons),
            focus=focus,
            auto_skeletonized=auto,
            elided=list(elided),
            pragma=pragma,
        )


    def commit(
        self,
        session_id: str,
        node_id: str,
        source: str | None = None,
        *,
        patch: list[dict] | None = None,
        allow_deletion: bool = False,
        at: float | None = None,
        dry_run: bool = False,
    ) -> CommitVerdict:
        """Stage either a full `source` or a `patch` of AST-level ops folded into
        the node's canonical state, then run Gates A → B → C.

        `dry_run=True` is the pre-write check a lifecycle hook makes before the
        agent's own tool writes the file: the same gates, nothing landed and no
        node state changed; an accepted verdict carries no attestation (the bytes
        are attested when `sync` adopts them). A rejection is still counted and
        logged — the omission was blocked."""
        s, node = self._get(session_id, node_id)
        if (source is None) == (patch is None):
            raise ValueError("commit() takes exactly one of source= or patch=")
        if patch is not None:
            try:
                source = _okf.apply_patch(node.info.source, patch)
            except ValueError as exc:
                return self._reject(s, node, "A", MechanicalError(f"patch cannot fold: {exc}"), dry_run=dry_run)
            sent_tokens = _tokens.count(json.dumps(patch, separators=(",", ":")))
        else:
            sent_tokens = _tokens.count(source)
        assert source is not None
        source = source.replace("\r\n", "\n")  # canonical state is always LF
        self._point_cache(s.root)
        try:
            stitched = _okf.stitch(node.info.source, source) if _okf.lang_module(node.info.path) is None else None
            tree = _gates.gate_a(node_id, node.locked, source, s.nodes, tree=stitched)
        except (MechanicalError, SyntaxError, RecursionError, MemoryError) as exc:
            return self._reject(s, node, "A", _as_mechanical(exc, node_id), dry_run=dry_run)

        staged_tree = tree if isinstance(tree, ast.Module) else None
        staged_info = _okf.analyze(node_id, node.info.path, source, self._modules(s), previous=node.info, tree=staged_tree)
        try:
            _gates.gate_b(node, staged_info, node.info.source, source, allow_deletion, nodes=s.nodes,
                          trees=_shared_trees(node.info.source, tree))
        except OmissionError as exc:
            return self._reject(s, node, "B", exc, dry_run=dry_run)

        # A declared deletion waives the mined guards; hand-written invariants always apply.
        live_invariants = (
            [inv for inv in node.info.invariants if inv not in node.info.mined_invariants]
            if allow_deletion
            else node.info.invariants
        )
        try:
            _gates.gate_c(
                node_id,
                live_invariants,
                source,
                _LazySources(s.nodes, node_id),
                mined=node.info.mined_invariants,
                project_paths={nid: n.path for nid, n in s.nodes.items()},
                previous_source=node.info.source,
                tree=staged_tree,
            )
        except LogicalError as exc:
            return self._reject(s, node, "C", exc, dry_run=dry_run)

        if dry_run:
            return CommitVerdict(accepted=True, gate=None, error=None, attestation=None, dirtied=[])
        try:
            digest = self._land(s, node, source)
        except MechanicalError as exc:
            return self._reject(s, node, "A", exc)
        return self._accept(s, node, staged_info, digest, at=at, sent_tokens=sent_tokens)

    def record_draft(self, session_id: str, node_id: str, text: str) -> None:
        """Door-1 support: park an intermediate (unverified) agent turn."""
        s = self._session(session_id)
        s.scratchpad.append(
            {"node_id": node_id, "text": text, "tokens": _tokens.count(text)}
        )
        self._persist(s)

    def drafts(self, session_id: str) -> list[dict]:
        return list(self._session(session_id).scratchpad)

    def graph(self, session_id: str) -> dict:
        """Read-only OKF graph view for Seam 2 / the UI (nodes + edges)."""
        s = self._session(session_id)
        # A lazily indexed node that nothing has needed yet is listed by its path, hash
        # and import edges (`materialized: false`); the view forces no analysis. An
        # attested node's facts are on record (its session entry), so they are shown.
        shown = {nid: (n.materialized or bool(n.verified)) for nid, n in s.nodes.items()}
        nodes = [
            {
                "node_id": nid,
                "path": n.path,
                "status": n.status,
                "locked": n.locked,
                "deps": list(n.deps),
                "exports": list(n.info.exports) if shown[nid] else [],
                "preserved_symbols": list(n.info.preserved_symbols) if shown[nid] else [],
                "invariants": list(n.info.invariants) if shown[nid] else [],
                "invariants_auto_mined": list(n.info.mined_invariants) if shown[nid] else [],
                "verified": len(n.verified),
                "attestation": n.verified[-1] if n.verified else None,
                "source": n.info.source if shown[nid] else None,
                "materialized": shown[nid],
                "disk_sha256": n.disk_sha256,
            }
            for nid, n in sorted(s.nodes.items())
        ]
        edges = [
            {"source": nid, "target": dep}
            for nid, n in sorted(s.nodes.items())
            for dep in n.deps
        ]
        return {"nodes": nodes, "edges": edges}

    def get_telemetry(self, session_id: str) -> Telemetry:
        s = self._session(session_id)
        raw, compacted, turns = _telemetry.compute(s.events)
        saved = raw - compacted
        return Telemetry(
            raw_bloated_tokens=raw,
            compacted_okf_tokens=compacted,
            tokens_saved=saved,
            dollars_saved=_telemetry.dollars(saved),
            omissions_blocked=s.omissions_blocked,
            turns=turns,
        )

    def finalize_session(self, session_id: str) -> bool:
        s = self._session(session_id)
        dirty = sorted(n for n, node in s.nodes.items() if node.status == DIRTY)
        if dirty:
            raise OmissionError(
                f"session cannot finalize: nodes {dirty} hold DIRTY_OMISSION_RISK "
                f"and must be checked out and re-verified",
                subtype="INTER_NODE_DIRTY",
            )
        rejected = self._refused(s)
        if rejected:
            raise OmissionError(
                f"session cannot finalize: nodes {rejected} are REJECTED — the bytes on disk "
                f"failed a gate; restore the file or re-commit it through the gates",
                subtype="INTER_NODE_REJECTED",
            )
        return True

    def lock_node(self, session_id: str, node_id: str) -> None:
        s, node = self._get(session_id, node_id)
        node.locked = True
        node.status = LOCKED
        self._flush(s)

    def record_event(self, session_id: str, event: dict) -> None:
        """Append a gateway-level event (a Door 1 turn: compaction bands, cache-cliff
        fold, routing) to the session log, persisted with the session, so the team
        ledger can aggregate it. Telemetry ignores kinds it does not price."""
        s = self._session(session_id)
        if not isinstance(event, dict) or "kind" not in event:
            raise ValueError("an event is a dict carrying a 'kind'")
        s.events.append(dict(event))
        self._persist(s)

    def events(self, session_id: str) -> list[dict]:
        """The session's event log (checkouts, commits, rejections, Door 1 turns)."""
        return [dict(e) for e in self._session(session_id).events]

    def compliance_bundle(self, target: str | Path) -> dict:
        """`DUC` (public dual-use card: hashes and counts only, self-checked for
        path/code leakage) and `DUA-E` (escrowed enterprise bundle: every in-toto
        Statement v1 envelope, the Merkle tree over attestation digests, control
        mappings) for a session id or a project root (its newest registered
        session). KeyError when nothing is registered."""
        from . import _compliance

        target_str = str(target)
        if _is_session_id(target_str):
            sid = target_str
        else:
            root = Path(target_str).resolve()
            sid = None
            for cand, r in self._registry().items():  # insertion order: the newest session wins
                if Path(r).resolve() == root:
                    sid = cand
            if sid is None:
                raise KeyError(f"no StepCheck session is registered for {root}")
        return _compliance.bundle(self, sid)

    def perf_stats(self) -> dict[str, int]:
        """Process-wide counters of the work the analysis cache and the incremental
        gates did and skipped: analysis_full / analysis_incremental / analysis_memory_hits
        / analysis_disk_hits / symbols_remined, gate_c_sandbox_loads /
        gate_c_probes_skipped / gate_c_symbols_checked."""
        return {**_okf.PERF, **_gates.PERF}

    def _point_cache(self, root: Path) -> None:
        """Aim the content-addressed analysis cache at this project (an ephemeral
        kernel reads it but writes nothing under the tree) and name the root package
        when the root directory is itself a package."""
        _okf.set_cache(root / ".stepcheck" / "cache" / "analysis", writable=not self._ephemeral)
        _okf.set_root_package(root.name if (root / "__init__.py").is_file() else None)

    def provenance(self, session_id: str, node_id: str) -> dict:
        """The node's latest attestation as an in-toto Statement v1 inside a DSSE
        envelope (`payloadType: application/vnd.in-toto+json`, base64 payload):
        subject = the tracked file and its on-disk SHA-256; predicate = the gate
        verdicts, conserved symbols, executed invariants and the session turn.
        Deterministic across machines and rehydration; the signature is the
        kernel's SHA-256 scheme, not a key. KeyError when the node has never
        landed a commit."""
        s, node = self._get(session_id, node_id)
        if not node.verified:
            raise KeyError(f"node '{node_id}' has no attestation in session '{session_id}'")
        return _in_toto_envelope(session_id, node.info, node.verified[-1]["payload"], len(node.verified))

    def _assemble(self, s: _Session, node: _Node, focus: list[str] | None) -> tuple:
        """Everything in a CheckoutPayload that does not depend on the turn:
        (frame, dependency signatures, locked invariants, dependency skeletons,
        token count, auto_skeletonized, elided). Pure in the session's canonical
        state, so `checkout` memoizes it until the session mutates."""
        dep_sigs = {
            dep: list(s.nodes[dep].info.exports)
            for dep in node.info.deps
            if dep in s.nodes
        }
        from . import _compactor  # lazy: keeps the package import graph acyclic

        compactor = _compactor.ContextCompactor(
            node.info,
            {dep: s.nodes[dep].info for dep in node.info.deps if dep in s.nodes},
            self._modules(s),
            focus,
        )
        dep_skeletons = compactor.dependency_skeletons()  # import-scoped, docstring-free
        invariants = list(node.info.invariants)
        for dep in node.info.deps:
            if dep in s.nodes and s.nodes[dep].locked:
                invariants.extend(s.nodes[dep].info.invariants)
        invariants, _hidden = _scope_guards(node, s.nodes, invariants, focus, compactor.tree)
        frame = _okf.frame_markdown(
            node.info, node.status, node.locked, node.verified,
            focus=focus, fold_history=True, compact_meta=bool(focus), tree=compactor.tree,
        )
        # The frame's frontmatter carries the total (`guard_invariants: N`); the rest
        # of the guards stay enforced at Gate C without being listed here.
        listed = invariants
        rendered = _render_payload(frame, dep_skeletons, listed)
        tokens = _tokens.count(rendered)
        # The floor yields to the budget: a frame at or over CHECKOUT_TOKEN_BUDGET takes
        # the ladder below instead (it is far under raw once fitted).
        raw = _tokens.count(node.info.source) if tokens < CHECKOUT_TOKEN_BUDGET else tokens
        if focus is not None and tokens > raw:  # a focused or skeleton view, never the full frame
            # Zero-bloat floor. The OKF frame would cost more than the file it slices,
            # so the frontmatter and prose go: a one-line pragma over the same sliced
            # body, still followed by the dependency interfaces and the invariant list
            # (the only way a Door 1 or hook reader sees them). When the focus and its
            # cone cover the whole module there is nothing left to hide, and the bare
            # source — exactly `raw` tokens — is the floor (the deps keep their
            # signatures in `dependency_signatures`). A partial focus is never expanded
            # to the whole file: it stays sliced even when its stubs, cone and
            # interfaces outweigh the few lines they hide.
            body = _okf.skeleton(node.info.source, list(focus), tree=compactor.tree)
            callees = (_okf.callee_closure(compactor.tree, list(focus), node.info.source)[0]
                       if compactor.tree is not None else [])
            frame = _okf.pragma_frame(node.info, node.status, node.locked, len(node.info.invariants), body, callees=callees)
            tokens = _tokens.count(_render_payload(frame, dep_skeletons, listed))
            if tokens > raw and _okf.covers_module(node.info.source, list(focus), compactor.tree):
                return node.info.source, dep_sigs, invariants, {}, raw, False, [], True
            return frame, dep_sigs, invariants, dep_skeletons, tokens, False, [], False
        auto = False
        if focus is None and tokens >= CHECKOUT_TOKEN_BUDGET:
            # Unfocused frame would blow the budget: fall back to a pure AST
            # skeleton with a symbol index so the agent can pick a focus.
            frame = _okf.frame_markdown(
                node.info, node.status, node.locked, node.verified,
                focus=[], fold_history=True, symbol_index=True, tree=compactor.tree,
            )
            rendered = _render_payload(frame, dep_skeletons, listed)
            tokens = _tokens.count(rendered)
            auto = True
        elided: list[str] = []
        if (focus is not None or auto) and tokens >= CHECKOUT_TOKEN_BUDGET:
            # Still over budget: the ContextCompactor's ladder — unreferenced
            # sibling method signatures, dependency stubs, frontmatter lists,
            # then (unfocused only) docstrings / __init__ / parameters. The
            # focused symbol and every top-level public name survive.
            frame, dep_skeletons, elided = compactor.fit(
                frame, dep_skeletons, listed, CHECKOUT_TOKEN_BUDGET,
                _tokens.count, _render_payload, focus=[] if auto else focus,
            )
            rendered = _render_payload(frame, dep_skeletons, listed)
            tokens = _tokens.count(rendered)
        return frame, dep_sigs, invariants, dep_skeletons, tokens, auto, elided, False

    def flush(self, session_id: str) -> None:
        """Write the session's in-memory state — the telemetry of checkout-only
        bursts included — to `<root>/.stepcheck/`. Mutating calls flush on their
        own; a short-lived process that only checked out should call this
        before it exits. A no-op on an ephemeral kernel."""
        self._flush(self._session(session_id))

    def locate(self, session_id: str, path: str | Path) -> dict | None:
        """The tracked node a file path belongs to, without the sources the graph
        view carries: `{node_id, path, status, locked, source_tokens, invariants,
        invariants_auto_mined}`, or None when the path is outside the project or
        untracked. The cheap query the lifecycle hooks make on every Read / Edit;
        the invariant lists are what a permissive Read puts in front of the agent."""
        s = self._session(session_id)
        try:
            rel = Path(path).resolve().relative_to(s.root)
        except ValueError:
            return None
        wanted = str(rel).replace("\\", "/")
        for nid, n in s.nodes.items():
            if n.path.replace("\\", "/") == wanted:  # the path never needs the analysis; the hit's facts do
                return {"node_id": nid, "path": n.path, "status": n.status, "locked": n.locked,
                        "source_tokens": _tokens.count(n.info.source),
                        "invariants": list(n.info.invariants), "invariants_auto_mined": list(n.info.mined_invariants)}
        return None

    def node_source(self, session_id: str, node_id: str) -> str:
        """The canonical source of one node — what a commit folds patches into."""
        return self._get(session_id, node_id)[1].info.source

    def sync(self, session_id: str, node_id: str | None = None) -> dict:
        """Adopt what an agent's own tools wrote to tracked files — after a
        `dry_run` approval, or any change made behind the session (git, a
        formatter): every file (or just `node_id`'s) whose bytes differ from what
        the session last saw is committed through Gates A -> B -> C exactly as it
        stands on disk, attested and propagated like any commit. Returns
        `{"synced": [node ids], "rejected": {node id: "<gate>: [<subtype>: ]<reason>"}}`;
        a rejected node keeps its canonical source, turns REJECTED and its bytes
        are left alone (judged once per distinct content; `refusals` remembers the
        verdict). Unreadable, deleted or undecodable files are skipped."""
        s = self._session(session_id)
        synced: list[str] = []
        rejected: dict[str, str] = {}
        for nid in ([node_id] if node_id is not None else sorted(s.nodes)):
            node = s.nodes[nid]
            try:
                raw = (s.root / node.info.path).read_bytes()
                text = _okf.decode_source(raw).replace("\r\n", "\n")
            except (OSError, UnicodeError):
                continue
            digest = _sha256(raw)
            if digest == node.disk_sha256:
                if node.status == REJECTED:  # the refused bytes are gone: the file is what the session holds
                    node.status = VERIFIED if node.verified else ACTIVE
                    s.sync_refused.pop(nid, None)
                    self._flush(s)
                continue
            if s.sync_refused.get(nid) == digest:
                continue
            if text == node.info.source:  # line endings / encoding only
                node.disk_sha256 = digest
                continue
            verdict = self.commit(session_id, nid, source=text)
            if verdict.accepted:
                synced.append(nid)
                s.sync_refused.pop(nid, None)
            else:
                subtype = getattr(verdict.error, "subtype", None)
                rejected[nid] = f"{verdict.gate}: {subtype + ': ' if subtype else ''}{verdict.error}"
                s.sync_refused[nid] = digest
                s.sync_reasons[nid] = rejected[nid]
        return {"synced": synced, "rejected": rejected}

    def refusals(self, session_id: str) -> dict[str, str]:
        """node id -> the `sync` verdict that refused the bytes still on disk, for
        every node a sync left REJECTED in this process (what the Stop hook names
        when its own sync has nothing new to judge)."""
        s = self._session(session_id)
        return {nid: reason for nid, reason in s.sync_reasons.items() if nid in s.sync_refused}

    def omission_report(self, session_id: str) -> dict:
        """`{"dirty": [node ids in DIRTY_OMISSION_RISK], "rejected": [node ids left
        REJECTED — bytes a sync or commit refused], "can_finalize": bool}` — what
        `check_omission_risks` and the Stop hook ask, without the graph. Either
        list blocks finalization: a dependent still to re-verify, or a file on
        disk that failed a gate."""
        s = self._session(session_id)
        dirty = sorted(nid for nid, n in s.nodes.items() if n.status == DIRTY)
        rejected = self._refused(s)
        return {"dirty": dirty, "rejected": rejected, "can_finalize": not dirty and not rejected}

    def _refused(self, s: _Session) -> list[str]:
        """REJECTED nodes whose file on disk is not what the session holds — bytes a
        sync refused (or that were never judged). A rejected *attempt* that left the
        file alone is not one: the tree is still the attested one."""
        out = []
        for nid, n in sorted(s.nodes.items()):
            if n.status != REJECTED:
                continue
            try:
                if _sha256((s.root / n.path).read_bytes()) == n.disk_sha256:
                    continue
            except OSError:
                pass
            out.append(nid)
        return out

    def _reject(self, s: _Session, node: _Node, gate: str, exc: GateError, *, dry_run: bool = False) -> CommitVerdict:
        if not node.locked and not dry_run:
            node.status = REJECTED
        if gate in ("B", "C"):
            s.omissions_blocked += 1
        s.events.append({"kind": "reject", "node_id": node.info.node_id, "gate": gate})
        if node.locked or dry_run:
            # Gate A on a locked node changes no frame and invalidates no checkout:
            # keep the event on the record without re-rendering the project or
            # dropping the payload memo (the Edit hook probes this path per call).
            self._persist(s)
        else:
            self._flush(s)
        return CommitVerdict(
            accepted=False, gate=gate, error=exc, attestation=None, dirtied=[]
        )

    def _land(self, s: _Session, node: _Node, source: str) -> str:
        """Write gate-approved `source` to the tracked file; return the SHA-256 of
        the bytes on disk. Refuses to overwrite edits the kernel has not seen and
        leaves the file alone (no write, no mtime churn) when the bytes are equal.
        An ephemeral kernel never writes: it attests the bytes that would land."""
        path = s.root / node.info.path
        try:
            existing = path.read_bytes()
            data = _okf.encode_like(source, existing)
            # A file that changed behind the session is refused — unless it already
            # holds exactly the staged bytes (an agent's tool wrote what a dry-run
            # approved, and `sync` is adopting it).
            if _sha256(existing) != node.disk_sha256 and data != existing:
                raise MechanicalError(
                    f"'{node.info.path}' changed on disk since the session last read it "
                    f"— open a new session to pick up those edits"
                )
            if self._ephemeral:
                return _sha256(data)
            if data != existing:
                _okf.write_atomic(path, data)
        except (OSError, UnicodeError) as exc:
            raise MechanicalError(f"could not write '{node.info.path}': {exc}")
        node.disk_sha256 = _sha256(data)
        return node.disk_sha256

    def _accept(
        self,
        s: _Session,
        node: _Node,
        staged_info: _okf.ModuleInfo,
        digest: str,
        *,
        at: float | None,
        sent_tokens: int,
    ) -> CommitVerdict:
        exports_changed = staged_info.exports != node.info.exports
        removed_exports = set(node.info.exports) - set(staged_info.exports)  # gone, or signature moved
        # `exports` covers public names; a dependent that spells
        # `from m import _helper` relies on that private signature just as much.
        before, after = _okf._signatures(node.info.source), _okf._signatures(staged_info.source)
        changed = {name for name, sig in before.items() if after.get(name) != sig}
        python = _okf.lang_module(node.info.path) is None
        if not python:  # TS / Go / Rust / Java: per-name contract from the export signatures
            fb, fa = _okf.export_signature_map(node.info.exports), _okf.export_signature_map(staged_info.exports)
            changed = {name for name, sig in fb.items() if fa.get(name) != sig}
            changed |= {name.split(".")[0] for name in changed}  # `Class.member` moved -> `Class` moved
        modules = self._modules(s)
        node.info = staged_info
        node.status = LOCKED if node.locked else VERIFIED  # a locked node only lands byte-identical
        commit_ordinal = 1 + sum(1 for e in s.events if e["kind"] == "commit")

        dirtied: list[str] = []
        reverified: list[str] = []
        facades: list[tuple[str, set[str]]] = []  # (dirtied importer, the broken names it binds)
        for dep_id, dep in sorted(s.nodes.items()):
            if dep_id == node.info.node_id or node.info.node_id not in dep.deps:
                continue
            imported = _okf.resolve_imports(
                dep_id, dep.path, dep.source, modules
            ).get(node.info.node_id, set())
            # The contract a dependent relies on: the names it imports (`from m
            # import a`, `import { a } from './m'`, `use crate::m::a`), or every
            # public export for a module import (`import m`, Go's package import):
            # then only a removed or re-signed export breaks it, an added one does
            # not. "*" (an export whose name cannot be parsed) breaks every importer.
            if imported:
                broken = bool(imported & changed) or "*" in changed
            else:
                broken = bool(removed_exports)
            if not broken:
                if not exports_changed:
                    continue  # nothing the dependent can see moved
                if self._reverify(s, dep, modules, commit_ordinal):
                    reverified.append(dep_id)
                    continue
            dep.status = DIRTY
            dirtied.append(dep_id)
            if imported:
                facades.append((dep_id, {n for n in imported if n} & changed))
        # A dependent that binds a broken name at module level re-exports it — a
        # package `__init__` doing `from .app import foo`, a TS barrel's
        # `export { foo } from './sub'`, Rust's `pub use` — so the break reaches
        # whoever imports that name from the facade, however many hops away.
        while facades:
            via_id, names = facades.pop()
            if not names:
                continue
            for far_id, far in sorted(s.nodes.items()):
                if far_id in dirtied or far_id == node.info.node_id or via_id not in far.deps:
                    continue
                via = s.nodes[via_id]
                hit = {n for n in _okf.resolve_imports(far_id, far.path, far.source, modules)
                       .get(via_id, set()) if n} & names
                if hit and via is not None:
                    far.status = DIRTY
                    dirtied.append(far_id)
                    facades.append((far_id, hit))

        envelope = _dsse_envelope(
            node.info.node_id,
            node.info.path,
            digest,
            staged_info.exports,
            commit_ordinal,
        )
        node.verified.append(envelope)
        # Garbage-collect this node's dead-end scratchpad history.
        s.scratchpad = [d for d in s.scratchpad if d["node_id"] != node.info.node_id]
        s.events.append(
            {
                "kind": "commit",
                "node_id": node.info.node_id,
                "tokens": sent_tokens,  # the folded diff actually sent
                "full_tokens": _tokens.count(staged_info.source),
                "dirtied": list(dirtied),
                "reverified": list(reverified),
                "at": at,
            }
        )
        self._flush(s)
        return CommitVerdict(
            accepted=True, gate=None, error=None, attestation=envelope, dirtied=dirtied,
            reverified=reverified,
        )

    def _reverify(self, s: _Session, dep: _Node, modules: dict[str, str], ordinal: int) -> bool:
        """Re-run Gates A -> B -> C on an untouched dependent against the session's
        new state, in memory (no write, no context tokens). Only a dependent that
        is currently clean and whose on-disk bytes still hash to what the session
        last attested qualifies; on a pass its attestation is refreshed for the
        same bytes and it stays VERIFIED. Returns whether it passed."""
        if dep.status in (DIRTY, REJECTED) or dep.disk_sha256 is None:
            return False
        try:
            if _sha256((s.root / dep.path).read_bytes()) != dep.disk_sha256:
                return False  # changed behind the session: the agent must look at it
        except OSError:
            return False
        dep_id, source = dep.node_id, dep.info.source
        try:
            # Same bytes, so a lock is not being violated: Gate A checks syntax
            # and the names this dependent's own dependents import.
            _gates.gate_a(dep_id, False, source, s.nodes)
            staged = _okf.analyze(dep_id, dep.path, source, modules, previous=dep.info)
            _gates.gate_b(dep, staged, source, source, False)
            _gates.gate_c(
                dep_id,
                dep.info.invariants,
                source,
                _LazySources(s.nodes, dep_id),
                mined=dep.info.mined_invariants,
                project_paths={nid: n.path for nid, n in s.nodes.items()},
                previous_source=source,
            )
        except GateError:
            return False
        dep.info = staged
        dep.status = LOCKED if dep.locked else VERIFIED
        dep.verified.append(_dsse_envelope(dep_id, dep.path, dep.disk_sha256, staged.exports, ordinal))
        return True

    # -- internals --------------------------------------------------------

    def _session(self, session_id: str) -> _Session:
        """The in-memory session, or one rehydrated from `<root>/.stepcheck/sessions/`
        through the local registry; anything unknown is a KeyError (Seam 2: 404)."""
        # okf-invariant: call:StateKernel().graph("nope") raises KeyError
        s = self._sessions.get(session_id)
        if s is not None:
            return s
        if not _is_session_id(session_id):
            raise KeyError(session_id)
        root = self._registry().get(session_id)
        path = Path(root) / ".stepcheck" / "sessions" / f"{session_id}.json" if root else None
        if path is None or not path.is_file():
            raise KeyError(session_id)
        s = _session_from_json(_read_json(path))
        s.disk_mtime_ns = path.stat().st_mtime_ns
        self._bind(s)
        self._sessions[session_id] = s
        return s

    def refresh_sessions(self) -> dict[str, list[str]]:
        """Reconcile the in-memory sessions with `<root>/.stepcheck/sessions/`: a
        session whose file was archived or deleted is evicted (the next use is a
        KeyError, as for any unknown id), and one whose file another process
        rewrote since this process last read or wrote it (`st_mtime_ns` moved) is
        reloaded from disk. What a long-lived gateway calls before serving a
        request, so archiving a session or re-verifying it out of process takes
        effect without a restart. A no-op on an ephemeral kernel.
        Returns {"evicted": [...], "reloaded": [...]}."""
        out: dict[str, list[str]] = {"evicted": [], "reloaded": []}
        if self._ephemeral:
            return out
        for sid, s in list(self._sessions.items()):
            path = s.root / ".stepcheck" / "sessions" / f"{sid}.json"
            try:
                mtime = path.stat().st_mtime_ns
            except OSError:
                del self._sessions[sid]
                out["evicted"].append(sid)
                continue
            if mtime == s.disk_mtime_ns:
                continue
            data = path.read_bytes()
            if _sha256(data) == s.persisted_sha:  # this process's own last write
                s.disk_mtime_ns = mtime
                continue
            fresh = _session_from_json(_read_json(path))
            fresh.disk_mtime_ns = mtime
            self._bind(fresh)
            self._sessions[sid] = fresh
            out["reloaded"].append(sid)
        return out

    def _get(self, session_id: str, node_id: str) -> tuple[_Session, _Node]:
        s = self._session(session_id)
        return s, s.nodes[node_id]

    def _modules(self, s: _Session) -> dict[str, str]:
        """The session's import map (dotted name -> node id); the node set is fixed at
        indexing, so it is built once per session object and per root package."""
        key = (_okf.ROOT_PACKAGE, len(s.nodes))
        if s.modules is None or s.modules[0] != key:
            s.modules = (key, _okf.module_map({nid: n.path for nid, n in s.nodes.items()}))
        return s.modules[1]

    def _registry(self) -> dict[str, str]:
        """session_id -> project root: the only thing the per-user index holds."""
        data = _read_json(_state_home() / "sessions.json")
        return {sid: root for sid, root in data.items() if isinstance(root, str)}

    def _register(self, s: _Session) -> None:
        if self._ephemeral:
            return
        registry = {
            sid: root
            for sid, root in self._registry().items()
            if (Path(root) / ".stepcheck" / "sessions" / f"{sid}.json").is_file()
        }
        registry[s.session_id] = str(s.root)
        _write_json(_state_home() / "sessions.json", registry)

    def _persist(self, s: _Session) -> None:
        """Session payload -> `<root>/.stepcheck/sessions/<id>.json`, skipped when
        the bytes equal what this process last wrote."""
        if self._ephemeral:
            return
        data = json.dumps(_session_to_json(s), ensure_ascii=False).encode("utf-8")
        digest = _sha256(data)
        if digest == s.persisted_sha:
            return
        _okf.write_atomic(s.root / ".stepcheck" / "sessions" / f"{s.session_id}.json", data)
        s.persisted_sha = digest

    def _flush(self, s: _Session) -> None:
        s.payload_cache.clear()  # the canonical state is about to change
        if self._ephemeral:
            return
        s.frame_shas = _okf.write_frames(s.root / ".stepcheck" / "okf", s.nodes, s.frame_shas, root=s.root)
        self._persist(s)


# -------------------------------------------------------- session persistence


def _state_home() -> Path:
    """Per-user registry location; STEPCHECK_HOME overrides it (tests, CI)."""
    import os

    return Path(os.environ.get("STEPCHECK_HOME") or Path.home() / ".stepcheck")


def _is_session_id(session_id: object) -> bool:
    import re

    return isinstance(session_id, str) and re.fullmatch(r"sk-[0-9a-f]{12}", session_id) is not None


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict) -> None:
    _okf.write_atomic(path, json.dumps(data, ensure_ascii=False).encode("utf-8"))


def _node_to_json(n: _Node) -> dict:
    """A node's persisted form. A lazy node is its path, hash and import edges; a
    materialized one adds its analysis without the source text when the text is
    recoverable (the file on disk still hashes to it, or its frame attests it) — the
    source itself is stored only for a node whose held text is nowhere else."""
    import dataclasses

    out = {"status": n.status, "locked": n.locked, "verified": n.verified, "disk_sha256": n.disk_sha256,
           "node_id": n.node_id, "path": n.path, "deps": list(n.deps)}
    if n.materialized:
        info = dataclasses.asdict(n.info)
        source = info.pop("source")
        if not n.verified:
            info["source"] = source  # unattested: no frame holds this text yet
        out["info"] = info
    return out


def _session_to_json(s: _Session) -> dict:
    return {
        "session_id": s.session_id,
        "root": str(s.root),
        "git_head": s.git_head,
        "lazy": s.lazy,
        "nodes": {nid: _node_to_json(n) for nid, n in s.nodes.items()},
        "events": s.events,
        "omissions_blocked": s.omissions_blocked,
        "scratchpad": s.scratchpad,
    }


def _session_from_json(data: dict) -> _Session:
    nodes: dict[str, _Node] = {}
    for nid, n in data["nodes"].items():
        info_data = n.get("info")
        if info_data is not None and "source" in info_data:
            node = _Node(info=_okf.ModuleInfo(**info_data), status=n["status"], locked=n["locked"],
                         verified=list(n["verified"]), disk_sha256=n.get("disk_sha256", ""))
        else:
            node = _Node(status=n["status"], locked=n["locked"], verified=list(n["verified"]),
                         disk_sha256=n.get("disk_sha256", ""), node_id=n.get("node_id", nid),
                         path=n.get("path", (info_data or {}).get("path", "")), deps=n.get("deps", (info_data or {}).get("deps", [])))
        nodes[nid] = node
        if info_data is not None and "source" not in info_data:
            # the analysis is kept (nothing is re-mined); the text comes back through the baseline on first use
            node.loader = (lambda d=info_data, node=node: _okf.ModuleInfo(**{**d, "source": node.source}))
    return _Session(
        session_id=data["session_id"],
        root=Path(data["root"]),
        nodes=nodes,
        events=list(data.get("events", [])),
        omissions_blocked=int(data.get("omissions_blocked", 0)),
        scratchpad=list(data.get("scratchpad", [])),
        git_head=data.get("git_head"),
        lazy=bool(data.get("lazy", False)),
    )


def _git_head(root: Path) -> str | None:
    import subprocess

    if not (root / ".git").exists():
        return None
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else None


def _git_dirty_paths(root: Path) -> set[str]:
    """Paths modified or untracked in the working tree (their bytes are not in HEAD)."""
    import subprocess

    try:
        out = subprocess.run(["git", "-C", str(root), "status", "--porcelain", "-z", "--untracked-files=all"],
                             capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return set()
    paths: set[str] = set()
    for entry in out.stdout.split(b"\0"):
        if len(entry) > 3:
            paths.add(entry[3:].decode("utf-8", "replace").replace("\\", "/"))
    return paths


def _git_show(root: Path, commit: str, rel: str) -> bytes | None:
    import subprocess

    try:
        out = subprocess.run(["git", "-C", str(root), "show", f"{commit}:{rel.replace(chr(92), '/')}"],
                             capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout if out.returncode == 0 else None


class _LazySources(dict):
    """node_id -> held source for every node but one, read on demand: the sandbox binds a
    project import to its canonical text only when the module under test imports it,
    so a 2,000-module repository never has every file read for one commit."""

    def __init__(self, nodes: dict, exclude: str) -> None:
        super().__init__()
        self._nodes = {nid: n for nid, n in nodes.items() if nid != exclude}

    def __contains__(self, key) -> bool:
        return key in self._nodes

    def __iter__(self):
        return iter(self._nodes)

    def __len__(self) -> int:
        return len(self._nodes)

    def keys(self):
        return self._nodes.keys()

    def __getitem__(self, key):
        return self._nodes[key].source

    def get(self, key, default=None):
        node = self._nodes.get(key)
        return node.source if node is not None else default

    def items(self):
        for nid in self._nodes:
            yield nid, self[nid]


def _as_mechanical(exc: BaseException, node_id: str) -> MechanicalError:
    """A Gate A verdict for whatever stopped the parser: its own MechanicalError, or the
    interpreter's limits (recursion, memory) on a pathological file."""
    if isinstance(exc, MechanicalError):
        return exc
    if isinstance(exc, SyntaxError):  # the edited block alone was parsed (stitch): its error is the edit's
        return MechanicalError(f"invalid AST syntax in '{node_id}': {exc.msg} (line {exc.lineno})")
    return MechanicalError(f"'{node_id}' is past the parser's limits: {type(exc).__name__}")


def _shared_trees(held_source: str, staged_tree) -> tuple | None:
    """(held tree, staged tree) for Gate B when both are Python: the held source is parsed
    once per text (memoized) and shared with the edit scope; None for other languages."""
    if not isinstance(staged_tree, ast.Module):
        return None
    try:
        return _okf.parse_cached(held_source), staged_tree
    except (SyntaxError, ValueError):
        return None


_IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_IN_TOTO_PREDICATE_TYPE = "https://stepcheck.dev/attestation/v1"
_IN_TOTO_BUILDER_ID = "https://github.com/lalithasutam/stepcheck-dev#StateKernel"


def _in_toto_envelope(session_id: str, info: _okf.ModuleInfo, latest: dict, count: int) -> dict:
    """in-toto Statement v1 for a landed commit, DSSE-wrapped the way cosign /
    Witness expect: `subject[]` carries the file and its sha256, the predicate
    carries what the gates verified. Same deterministic sha256 "signature" as
    the per-commit envelope (keyid `_DSSE_KEYID`); no private key is involved."""
    import base64
    import json

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": info.path.replace("\\", "/"), "digest": {"sha256": latest["sha256"]}}],
        "predicateType": _IN_TOTO_PREDICATE_TYPE,
        "predicate": {
            "builder": {"id": _IN_TOTO_BUILDER_ID},
            "session_id": session_id,
            "node_id": info.node_id,
            "turn": latest["turn"],
            "attestation_count": count,
            "gates": {"A": "pass", "B": "pass", "C": "pass"},
            "deps": list(info.deps),
            "exports": list(info.exports),
            "preserved_symbols": list(info.preserved_symbols),
            "invariants_executed": list(info.invariants),
            "invariants_auto_mined": list(info.mined_invariants),
        },
    }
    canonical = json.dumps(statement, sort_keys=True, separators=(",", ":"))
    return {
        "payloadType": _IN_TOTO_PAYLOAD_TYPE,
        "payload": base64.b64encode(canonical.encode("utf-8")).decode("ascii"),
        "signatures": [
            {"keyid": _DSSE_KEYID, "sig": _sha256(f"DSSEv1 {_IN_TOTO_PAYLOAD_TYPE} {canonical}")}
        ],
    }
