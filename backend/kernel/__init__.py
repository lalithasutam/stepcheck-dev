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
    """Gate C: a frame invariant no longer holds."""


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

    def rendered(self) -> str:
        return _render_payload(
            self.frame_markdown, self.dependency_skeletons, self.locked_invariants
        )


def _render_payload(frame: str, dep_skeletons: dict[str, str], invariants: list[str]) -> str:
    parts = [frame, "\n## Verified dependency interfaces (AST skeletons)\n"]
    for dep, sk in sorted(dep_skeletons.items()):
        parts.append(f"### {dep}\n```python\n{sk}```\n")
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


@dataclass(frozen=True)
class Telemetry:
    raw_bloated_tokens: int
    compacted_okf_tokens: int
    tokens_saved: int
    dollars_saved: float
    omissions_blocked: int
    turns: int


@dataclass
class _Node:
    info: _okf.ModuleInfo
    status: str = ACTIVE
    locked: bool = False
    verified: list[dict] = field(default_factory=list)
    disk_sha256: str = ""  # SHA-256 of the tracked file as the kernel last saw it


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
        files = _okf.tracked_files(root)
        loaded: dict[Path, tuple[str, bytes]] = {}
        for p in files:
            raw = p.read_bytes()
            try:
                loaded[p] = (_okf.decode_source(raw), raw)
            except UnicodeDecodeError:
                continue  # not UTF-8: leave untracked, write-back could not round-trip it
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
        for p, (text, raw) in loaded.items():
            info = _okf.analyze(ids[p], rel[p], text, modules)
            nodes[info.node_id] = _Node(info=info, disk_sha256=_sha256(raw))
        session_id = f"sk-{uuid.uuid4().hex[:12]}"
        session = _Session(session_id=session_id, root=root, nodes=nodes)
        self._sessions[session_id] = session
        self._register(session)
        self._flush(session)
        return session_id

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
        frame, dep_sigs, invariants, dep_skeletons, tokens, auto, elided = cached
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
    ) -> CommitVerdict:
        """Stage either a full `source` or a `patch` of AST-level ops folded into
        the node's canonical state, then run Gates A → B → C."""
        s, node = self._get(session_id, node_id)
        if (source is None) == (patch is None):
            raise ValueError("commit() takes exactly one of source= or patch=")
        if patch is not None:
            try:
                source = _okf.apply_patch(node.info.source, patch)
            except ValueError as exc:
                return self._reject(s, node, "A", MechanicalError(f"patch cannot fold: {exc}"))
            sent_tokens = _tokens.count(json.dumps(patch, separators=(",", ":")))
        else:
            sent_tokens = _tokens.count(source)
        assert source is not None
        source = source.replace("\r\n", "\n")  # canonical state is always LF
        try:
            _gates.gate_a(node_id, node.locked, source, s.nodes)
        except MechanicalError as exc:
            return self._reject(s, node, "A", exc)

        staged_info = _okf.analyze(node_id, node.info.path, source, self._modules(s))
        try:
            _gates.gate_b(node, staged_info, node.info.source, source, allow_deletion)
        except OmissionError as exc:
            return self._reject(s, node, "B", exc)

        # Hand-written invariants always apply; auto-mined guards are waived by a
        # declared deletion (the agent said it meant to remove behaviour).
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
                {nid: n.info.source for nid, n in s.nodes.items() if nid != node_id},
                mined=node.info.mined_invariants,
                project_paths={nid: n.info.path for nid, n in s.nodes.items()},
            )
        except LogicalError as exc:
            return self._reject(s, node, "C", exc)

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
        nodes = [
            {
                "node_id": nid,
                "path": n.info.path,
                "status": n.status,
                "locked": n.locked,
                "deps": list(n.info.deps),
                "exports": list(n.info.exports),
                "preserved_symbols": list(n.info.preserved_symbols),
                "invariants": list(n.info.invariants),
                "invariants_auto_mined": list(n.info.mined_invariants),
                "verified": len(n.verified),
                "attestation": n.verified[-1] if n.verified else None,
                "source": n.info.source,
            }
            for nid, n in sorted(s.nodes.items())
        ]
        edges = [
            {"source": nid, "target": dep}
            for nid, n in sorted(s.nodes.items())
            for dep in n.info.deps
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
        frame = _okf.frame_markdown(
            node.info, node.status, node.locked, node.verified,
            focus=focus, fold_history=True, compact_meta=bool(focus), tree=compactor.tree,
        )
        rendered = _render_payload(frame, dep_skeletons, invariants)
        tokens = _tokens.count(rendered)
        auto = False
        if focus is None and tokens >= CHECKOUT_TOKEN_BUDGET:
            # Unfocused frame would blow the budget: fall back to a pure AST
            # skeleton with a symbol index so the agent can pick a focus.
            frame = _okf.frame_markdown(
                node.info, node.status, node.locked, node.verified,
                focus=[], fold_history=True, symbol_index=True, tree=compactor.tree,
            )
            rendered = _render_payload(frame, dep_skeletons, invariants)
            tokens = _tokens.count(rendered)
            auto = True
        elided: list[str] = []
        if (focus is not None or auto) and tokens >= CHECKOUT_TOKEN_BUDGET:
            # Still over budget: the ContextCompactor's ladder — unreferenced
            # sibling method signatures, dependency stubs, frontmatter lists,
            # then (unfocused only) docstrings / __init__ / parameters. The
            # focused symbol and every top-level public name survive.
            frame, dep_skeletons, elided = compactor.fit(
                frame, dep_skeletons, invariants, CHECKOUT_TOKEN_BUDGET,
                _tokens.count, _render_payload, focus=[] if auto else focus,
            )
            rendered = _render_payload(frame, dep_skeletons, invariants)
            tokens = _tokens.count(rendered)
        return frame, dep_sigs, invariants, dep_skeletons, tokens, auto, elided

    def flush(self, session_id: str) -> None:
        """Write the session's in-memory state — the telemetry of checkout-only
        bursts included — to `<root>/.stepcheck/`. Mutating calls flush on their
        own; a short-lived process that only checked out should call this
        before it exits. A no-op on an ephemeral kernel."""
        self._flush(self._session(session_id))

    def locate(self, session_id: str, path: str | Path) -> dict | None:
        """The tracked node a file path belongs to, without the sources the graph
        view carries: `{node_id, path, status, locked, source_tokens}`, or None
        when the path is outside the project or untracked. The cheap query the
        lifecycle hooks make on every Read / Edit."""
        s = self._session(session_id)
        try:
            rel = Path(path).resolve().relative_to(s.root)
        except ValueError:
            return None
        wanted = str(rel).replace("\\", "/")
        for nid, n in s.nodes.items():
            if n.info.path.replace("\\", "/") == wanted:
                return {"node_id": nid, "path": n.info.path, "status": n.status, "locked": n.locked,
                        "source_tokens": _tokens.count(n.info.source)}
        return None

    def node_source(self, session_id: str, node_id: str) -> str:
        """The canonical source of one node — what a commit folds patches into."""
        return self._get(session_id, node_id)[1].info.source

    def omission_report(self, session_id: str) -> dict:
        """`{"dirty": [node ids in DIRTY_OMISSION_RISK], "can_finalize": bool}` —
        what `check_omission_risks` and the Stop hook ask, without the graph."""
        s = self._session(session_id)
        dirty = sorted(nid for nid, n in s.nodes.items() if n.status == DIRTY)
        return {"dirty": dirty, "can_finalize": not dirty}

    def _reject(self, s: _Session, node: _Node, gate: str, exc: GateError) -> CommitVerdict:
        if not node.locked:
            node.status = REJECTED
        if gate in ("B", "C"):
            s.omissions_blocked += 1
        s.events.append({"kind": "reject", "node_id": node.info.node_id, "gate": gate})
        if node.locked:
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
            if _sha256(existing) != node.disk_sha256:
                raise MechanicalError(
                    f"'{node.info.path}' changed on disk since the session last read it "
                    f"— open a new session to pick up those edits"
                )
            data = _okf.encode_like(source, existing)
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
        # `exports` covers public names; a dependent that spells
        # `from m import _helper` relies on that private signature just as much.
        before, after = _okf._signatures(node.info.source), _okf._signatures(staged_info.source)
        modules = self._modules(s)
        node.info = staged_info
        node.status = VERIFIED

        dirtied: list[str] = []
        for dep_id, dep in sorted(s.nodes.items()):
            if dep_id == node.info.node_id or node.info.node_id not in dep.info.deps:
                continue
            if not exports_changed:
                imported = _okf.resolve_imports(
                    dep_id, dep.info.path, dep.info.source, modules
                ).get(node.info.node_id, set())
                if not any(n and n.startswith("_") and before.get(n) != after.get(n) for n in imported):
                    continue
            dep.status = DIRTY
            dirtied.append(dep_id)

        commit_ordinal = 1 + sum(1 for e in s.events if e["kind"] == "commit")
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
                "at": at,
            }
        )
        self._flush(s)
        return CommitVerdict(
            accepted=True, gate=None, error=None, attestation=envelope, dirtied=dirtied
        )

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
        self._sessions[session_id] = s
        return s

    def _get(self, session_id: str, node_id: str) -> tuple[_Session, _Node]:
        s = self._session(session_id)
        return s, s.nodes[node_id]

    def _modules(self, s: _Session) -> dict[str, str]:
        return _okf.module_map({nid: n.info.path for nid, n in s.nodes.items()})

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
        s.frame_shas = _okf.write_frames(s.root / ".stepcheck" / "okf", s.nodes, s.frame_shas)
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


def _session_to_json(s: _Session) -> dict:
    import dataclasses

    return {
        "session_id": s.session_id,
        "root": str(s.root),
        "nodes": {
            nid: {
                "info": dataclasses.asdict(n.info),
                "status": n.status,
                "locked": n.locked,
                "verified": n.verified,
                "disk_sha256": n.disk_sha256,
            }
            for nid, n in s.nodes.items()
        },
        "events": s.events,
        "omissions_blocked": s.omissions_blocked,
        "scratchpad": s.scratchpad,
    }


def _session_from_json(data: dict) -> _Session:
    nodes = {
        nid: _Node(
            info=_okf.ModuleInfo(**n["info"]),
            status=n["status"],
            locked=n["locked"],
            verified=list(n["verified"]),
            disk_sha256=n.get("disk_sha256", ""),
        )
        for nid, n in data["nodes"].items()
    }
    return _Session(
        session_id=data["session_id"],
        root=Path(data["root"]),
        nodes=nodes,
        events=list(data.get("events", [])),
        omissions_blocked=int(data.get("omissions_blocked", 0)),
        scratchpad=list(data.get("scratchpad", [])),
    )


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
