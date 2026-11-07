# StepCheck Dev — GLOSSARY

Ubiquitous language for the Anti-Context-Rot State Engine. Use these terms exactly, in code,
tests, frames, and UI. Scope: AI coders, engineering teams, multi-agent swarms (Segments 1–3).

## Core nouns

**OKFFrame** — One Markdown document with *strict* YAML frontmatter that is the canonical,
compacted representation of one code module (one Python file). Frontmatter keys:
`node_id`, `path`, `status`, `exports[]` (name + signature), `deps[]` (node_ids),
`preserved_symbols[]`, `invariants[]` (executable Python assertions over `src`),
`verified[]` (append-only DSSE attestation envelopes), `locked` (bool).
Body: a short generated summary + the current source fenced block. Frontmatter that fails
strict parsing (missing keys, wrong types, duplicate keys) is a `MechanicalError` at index time.

**OKF graph** — The project-level artifact: `index.md` (project frame listing every node and
edge) plus one OKFFrame per module, linked by `deps[]`. It is a DAG over `node_id`s; an import
cycle collapses into mutual dep edges (no dirty-propagation infinite loops: propagation visits
each node once).

**node_id** — A module's file stem while that stem is unique in the project (`billing`); when
stems collide (several `__init__.py`, `pkg/models.py` + `other/models.py`) the colliding files use
their dotted relative path (`kernel.__init__`, `other.models`). `deps[]` are resolved through
packages: absolute and relative imports (`from . import _gates`, `from kernel import StateKernel`)
both land on the right node, and Gate A checks the names a dependent imports against the staged
module's top-level bindings. Gate C loads a package module as a package, so its relative imports
resolve to canonical sources. **Source roots:** a session rooted at the repository also resolves
names relative to a first-level directory that code puts on `sys.path` (`src/`, `backend/`): with
the root at the repo, `from kernel import StateKernel` in `backend/server.py` still resolves to
`backend/kernel/__init__.py`, and the Gate C sandbox binds that alias to the canonical source. An
alias only resolves while it is unambiguous, never when its top-level name is a standard-library
module (`utils/json.py` does not capture `import json`); a root-relative name always wins over an alias.

**Session persistence** — Every session is written to `<root>/.stepcheck/sessions/<session_id>.json`
on each state change and indexed in `~/.stepcheck/sessions.json` (`STEPCHECK_HOME` overrides the
directory). A fresh `StateKernel` (a gateway restart) rehydrates a known `session_id` on first use;
an unknown or malformed id is a `KeyError` (404 at Seam 2). `StateKernel(ephemeral=True)` is
verification-only: gates, attestations and the graph work in memory, but no frame, session file,
registry entry or tracked-file write-back is ever written — this is what `stepcheck ci` runs on.

**StateKernel** — The single deep module behind Seam 1. Owns OKF compilation, sessions,
checkout/commit, the three gates, locking, attestation, and telemetry. Everything else in
`backend/kernel/` is private implementation (`_`-prefixed modules), not interface.

**CheckoutPayload** — What `checkout()` returns: the target OKFFrame (full, or sliced by
`focus`), its immediate verified dependencies as **interface skeletons**, the locked
invariants that constrain the edit, and `token_count`. Hard budget: `token_count < 4000`.
Never contains unrelated sibling frames. An unfocused checkout whose frame would meet the
budget auto-falls back to a pure skeleton + symbol index (`auto_skeletonized=True`). Superseded attestations fold into one
`attestation: {count, latest_sha256, latest_turn}` summary in the payload; the on-disk frame
keeps the append-only `verified[]` chain.

**Focus / AST skeleton** — `checkout(…, focus=[names])` serves the named top-level defs
verbatim (comments included) and every other def/class as decorators + signature + docstring +
`...`, with runs of module-level assignments folded into one summary line. `focus=[]` is a pure
skeleton; `focus=None` is the full frame.

**Patch (diff folding)** — `commit(…, patch=[ops])` folds AST-level ops into the node's canonical
state before the gates run: `{"op":"append","code"}`, `{"op":"replace_symbol","name","code"}`
(decorators included), `{"op":"delete_symbol","name"}`. Telemetry charges the patch, not the
module. A patch that cannot fold is a `MechanicalError` at Gate A.

**CommitVerdict** — What `commit()` returns: `accepted: bool`, `gate` (`"A" | "B" | "C" | None`),
`error` (a `GateError` or `None`), `attestation` (envelope dict when accepted), `dirtied[]`
(node_ids transitioned to `DIRTY_OMISSION_RISK`), `reverified[]` (dependents re-checked in memory
and re-attested instead — see OmissionRisk).

**PreservedSymbol** — A named AST element (decorator usage, guard clause marker, internal call,
exported def) listed in a frame's `preserved_symbols[]`. Silently dropping one is an
`OmissionError(subtype="INTRA_NODE_SYMBOL_DROPPED")` unless the commit passes
`allow_deletion=True`.

**OmissionRisk** — Node status `DIRTY_OMISSION_RISK`: a dependency's exported signature changed,
so this node may silently rely on stale behavior. A session cannot finalize while any node holds
this status; it clears only by checking the node out and re-committing it through all gates.
**In-kernel re-verification:** for a Python dependency, a dependent whose *contract* is intact —
no signature changed or removed among the names it imports (`from m import a`), or among the
public exports for a module import (`import m`) — is not dirtied: if it is clean and its on-disk
bytes still hash to what the session last attested, Gates A/B/C run on it in memory against the
new state and, on a pass, its attestation is refreshed (`CommitVerdict.reverified[]`). Purely
additive changes therefore dirty nothing. TS / Go / Rust / Java dependencies are always dirtied
on an export change.

**TokenFirewall** — Door 1 of the gateway: the BYOK proxy that intercepts bloated `messages[]`,
commits verified steps into the StateKernel, prunes dead-end exploration history, injects the
compact CheckoutPayload, and forwards upstream with the caller's own key (deterministic local
dry-run when no key is supplied).

**DualDoorGateway** — The whole HTTP surface (Seam 2): Door 1 (TokenFirewall proxy routes) +
Door 2 (explicit REST + Streamable HTTP MCP at `/mcp` + `WS /v1/ws/{session_id}`).

## Statuses

`ACTIVE` → editable; `VERIFIED` → last commit passed all gates (attested); `LOCKED` → verified
and pinned, any mutation rejected at Gate A; `DIRTY_OMISSION_RISK` → see OmissionRisk;
`REJECTED` → last commit failed a gate (frame content unchanged).

## Gates (run in order inside `commit()`)

**Gate A — Mechanical & Locked:** source must parse (`ast`), exported defs required by
dependents must keep their signatures, and a `LOCKED` node rejects every mutation.
Failure: `MechanicalError`. `verified[]` untouched on rejection.

**Gate B — Omission:** AST symbol fingerprinting. Rejects (1) dropped `preserved_symbols[]`
(`INTRA_NODE_SYMBOL_DROPPED`), (2) >15% AST-statement shrinkage without `allow_deletion=True`
(`INTRA_NODE_MASS_DELETION`). On an *accepted* export-signature change, downstream dependents
transition to `DIRTY_OMISSION_RISK` (`INTER_NODE_DIRTY` propagation). Failure: `OmissionError`.

**Gate C — Logical, Attestation, Telemetry:** every `invariants[]` expression must hold
(failure: `LogicalError`). Each evaluates with `src` (= `ast.unparse(tree)`: normalized,
comment-free, so whitespace never trips it and an invariant can never satisfy itself), `tree`
(`ast.Module`), `ns` (the staged module exec-loaded into an isolated namespace, project imports
resolved to canonical sources — loaded only when referenced), plus `ast` and
`raises(fn, "Exc")`. Sugar: `call:<expr> raises <Exc>`. **Auto-mined invariants:** at analysis time every top-level
function whose body opens with guard clauses (`if <cond on one param>: raise <Exc>`) gets a
synthesized `call:fn(param=value, …) raises Exc` invariant (listed in `invariants_auto_mined`,
de-duplicated against hand-written ones, re-mined on every accepted commit). Mined guards are
waived by `allow_deletion=True`; hand-written invariants never are. When the staged signature
gains required parameters, a mined `call:` invariant is evaluated with typed mocks for them, so
the guard is still exercised (hand-written calls are never filled in). Namespace loading and every evaluation run under an
execution guard (200k line-event steps / 0.5 s backstop); overrun is a deterministic
`LogicalError`. On pass, write the source to the tracked file (UTF-8, keeping the file's BOM and
line endings; a file changed on disk since the kernel last read it is a `MechanicalError` and is
left alone), append a deterministic SHA-256 / DSSE-style envelope whose `sha256` hashes those exact
bytes to `verified[]`, garbage-collect dead-end scratchpad history, and update telemetry.
`omissions_blocked` counts Gate B and Gate C rejections.

Canonical state is always LF. Files that are not valid UTF-8 are left untracked.

## Errors

`GateError` (base) → `MechanicalError` (Gate A), `OmissionError(subtype=...)` (Gate B),
`LogicalError` (Gate C). Subtypes: `INTRA_NODE_SYMBOL_DROPPED`, `INTRA_NODE_MASS_DELETION`,
`INTER_NODE_DIRTY`, `LOCKED_MUTATION`.

## Telemetry terms

Telemetry counts the read path only: a **turn** is a checkout. Commits (patches, whole-source
writes, `sync` adoptions, in-kernel re-verification) charge nothing and add no turn.
**raw_bloated_tokens** — tokens an unfirewalled agent would have paid: full re-read of every
file read so far on each turn, *plus the 5-minute cache-cliff penalty* (a re-read later than 300s
after the previous one is billed again at full input rate, not cache-hit rate).
**compacted_okf_tokens** — tokens actually returned to the agent: CheckoutPayload sizes.
**dollar savings** — `(raw − compacted) / 1e6 × $3.00` (Sonnet-class input rate; constant lives
in one place: `kernel/_telemetry.py`). Token counting is deterministic: `ceil(len(text)/4)`.

## The two public seams (pre-agreed; all tests live here)

**Seam 1 — StateKernel public Python API** (`backend/kernel/__init__.py`):
`init_session(project_root) -> session_id` · `checkout(session_id, node_id, *, focus=None) -> CheckoutPayload`
· `commit(session_id, node_id, source=None, *, patch=None, allow_deletion=False) -> CommitVerdict`
· `lock_node(session_id, node_id)` · `get_telemetry(session_id) -> Telemetry`
· `finalize_session(session_id)` · `record_draft(session_id, node_id, text)` /
`drafts(session_id)` (Door-1 scratchpad support; accepted commits GC that node's drafts).
Catches: compilation, gates, propagation, attestation, telemetry math.
Misses: HTTP serialization — that's Seam 2's job.

**Seam 2 — DualDoorGateway HTTP/MCP boundary** (`backend/server.py`):
`POST /v1/chat/completions` · `POST /v1/messages` · `POST /v1/step/*` ·
`WS /v1/ws/{session_id}` · Streamable HTTP `/mcp`. Door 1 honours `x-stepcheck-focus`
(`"a,b"`, or `""` for a pure skeleton) and folds a ```` ```stepcheck-patch ```` JSON block in the
latest assistant turn as a patch commit.
Catches: proxy pruning/injection, BYOK forwarding + dry-run fallback, MCP tool wiring,
WS state streaming. Misses: kernel internals — already covered at Seam 1.

## Testing rules (skill precedence)

Matt Pocock `tdd` + `codebase-design` override `python-testing-patterns` on mocking:
**never mock internal modules, AST parsers, YAML validators, or hash functions.** Tests hit
Seam 1 / Seam 2 only, against concrete non-tautological fixtures (hand-written literal projects
and hand-calculated expected numbers). `python-testing-patterns` is used only for pytest
fixture parameterization and async test runners.
