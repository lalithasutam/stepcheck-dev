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
both land on the right node — at any nesting depth: a **lazy import** inside a function, an
`if TYPE_CHECKING:` block or a `try: … except ImportError:` fallback is a dependency too — and Gate A checks the names a dependent imports against the staged
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
**Session refresh:** `refresh_sessions()` reconciles memory with disk — a session whose file was
archived or deleted is evicted (its next use is the `KeyError` of an unknown id), and one whose file
another process rewrote (newer `mtime_ns`, bytes not this process's own last write) is reloaded.
The gateway runs it before every `/v1/…` and `/mcp` request, so a long-lived daemon never answers
the Stop hook from a session already archived on disk.

**Hook offline fast path** — The installed lifecycle hook (`stepcheck hooks`) detects an offline
gateway with a 15 ms loopback connect probe before importing anything beyond the standard library.
A PreToolUse on a non-editing tool (Read) then exits at once — tens of milliseconds of hook time,
`STEPCHECK_HOOK_TRACE=1` prints it — while an editing tool, PostToolUse and Stop still run the
in-process gates: a dead socket never lets a broken write through.
**Shell writes:** a `Bash` command is not gated before it runs (nothing is staged to judge), so its
PostToolUse syncs every registered session for the cwd; a tracked file the gates refuse stays
REJECTED and is reported as additionalContext, and the Stop hook blocks on it (`omission_report`
lists `rejected` next to `dirty`; `can_finalize` needs both empty, `finalize_session` raises
`INTER_NODE_REJECTED`). **Frame protection:** a session whose view of a node is behind the tree
(its sync was rejected, or its last attestation is older than the file) never overwrites that
node's on-disk OKF frame while the frame is VERIFIED and attests the file's current bytes — a
stale session cannot make `stepcheck ci` fail on a correct tree.

**Permissive Read** — A PreToolUse Read of a tracked module over the token threshold is
*allowed*: the module is synced into the session, a `focus=[]` checkout is charged like any
frame, and the answer rides that frame — exports, preserved symbols, dependency interfaces — plus
every Gate C invariant the module carries (mined guards first, then the executed `call:` and
declared ones) as `additionalContext`, so the agent sees the contract on the turn it first reads
the file and is never blocked from reading. Scoped slices (`limit <= 120`) and modules under the
threshold pass silently. **Strict read** is opt-in (`STEPCHECK_STRICT_READ=1`, or `strict_read:
true` on the event): the old behaviour, the Read denied and the skeleton supplied instead.

**Catch receipt** — Every block at Gate A / B / C that a hook makes — a denied Edit / Write /
MultiEdit, a Bash write the PostToolUse sync refused, a blocked Stop (DIRTY_OMISSION_RISK or
REJECTED) — is phrased as the banner `[STEPCHECK CATCH — Gate X] <module> (<symbol>): <what would
have broken>` (the symbol is the definition the edit changed, read from the two ASTs, else the one
the verdict names) and appended as one JSON line to `<project>/.stepcheck/catches.jsonl`:
`timestamp, module, symbol, gate, code, reason, hook, tool, session_id`. `code` is the Gate B
subtype (`INTRA_NODE_SYMBOL_DROPPED`, `INTRA_NODE_BODY_STUBBED`, `INTER_NODE_DIRTY`, …) or the kind
of Gate A / C failure (`LOCKED`, `SYNTAX`, `EXPORT_REQUIRED`, `GUARD_INVARIANT`, `CALL_INVARIANT`,
`FRAME_INVARIANT`, `EXECUTION_BUDGET`). A human reads the receipt without the kernel; a sync's
verdict is remembered per process (`StateKernel.refusals`) so the Stop names the same code.

**Incremental analysis** — A commit analyses the staged module against the module the session
holds, in *segments*: a top-level def, a class shell (its `class` line, attributes and nested
classes) and each `Class.method`. Segments whose text did not change, and that name no changed
symbol, keep their mined invariants; only the affected segments are re-mined (`guard:` clauses,
`call:` probes, branch invariants). A change at the module level (imports, constants) is a full
analysis again. Gate C follows the same **edit scope**: a runtime `call:` probe or a structural
guard whose owning segment is outside the scope is untouched by definition and is not re-run,
so the sandbox is never loaded for an edit that cannot reach a probe; hand-written invariants
always run. `StateKernel.perf_stats()` counts what was mined, reused and skipped.

**Analysis cache** — The facts that depend on a file's text alone (exports, decorator and
symbol fingerprints, mined invariants, the names it calls) are content-addressed
(`sha256(rules version + path + source)`) in memory and under `<root>/.stepcheck/cache/analysis/`;
what depends on the rest of the project (dependencies, `call:<imported>` fingerprints) is
recomputed on every call. An ephemeral kernel (`stepcheck ci`) reads the cache but writes
nothing under the tree.

**File discovery** — `tracked_files` skips generated and vendored code by pattern
(`migrations/`, `*_pb2.py`, `*_pb2_grpc.py`, `*.min.js`, `*.d.ts`, `*.generated.*`, `vendor/`,
`dist/`, `build/`, `.next/`, `target/`, `node_modules/`) and, inside a git repository, everything
`.gitignore` hides (`git ls-files --cached --others --exclude-standard`). A file the running
Python cannot parse (a newer grammar such as PEP 695 `type X = …`, or more than the parser's 100
indentation levels) is left untracked instead of aborting the index; growing a tracked file past
those limits is a Gate A verdict.

**Compliance Statement** — `stepcheck compliance` leads with `attestation.intoto.json`: a standard
in-toto Statement v1 (`_type` `https://in-toto.io/Statement/v1`, `predicateType`
`https://stepcheck.dev/attestation/v1`) whose `subject[]` is every tracked file with its sha256 and
whose predicate carries what the session verified — gate verdicts, invariant counts, the Merkle
root over attestation digests, each module's status and latest attestation, the per-node DSSE
envelopes, the control mappings. The dual-use pair stays beside it: `DUC.json` (public card,
hashes and counts only, self-checked for leakage) and `DUA-E.json` (escrowed envelopes, Merkle
tree, controls). Deterministic: the same session yields byte-identical files.

**Causal cone** — What a focused checkout carries besides the focus: same-file callees
(`name(...)`, `self.m(...)`, `Class.m(...)`) followed transitively, bare decorators, a method's
`__init__` / `__post_init__` and class attributes, and the module constants the cone reads.
Callees are expanded verbatim breadth-first, smallest first, up to the 1,000-token callee budget;
a callee over the budget is kept as a signature and named in the frame note — and still walked,
so the helpers it calls are expanded when they fit and named when they do not, and the constants
read only behind that wall are named too. Nothing in the cone is silently absent.

**StateKernel** — The single deep module behind Seam 1. Owns OKF compilation, sessions,
checkout/commit, the three gates, locking, attestation, and telemetry. Everything else in
`backend/kernel/` is private implementation (`_`-prefixed modules), not interface.

**CheckoutPayload** — What `checkout()` returns: the target OKFFrame (full, or sliced by
`focus`), its immediate verified dependencies as **interface skeletons**, the locked
invariants that constrain the edit, and `token_count`. Hard budget: `token_count < 4000`.
Never contains unrelated sibling frames. An unfocused checkout whose frame would meet the
budget auto-falls back to a pure skeleton + symbol index (`auto_skeletonized=True`). Superseded attestations fold into one
`attestation: {count, latest_sha256, latest_turn}` summary in the payload; the on-disk frame
keeps the append-only `verified[]` chain. **Compact header:** when a focused checkout's cone
covers every top-level symbol (the frame is the whole module, served verbatim) or the full header
would outweigh the file, the frontmatter shrinks to `node_id, path, status, locked` (+ `deps`,
`attestation` when non-empty); everything dropped is still enforced at the gates. Empty
dependency / invariant sections are omitted from the payload. **Zero-bloat floor:** a focused or
skeleton checkout (`focus` given, `[]` included) never costs more than the file it slices when
there is a cheaper honest view. When the full frame would, the frontmatter and prose go and the
frame becomes one pragma line — `# [stepcheck: <node_id> | <status> | invariants: N enforced |
callees: …]` (`//` outside Python) — over the sliced body in a code fence, still followed by the
dependency interfaces and the `## Locked invariants` list (the only way a Door 1 or hook reader
sees them). When the focus and its cone cover the whole module there is nothing left to hide and
the payload is the bare source, exactly `raw` tokens (`CheckoutPayload.pragma=True`; the deps
keep their signatures in `dependency_signatures`). A partial focus is never expanded to the whole
file: it stays sliced even when its stubs, cone and interfaces outweigh the few lines they hide.
The full frame (`focus=None`) is never floored, and a frame at or over the 4,000-token budget
takes the budget ladder instead.

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
additive changes therefore dirty nothing. TS / Go / Rust / Java use the same per-name contract,
read from the export signatures (`Class.member` counts as `Class`; Go names are the identifiers
read off the package alias, `ledger.Open`; a Java file's same-package references — the type name
of a sibling file in its directory used as an identifier, no `import` needed — are edges on that
name); an export whose name cannot be parsed (`default`) breaks every importer. A locked dependent that is dirtied clears by re-committing its locked bytes
unchanged (see Gate A).

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
dependents must keep their signatures, and a `LOCKED` node rejects every mutation. **Lock
re-verification:** a commit whose source is byte-identical to the locked node's canonical state,
whose on-disk bytes still hash to its last attestation, is not a mutation — it runs Gates B/C
against the current upstream and lands with the node still `LOCKED` (how a locked module dirtied
by a dependency change returns to clean). Failure: `MechanicalError`. `verified[]` untouched on rejection.

**Gate B — Omission:** AST symbol fingerprinting. Rejects (1) dropped `preserved_symbols[]`
(`INTRA_NODE_SYMBOL_DROPPED`), (2) >15% AST-statement shrinkage without `allow_deletion=True`
(`INTRA_NODE_MASS_DELETION`) — for Python only when the shrink also loses a **binding** (a def,
class, method, or module- / class-level assigned name) or changes an exported signature: a
**concise refactor** that keeps every binding, stubs no body and keeps every Gate C guard passes.
A **skeleton-stub body** (`INTRA_NODE_BODY_STUBBED`) is a def whose real body became `...` / `pass`
/ docstring-only — and, for TS/JS, Go, Rust and Java, a brace body of two or more statements that
became empty, comment-only, a placeholder macro (`todo!()`, `unimplemented!()`) or a lone trivial
`return` (`return nil / null / 0 / "" / false`). A decorator a symbol carries more than once is
counted (`@overload on f x2`), so dropping one block of an overload set is a dropped fingerprint.
On an *accepted* export-signature change, downstream dependents
transition to `DIRTY_OMISSION_RISK` (`INTER_NODE_DIRTY` propagation), and the break follows
**re-export facades**: a dependent that binds a broken name at module level (`from .app import foo`
in a package `__init__`, a TS barrel's `export { foo } from './sub'`, Rust `pub use`) forwards it
to whoever imports that name from the facade, however many hops away. Failure: `OmissionError`.
**Dead-symbol rule (strict mode):** a dropped Python `def X` / `class X` passes without
`allow_deletion` when the name occurs nowhere in the staged module (name, attribute, definition or
string), nowhere in any dependent's source, and the module still exports something — removing or
renaming dead code is a refactor, not an omission (Gate C then does not ask for that symbol's
guards either). A decorator fingerprint (`@dec on X`) or an internal call (`call:X`) is never dead
this way: those are the silent drops.

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
the guard is still exercised (hand-written calls are never filled in). **Structural guard
invariants** (`guard:<Symbol>:<clause>`, Python as well as TS / Go / Rust / Java) need no runtime
arguments, so they cover what `call:` mining cannot — methods (`Class.method`), nested scopes
(`fn.Inner.m`), external types (`isinstance(x, CookieJar)`): every `if <cond> raises <Exc>` at any
depth, every `assert <cond>`, `if <cond> returns <const / None / empty>` and `if <cond> returns
early` (a computed value: the condition is pinned, the expression may be refactored) for every
`if` that is a direct branch of the def — not one inside a loop, `with` or `try`, which is control
flow — `else raises <Exc>` for an if / elif chain whose final `else` raises (one clause per chain,
so branches may be added), every `except <T> raises <Exc>` handler, and `<obj>.get(<key>) has
default` for any two-argument `.get(key, default)` (any key, any default; a `.get(key)` keeps it,
a bare `<obj>[<key>]` subscript drops it). **Assert waivers (strict mode):** a missing `assert
<cond>` is accepted when a variable it read no longer exists anywhere in the module (renamed or
removed in the same refactor) or when the def now carries the equivalent `if not <cond>: raise …`
(a flipped comparison counts); a live assertion deleted outright, or weakened in place, is still
rejected. Clauses are normalized with `ast.unparse` (messages, quotes,
parentheses never matter) and a repeated clause is numbered (`… #2`). Gate C requires each to stay
present anywhere in its symbol's body, after the executable invariants run; a leading guard the
`call:` miner already exercises is left to that semantic check, so an equivalent rewrite passes.
A focused checkout lists only the focus's guards (frontmatter `guard_invariants: N` counts all).
Namespace loading and every evaluation run under an
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
