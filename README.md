# StepCheck Dev

[![CI](https://github.com/lalithasutam/stepcheck-dev/actions/workflows/ci.yml/badge.svg)](https://github.com/lalithasutam/stepcheck-dev/actions/workflows/ci.yml)
**Live:** [131-session audit receipt](https://lalithasutam.github.io/stepcheck-dev/audit.html) · [50-turn interactive replay](https://lalithasutam.github.io/stepcheck-dev/)

**Catches what your tests don't cover.** Test-driven agent gates and static AI-defect scanners (Skylos,
linters) catch a regression only when a unit test fails or a generic lint rule fires. They miss a dropped
domain guard (`if currency == "JPY": return amount`), a flipped boundary (`<=` → `<`) and a neutered raise
(`raise` → `return None`) in code no test covers — exactly what an agent does around turn 25, when the file
it is editing has been sitting in context as a stale 500-line read. StepCheck auto-mines per-function Gate C
invariants straight from the AST (`guard:` clauses and executable `call:` probes, no annotations) and
enforces them in about 15 ms before any byte reaches disk, cuts read tokens by 75–89% with causal-cone AST
slicing, and emits standard in-toto Statement v1 provenance (`attestation.intoto.json`). You also stop
paying for every stale read again each time you pause past the provider's cache window; teams get both
fixes on PRs no senior engineer has time to review for cross-file omissions.

**Skylos 4.50.1 vs StepCheck on 239 untested faults** (same corpus as the external certification: CanItEdit,
psf/requests, pallets/flask; no covering unit test; Skylos run as `skylos . -a --ai-defects --json`, any new
finding in the mutated file counted as a catch; StepCheck = `StateKernel.commit` rejected at Gate B or C):

| Fault, no covering test | Cases | Skylos 4.50.1 | StepCheck Gate B/C |
| --- | ---: | ---: | ---: |
| dropped guard (CanItEdit) | 16 | 6 (37.5%) | 16 (100%) |
| dropped guard in the wild (requests/flask) | 34 | 6 (17.6%) | 34 (100%) |
| body stubbed to `...` (CanItEdit / requests/flask) | 65 | 56 (86.2%) | 65 (100%) |
| `@overload` / decorator stripped | 18 | 6 (33.3%) | 18 (100%) |
| boundary flipped in an `if` guard or `assert` | 18 | 0 (0%) | 18 (100%) |
| `raise` neutered to `pass` / `return None` | 26 | 1 (3.8%) | 26 (100%) |
| `if False and cond` short-circuit | 26 | 26 (100%) | 26 (100%) |
| `except` widened (raise kept / swallowed) | 36 | 17 (47.2%) | 36 (100%) |
| **all** | **239** | **118 (49.4%)** | **239 (100%)** |

Receipt: `.stepcheck/discovery/receipts/skylos_vs_stepcheck.json` (script `benchmark_vs_skylos.py`, re-runnable).

**Three steps, none of them in your prompt:**

1. `stepcheck audit --card` — sixty seconds, no server: reads your local Claude Code transcripts and shows the
   dollars lost to cache-cliff re-reads, the share of Read tokens spent on bodies the agent never used, and
   the exact turns where a decorator or guard went missing. Nothing but totals leaves the machine.
2. `stepcheck hooks && stepcheck up` — invisible daily protection: a `PreToolUse` hook turns large file reads
   into AST skeletons, every edit runs Gates A/B/C (dropped decorator or guard: blocked; changed signature:
   callers flagged `DIRTY_OMISSION_RISK`), and the `Stop` hook refuses to end the turn until those callers are
   re-verified.
3. Door 1 proxy + PR bot — for teams: accordion compaction of old tool results, a cache-cliff shield, gate-backed
   routing of focused edits to a cheaper model, and `stepcheck ci --report` (or the GitHub Action) posting a
   blast-radius and in-toto provenance checklist on every PR.

| Tier | Who | What it unlocks |
| --- | --- | --- |
| Open core (free, Apache-2.0) | every developer | audit card, hooks, the gateway, Gates A/B/C, MCP, Studio |
| Pro FinOps proxy ($19/mo or 15% of verified savings) | heavy API / BYOK users | all-turn accordion compaction, cache-cliff shield, `x-stepcheck-tier: auto` arbitrage |
| Team PR & FinOps ($39/seat/mo) | 10–100 seat teams | GitHub Action PR bot, `GET /v1/team/summary` ledger, org-wide Pin & Lock |
| Enterprise Trust Ledger ($79/seat/mo or self-hosted) | regulated engineering orgs | polyglot monorepo verification, `stepcheck compliance` in-toto Statement v1 + DUC / DUA-E bundles |

Licensing is opt-in (`STEPCHECK_REQUIRE_KEY=1`); with it unset everything in this repository runs locally with no
key. Ubiquitous language and the two public testing seams live in `GLOSSARY.md`.

## Layout

| Path | What it is |
| --- | --- |
| `backend/kernel/` | **StateKernel** (Seam 1): OKF graph compilation, bounded `checkout(focus=)` with AST skeleton slicing, 3-tier gated `commit(source= \| patch=)` with diff folding (A mechanical/locked · B omission · C semantic invariants over `src`/`tree`/`ns`, auto-mined from leading `if …: raise` guards with zero annotations), DSSE/SHA-256 attestation, draft GC, cache-cliff telemetry |
| `backend/server.py` | **DualDoorGateway** (Seam 2): Door 1 firewall proxy (`/v1/chat/completions`, `/v1/messages`, BYOK or dry-run) with three-band accordion compaction and opt-in tier routing, Door 2 REST `/v1/step/*` (incl. the warm `POST /v1/step/hook` lifecycle-hook evaluator) + FastMCP Streamable HTTP at `/mcp` + `WS /v1/ws/{session_id}` |
| `backend/tests/` | 376 tests, all at the two seams, zero mocks of internals (incl. the 50-turn ≥85% benchmark gate, self-hosted compaction floors, latency budgets, a 10-class fault-injection matrix, the wild-corpus hardening cases, dotted method slicing, multi-definition symbol groups, budget laundering and in-toto provenance) |
| `frontend/` | StepCheck Studio: React + TS + Vite + Tailwind, @xyflow/react OKF graph (Pin & Lock), Monaco DiffEditor + attestation viewer, live gate feed + cost chart, WS-driven; replays a built-in demo session when no gateway is reachable |
| `extension/` | VS Code / Cursor webview wrapper (`StepCheck: Open Studio`) |
| `benchmarks/` | 50-turn coding-rot benchmark (events injected at T20/T25/T35/T36; 88.4% tokens saved) + review generator |
| `architecture-review.html` | Generated visual report |
| `stepcheck-studio-preview.html` | Zero-dependency interactive replay of the 50-turn run (turn scrubber, graph, patch diff, attestation, cost curve) |
| `backend/cli.py` + `pyproject.toml` | `stepcheck up / benchmark / review / preview / audit [--card] / ci [--report] / llms / hooks` — `hooks [path]` installs idempotent Claude Code hook wiring under `.claude/` that calls the gateway's `/v1/step/hook` and allows when the daemon is offline; `ci --report` writes the PR blast-radius and provenance checklist; `audit --card` writes an anonymized SVG badge; `llms` regenerates `docs/llms.txt` + `docs/llms-full.txt` (llmstxt.org) from the repo's own files, so AI search engines quote the measured figures; `ci [path]` is the headless PR gatekeeper: every module must parse, match its DSSE attestation, hold no `DIRTY_OMISSION_RISK`, and pass Gates A/B/C with all invariants executed (exit 1 names the module and violation); `.github/workflows/ci.yml` runs it on Ubuntu + Windows |
| `backend/audit.py` | `stepcheck audit [path]`: reads Claude Code `~/.claude/projects/*.jsonl`, receipts cache-cliff waste vs skeleton checkouts and dropped-decorator/guard edits + their retry loops → `stepcheck-audit.html` (falls back to `benchmarks/fixtures/sample_session.jsonl`) |
| `CLAUDE.md` → `.cursorrules` | Agent rules: enforces the StepCheck MCP workflow (init → focused checkout → patch commit → omission check + savings) in Claude Code and Cursor |

## Run (turnkey)

```bash
pipx install git+https://github.com/lalithasutam/stepcheck-dev   # the `stepcheck` CLI, no clone needed
pip install -e .            # …or from a clone (editable)
(cd frontend && npm install && npm run build)   # once: compiled Studio served at /studio
stepcheck up                # one port (:8420): Studio UI + Door 1 proxy + REST + MCP + WS
stepcheck benchmark         # 50-turn coding-rot benchmark
stepcheck review            # architecture-review.html
stepcheck preview           # stepcheck-studio-preview.html (self-contained replay)
stepcheck audit             # your own cache-cliff waste + Read-tool bloat, no server needed → stepcheck-audit.html
stepcheck ci backend        # headless gate: parse + attestations + Gates A/B/C for every module (CI/PR)
stepcheck llms              # docs/llms.txt + docs/llms-full.txt from README, GLOSSARY, LAUNCH and benchmarks/results.json
stepcheck hooks             # .claude/hooks + settings wiring: Read over threshold -> allowed, frame + Gate C invariants alongside (STEPCHECK_STRICT_READ=1: skeleton instead); Edit through Gates A/B/C -> [STEPCHECK CATCH] banner + .stepcheck/catches.jsonl; Stop while dirty / rejected -> block
stepcheck compliance        # attestation.intoto.json (in-toto Statement v1: every tracked file + sha256, gate verdicts, Merkle root, DSSE envelopes) + DUC.json / DUA-E.json
stepcheck ci . --report     # the headless gate plus a Markdown PR checklist: touched modules, re-verified callers, conserved symbols, in-toto digests
stepcheck audit --card      # stepcheck-audit-card.svg + a copy-paste badge line; file names and session ids never appear
stepcheck retro . --commits 50   # the git time machine: every commit's modified modules through Gates B/C — guard drops, flips, neuters, stubbed bodies, stripped decorators; structural by default and parallel (--probes: runtime call: checks too; --all: structural removals + test files; --json)
stepcheck diff . [--staged | --base origin/main...HEAD] [--markdown]   # the working tree, the index or a PR against its baseline; exit 1 on a silent regression
stepcheck allow <file> [symbol] --reason "..."   # declare one intended guard / symbol removal for the next native-tool edit (.stepcheck/declared.jsonl; consumed once)
stepcheck connect .         # hooks + .mcp.json + session + a git pre-commit gate (`diff --staged`, chains your existing hook) + .cursor/mcp.json when .cursor/ exists; `disconnect` undoes it
```

`action.yml` is a composite GitHub Action: on a pull request it runs `stepcheck diff --base <base sha> --markdown`, writes the
table to the job summary and fails the check on a silent regression (`fail-on-catch: 'false'` to report only); on a push it
runs `stepcheck ci`.

## Door 1: accordion compaction and tier routing

Every proxied turn through `/v1/messages` or `/v1/chat/completions` passes a three-band compactor: the last
four messages stay verbatim, older Python source blocks over 150 tokens are replaced in place by their AST
skeleton, dead-end turns are pruned, and after a cache-cliff gap the oldest band folds into one OKF
session-state frame. The dry-run response carries a `stepcheck.compaction` block with per-band token counts.
Routing is opt-in: `x-stepcheck-tier: auto` (or `STEPCHECK_TIER_POLICY=auto`) sends a focused single-symbol
turn to `STEPCHECK_FAST_MODEL` first and re-sends it to the requested frontier model only when a gate rejects
the draft; without the header nothing changes.

## TypeScript and JavaScript projects

`.ts`, `.tsx`, `.js` and `.jsx` files are indexed next to `.py` (declaration files, `node_modules`, `dist`,
`build` and `out` are skipped). Relative imports become graph edges, top-level declarations render as
brace-elided skeletons, patch ops splice exact line spans, and Gates A/B plus the DSSE attestation apply
unchanged; Gate C has no invariants for TypeScript yet, and class members are not individually addressable.

Checkouts and patch ops address methods too: `focus=["StateKernel.commit"]` emits that one method verbatim inside a
class skeleton, and `replace_symbol` / `delete_symbol` on `"Class.method"` splice only its lines. A name always
addresses its whole definition group (`@overload` stubs + implementation, a `@property` with its setter).
`StateKernel.provenance(session_id, node_id)` exports the latest attestation as an in-toto Statement v1 inside a
DSSE envelope (`application/vnd.in-toto+json`), the shape cosign and Witness consume; the signature is the kernel's
deterministic SHA-256 scheme, not a key.

## Claude Code slash commands (work out of the box after cloning)

`.claude/commands/` ships four project commands. They need the gateway running (`stepcheck up`) and the
`stepcheck` MCP server connected (`claude mcp add --transport http stepcheck http://127.0.0.1:8420/mcp/`);
`CLAUDE.md` supplies the rules they enforce.

| Command | What it does |
| --- | --- |
| `/stepcheck-session [node_id …]` | Brings `:8420` up if needed, calls `init_project_session` on the repo root, locks the named modules (`lock_module_invariants`), prints the live Studio URL `…/studio/?session=<id>` |
| `/stepcheck-fix <issue>` | Fixes the issue strictly through the gates: Red→Green test at a public seam, `checkout_context_frame` with a narrow `focus`, surgical `commit_verified_step` patch, re-verifies every `DIRTY_OMISSION_RISK` dependent until `can_finalize: true`, reports attestation sha256s and token savings |
| `/stepcheck-ci [message]` | Runs `stepcheck ci .` (zero dirty nodes, zero SHA-256 drift, Gates A/B/C on every module) and the full `pytest -q`; only then commits with the given message (push only when asked) |
| `/stepcheck-audit [path] [--limit N]` | Runs `stepcheck audit` on local Claude Code transcripts and summarises cache-cliff waste, Read-tool bloat vs AST skeletons, and the regressions a gate would have blocked |

## Run (development)

```bash
# backend + tests
cd backend && pip install -r requirements.txt && python -m pytest -q
python server.py                         # gateway on :8420 (PORT overrides)

# frontend
cd frontend && npm install && npm run dev   # Studio on :5173
# open http://localhost:5173/?session=<session_id from POST /v1/step/init>

# benchmark + report
python3 benchmarks/coding_rot_benchmark.py
python3 benchmarks/generate_review.py

# extension (compile check; load the folder via VS Code "Run Extension")
cd extension && npm install && npm run compile
```

## Door 1 in one call

```bash
SID=$(curl -s localhost:8420/v1/step/init -d '{"project_root":"/path/to/project"}' \
      -H 'content-type: application/json' | jq -r .session_id)
curl -s localhost:8420/v1/messages \
  -H "x-stepcheck-session: $SID" -H "x-stepcheck-node: billing" \
  -H 'content-type: application/json' \
  -d '{"model":"claude-sonnet-4-5","max_tokens":512,"messages":[...]}'
# add x-api-key + x-stepcheck-upstream (or STEPCHECK_UPSTREAM_BASE) to forward BYOK;
# without them you get the deterministic dry-run with stepcheck.sent_messages.
```

## Testing rules (skill precedence)

`tdd` + `codebase-design` override `python-testing-patterns` on mocking: never
mock internal modules, AST parsers, YAML validators, or hash functions. Tests
hit Seam 1 / Seam 2 only, against concrete non-tautological fixtures
(hand-written projects, hand-calculated telemetry numbers).

## Security model

Gate C exec-loads the agent's staged module in an isolated namespace under a step/time guard so
callable invariants can run against it. That is an isolated namespace, **not a security sandbox**:
run the gateway in a container when the agent is untrusted. The executable `call:` invariants are
Python-only; TypeScript/JavaScript, Go, Rust and Java get the same three gates with structural guards
and signature contracts instead.

## License

Apache-2.0 — see `LICENSE` and `NOTICE`. Everything in this repository is the open core (kernel,
gates, MCP server, BYOK proxy, Studio, `stepcheck ci` and `stepcheck audit`). If StepCheck gets real
use, the paid product will be a team layer (shared attestation ledger, org-wide CI gate); the core
stays open.
