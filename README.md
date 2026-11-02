# StepCheck Dev

[![CI](https://github.com/lalithasutam/stepcheck-dev/actions/workflows/ci.yml/badge.svg)](https://github.com/lalithasutam/stepcheck-dev/actions/workflows/ci.yml)
**Live:** [116-session audit receipt](https://lalithasutam.github.io/stepcheck-dev/audit.html) · [50-turn interactive replay](https://lalithasutam.github.io/stepcheck-dev/)

Deterministic Anti-Context-Rot State Engine · BYOK Token-Firewall Proxy ·
Streamable HTTP MCP Server · Split-Pane Visual Workspace.
Ubiquitous language and the two public testing seams live in `GLOSSARY.md`.

## Layout

| Path | What it is |
| --- | --- |
| `backend/kernel/` | **StateKernel** (Seam 1): OKF graph compilation, bounded `checkout(focus=)` with AST skeleton slicing, 3-tier gated `commit(source= \| patch=)` with diff folding (A mechanical/locked · B omission · C semantic invariants over `src`/`tree`/`ns`, auto-mined from leading `if …: raise` guards with zero annotations), DSSE/SHA-256 attestation, draft GC, cache-cliff telemetry |
| `backend/server.py` | **DualDoorGateway** (Seam 2): Door 1 firewall proxy (`/v1/chat/completions`, `/v1/messages`, BYOK or dry-run), Door 2 REST `/v1/step/*` + FastMCP Streamable HTTP at `/mcp` + `WS /v1/ws/{session_id}` |
| `backend/tests/` | 95 tests, all at the two seams, zero mocks of internals (incl. the 50-turn ≥85% benchmark gate) |
| `frontend/` | StepCheck Studio: React + TS + Vite + Tailwind, @xyflow/react OKF graph (Pin & Lock), Monaco DiffEditor + attestation viewer, live gate feed + cost chart, WS-driven; replays a built-in demo session when no gateway is reachable |
| `extension/` | VS Code / Cursor webview wrapper (`StepCheck: Open Studio`) |
| `benchmarks/` | 50-turn coding-rot benchmark (events injected at T20/T25/T35/T36; 88.2% tokens saved) + review generator |
| `architecture-review.html` | Generated visual report |
| `stepcheck-studio-preview.html` | Zero-dependency interactive replay of the 50-turn run (turn scrubber, graph, patch diff, attestation, cost curve) |
| `backend/cli.py` + `pyproject.toml` | `stepcheck up / benchmark / review / preview / audit / ci` — `ci [path]` is the headless PR gatekeeper: every module must parse, match its DSSE attestation, hold no `DIRTY_OMISSION_RISK`, and pass Gates A/B/C with all invariants executed (exit 1 names the module and violation); `.github/workflows/ci.yml` runs it on Ubuntu + Windows |
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
```

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
run the gateway in a container when the agent is untrusted. Python projects only for now.

## License

Apache-2.0 — see `LICENSE` and `NOTICE`. Everything in this repository is the open core (kernel,
gates, MCP server, BYOK proxy, Studio, `stepcheck ci` and `stepcheck audit`). If StepCheck gets real
use, the paid product will be a team layer (shared attestation ledger, org-wide CI gate); the core
stays open.
