# StepCheck Dev — launch kit

Every number below is read from the repo as it stands, not rounded up:

| Metric | Value | Source |
| --- | --- | --- |
| Kernel + gateway + CLI + audit | ≈7,400 LOC (`cat backend/kernel/*.py backend/server.py backend/cli.py backend/audit.py \| wc -l`) | `wc -l` |
| License | Apache-2.0 (`LICENSE`, `NOTICE`, `pyproject.toml`); the whole repo is the open core | `LICENSE` |
| Tests | 376, all at the public seams (kernel API, HTTP/MCP, CLI), zero mocks of internals, ~20–50 s depending on OS (includes the live 50-turn benchmark gate, a real uvicorn MCP round-trip, self-hosted compaction and latency budgets, and a 10-class fault matrix) | `python -m pytest -q` |
| 50-turn benchmark | 120,815 raw → 14,048 compacted tokens, 88.4% saved, $0.3203 at $3.00/MTok | `benchmarks/results.json` |
| Real-log audit | 131 Claude Code sessions, 7,612 assistant turns, 95 cache-cliff resumes re-writing 5,876,819 tokens, $15.87 paid above cache-read price | `docs/audit.html` (file names and session IDs anonymized) |
| Catches | T20 Gate B `INTRA_NODE_SYMBOL_DROPPED` · T25 Gate B `INTER_NODE_DIRTY` (accepted, `api`+`workers` dirtied, finalize blocked) · T35 Gate C `call:charge(account="x", amount_cents=0) raises ValueError` (auto-mined — payments.py has no annotations) · T36 Gate A locked mutation | `stepcheck benchmark` |

Don't quote 88.7%, 88.5%, 0.29s, "1,700 LOC", "32 tests" or "59 tests" anywhere. Those were earlier runs and earlier suites; the T25 signature-change turn costs a little more than an append, and the suite now runs the benchmark itself. Don't put a percentage in a title.

---

## 0. Positioning: the two hair-on-fire problems

**Catches what your tests don't cover.** Test-driven agent gates and static AI-defect scanners (Skylos,
linters) catch a regression only when a unit test fails or a generic lint rule fires; they miss a dropped
domain guard (`if currency == "JPY": return amount`), a flipped boundary (`<=` → `<`) and a neutered raise
(`raise` → `return None`) in untested code. StepCheck auto-mines per-function Gate C invariants from the AST
(`guard:` clauses, executable `call:` probes) and enforces them in about 15 ms before disk writeback, cuts
read tokens by 75–89% with causal-cone AST slicing, and emits standard in-toto Statement v1 provenance
(`attestation.intoto.json`).

**Skylos 4.50.1 vs StepCheck on 239 untested faults** — the external certification corpus (CanItEdit,
psf/requests, pallets/flask), no covering unit test, Skylos run as `skylos . -a --ai-defects --json` with
any new finding in the mutated file counted as a catch; StepCheck = `StateKernel.commit` rejected at Gate B/C.
Receipt: `.stepcheck/discovery/receipts/skylos_vs_stepcheck.json`.

| Fault, no covering test | Cases | Skylos 4.50.1 | StepCheck Gate B/C |
| --- | ---: | ---: | ---: |
| dropped guard (CanItEdit) | 16 | 6 (37.5%) | 16 (100%) |
| dropped guard in the wild (requests/flask) | 34 | 6 (17.6%) | 34 (100%) |
| body stubbed to `...` | 65 | 56 (86.2%) | 65 (100%) |
| `@overload` / decorator stripped | 18 | 6 (33.3%) | 18 (100%) |
| boundary flipped in an `if` guard or `assert` | 18 | 0 (0%) | 18 (100%) |
| `raise` neutered to `pass` / `return None` | 26 | 1 (3.8%) | 26 (100%) |
| `if False and cond` short-circuit | 26 | 26 (100%) | 26 (100%) |
| `except` widened (raise kept / swallowed) | 36 | 17 (47.2%) | 36 (100%) |
| **all** | **239** | **118 (49.4%)** | **239 (100%)** |

**Individual developer — the turn-25 brain-melt and wallet bleed.** By the time a session reaches its
twenty-fifth turn, tens of thousands of tokens of stale file reads sit in context and the model's attention
over them has decayed. That is the turn where it edits `charge()` in `payments.py` and silently drops the
`@audit` decorator, weakens the `ValueError` guard, or changes the signature without touching `api.py` and
`workers.py`. The same reads are the bill: reading a 500-line file to look at one 15-line function keeps all
500 lines in history forever, and every pause longer than the provider's cache window re-bills that whole
prefix at the full input rate instead of the cache-read rate.

**Team — the unreviewable AI PR flood.** Agents produce several times more pull requests than a senior
engineer can review for cross-file omissions and dropped guards, while the CTO watches a frontier-model bill
driven by trivial edits over uncompacted history.

**The three-step flow (nothing to type into a prompt):**

1. `stepcheck audit --card` — sixty seconds, local, no server: the dollars lost to cache-cliff re-reads, the
   share of Read tokens wasted on bodies the agent never used, and the exact turns where a decorator or guard
   was dropped. Totals only; file names and session ids never leave the machine.
2. `stepcheck hooks && stepcheck up` — invisible daily protection: Read interception returns an AST skeleton,
   every Edit/Write/commit runs Gates A/B/C, signature changes mark callers `DIRTY_OMISSION_RISK`, and the
   Stop hook blocks the turn until they are re-verified.
3. Door 1 proxy + PR bot — accordion compaction of old tool results, cache-cliff shield, gate-backed model
   arbitrage, and a blast-radius + in-toto provenance checklist on every PR via `stepcheck ci --report` or
   the GitHub Action.

**Four tiers:** open core (free, Apache-2.0: audit, hooks, gateway, gates, MCP, Studio) · Pro FinOps proxy
($19/mo or 15% of verified savings: all-turn compaction, cache-cliff shield, `x-stepcheck-tier: auto`) ·
Team PR & FinOps ($39/seat/mo: GitHub Action PR bot, `GET /v1/team/summary`, org-wide Pin & Lock) ·
Enterprise Trust Ledger ($79/seat/mo or self-hosted: polyglot verification, `stepcheck compliance` in-toto
Statement v1 + DUC / DUA-E bundles). Enforcement is opt-in via `STEPCHECK_REQUIRE_KEY=1`; the default install asks for no key.

---

## 1. Show HN

**Title (80 chars; no percentage in the title):**
Show HN: StepCheck – AST skeletons and 3 commit gates vs. agent context rot

**Post** (order: the problem → your own bill → how it works → the benchmark with its caveat → try it → limits → the ask → license):

I kept watching long agent sessions go bad the same way. Around turn 30 the model quietly deletes a decorator it stopped reading, the tests it still runs pass, and the bill is climbing because every turn re-reads every file. If you're past Anthropic's 5-minute cache window between turns (real refactors are), you pay full input rate for all of it again.

I measured the bill half on my own logs. `stepcheck audit` reads the Claude Code transcripts under `~/.claude/projects`: across 131 sessions and 7,612 assistant turns, 95 turns resumed after the cache had expired and re-wrote 5.88M tokens of context at full rate — $15.87 above cache-read price — and 1.6M tokens were pulled with the Read tool where the same files as AST skeletons would have been 0.4M. The anonymized receipt is linked below.

StepCheck is a small deterministic layer between the agent and the model that fixes both halves.

Context: the repo gets compiled into an OKF graph, one Markdown frame per module with strict YAML frontmatter (exports, deps, preserved symbols, invariants, attestations). The agent checks out one node at a time. With `focus=[charge]` it gets that function verbatim and the rest of the module as an AST skeleton: signatures, decorators, docstrings, bodies replaced with `...`, runs of constants folded to one line. Dependencies come as interface skeletons only. The agent commits a patch of AST ops (append / replace_symbol / delete_symbol) and the kernel folds it into canonical state. Telemetry charges the patch, not the module.

Correctness: every commit runs three gates before it lands.
- Gate A, mechanical: parses, exported names dependents import still exist, locked modules refuse everything.
- Gate B, omission: AST symbol fingerprinting. Drop a `@audit` decorator the frame lists in `preserved_symbols[]` and you get `OmissionError(INTRA_NODE_SYMBOL_DROPPED)`. Change an exported signature and the dependents flip to `DIRTY_OMISSION_RISK`; the session can't finalize until each one is checked out and re-verified.
- Gate C, logical: invariants in the frame's frontmatter, evaluated against `src` (normalized via `ast.unparse`, so whitespace can't trip them and comments can't satisfy them), `tree`, and `ns`, the staged module exec-loaded in an isolated namespace with project imports resolved to canonical sources. `call:charge("acct", 0) raises ValueError` is a one-liner, and you usually don't write it: leading `if …: raise` guards are mined into invariants automatically at index time. Runs under a step/wall-clock guard so a runaway loop is a deterministic LogicalError, not a hung process.

A passing commit appends a DSSE-style SHA-256 envelope to the frame. Replay the same session on another machine and you get byte-identical envelopes.

Two doors: a BYOK proxy for `/v1/chat/completions` and `/v1/messages` that prunes dead-end turns and injects the compact frame, and a Streamable HTTP MCP server at `/mcp` for Claude Code / Cursor. One port, `stepcheck up`.

Numbers: my synthetic 50-turn benchmark on a 6-module repo sends 14,048 tokens where the raw agent sends 120,815 (88.4% less), and it catches all four injected faults — T20 silent `@audit` drop, T25 signature change dirtying two dependents and blocking finalize, T35 guard removed with identical statement count, T36 mutation of a locked module. It's my benchmark, so read it as a ceiling, not a promise: `stepcheck benchmark` reproduces it and the replay below lets you scrub every turn. 376 tests at the two public seams, zero mocks of internals, CI green on Ubuntu and Windows.

Try it in 60 seconds (the audit needs no server and prints your own number):

    pipx install git+https://github.com/lalithasutam/stepcheck-dev
    stepcheck audit        # your cache-cliff waste + Read-tool bloat from ~/.claude/projects
    stepcheck up           # then: claude mcp add --transport http stepcheck http://127.0.0.1:8420/mcp/

Honest limits: Gate C exec-loads the agent's staged module in an isolated namespace under a step/time guard — that is not a security sandbox, so run the gateway in a container for untrusted agents. The executable `call:` invariants are Python-only; TypeScript/JavaScript, Go, Rust and Java get the same three gates with structural guards and signature contracts instead. And the benchmark is mine.

What I'd like feedback on: the invariant ladder (string over normalized `src` → AST → callable `call:` form — is that the right shape?), and your own `stepcheck audit` numbers: sessions, turns, dollars above cache-read, Read-tool tokens vs skeletons. There's a pinned Discussion for receipts; please don't post raw transcripts, they contain your code.

Apache-2.0. If this gets real use, the paid thing will be a team layer (shared attestation ledger, org-wide CI gate); the core stays open.

- Repo: https://github.com/lalithasutam/stepcheck-dev
- 50-turn interactive replay: https://lalithasutam.github.io/stepcheck-dev/ (jump to a moment: [T20](https://lalithasutam.github.io/stepcheck-dev/#t20), [T25](https://lalithasutam.github.io/stepcheck-dev/#t25), [T35](https://lalithasutam.github.io/stepcheck-dev/#t35), [T36](https://lalithasutam.github.io/stepcheck-dev/#t36))
- 131-session anonymized audit receipt: https://lalithasutam.github.io/stepcheck-dev/audit.html

**First comment (post it within minutes of the submission):**

Author here. Two things up front so nobody has to dig for them. (1) The 88.4% is my own synthetic benchmark; the number I'd trust more is the audit of my real sessions ($15.87 of cache-cliff re-writes across 131 sessions), and `stepcheck audit` will print yours in under a minute with no server. (2) Gate C executes the agent's staged code in-process behind a step/time guard; it isn't a sandbox — containerize for untrusted agents. What I most want from this thread: is string → AST → callable the right invariant ladder, and what does your audit say? Receipts (numbers, not transcripts) in the pinned Discussion.

**If asked about price:** "Per-seat for teams, free for individuals and open-source projects, no price set yet — the team layer isn't built."

**Posting plan:** Monday 2026-11-02, 13:30 UTC (19:00 IST / 9:30 ET). Six hours blocked for replies. X thread +1 h linking the HN thread, Reddit +1 day. Success = one stranger posts an audit receipt.

---

## 2. Social

### X / Twitter thread

1/ Agents don't fail at turn 3. They fail at turn 35, when they stop re-reading the decorator they're about to delete. Tests pass. Bill climbs. Built a fix: StepCheck. 🧵

2/ The bill first. Past the 5-min cache window every turn re-reads every touched file at full rate. Over 50 turns on a 6-module repo that's 120,815 tokens. StepCheck sent 14,048. 88.4% less. Same edits, same gates passed.

3/ How: the repo compiles to OKF frames. Checkout with focus=[charge] gets that function in full and everything else as an AST skeleton. Deps arrive as interfaces only. Commits are AST patches folded into canonical state. You pay for the patch.

4/ Correctness: 3 deterministic gates on every commit.
A mechanical (parse, exports, locks)
B omission (symbol fingerprinting + dirty propagation)
C logical (invariants over normalized src, the AST, and the exec-loaded module)

5/ T20 in the benchmark: agent rewrites charge(), silently drops @audit. Gate B: INTRA_NODE_SYMBOL_DROPPED. T35: guard removed, statement count unchanged. payments.py has zero annotations; Gate C runs the invariant it mined from the guard itself, charge(amount_cents=0) doesn't raise. Rejected.

6/ T25 is the one I like. Legit signature change on payments.charge. Accepted. But api and workers go amber (DIRTY_OMISSION_RISK) and finalize is refused until both are re-verified. The thing agents never do on their own.

7/ Every passing commit gets a DSSE-style SHA-256 envelope. Deterministic across machines. ~4,900 LOC, 376 tests at two seams, no mocks of internals, CI green on Ubuntu + Windows. Apache-2.0.

8/ Try the interactive replay, no install, works on your phone: https://lalithasutam.github.io/stepcheck-dev/
Repo: https://github.com/lalithasutam/stepcheck-dev
`pipx install git+https://github.com/lalithasutam/stepcheck-dev && stepcheck audit` prints your own cache-cliff number; `stepcheck up` gives you the proxy, MCP server and Studio UI on one port.

### r/ClaudeAI · r/cursor post

**Title:** I built a deterministic "context firewall" MCP server for Claude Code / Cursor. 88.4% fewer tokens over 50 turns, and it caught the turn-35 regression. Interactive replay inside, no install.

Long sessions in Claude Code and Cursor have two problems that feed each other: the context fills with stale re-reads (and past the 5-minute cache window you pay full price for every one), and somewhere around turn 30 the model stops actually reading the code it's editing and drops something it shouldn't. A deleted decorator, a removed guard clause. Syntax is fine, tests still pass.

StepCheck is an MCP server (Streamable HTTP, `/mcp`) plus a BYOK proxy that sits between the agent and the model. The agent checks out one module frame at a time as an AST skeleton with only the function it's editing in full, commits a small AST patch, and the kernel runs three deterministic gates before anything lands: mechanical, omission (symbol fingerprinting + dependency dirty propagation), and logical (callable invariants like `call:charge("acct", 0) raises ValueError` executed against the staged module in an isolated namespace).

Numbers from the 50-turn benchmark in the repo, not estimates: 120,815 raw tokens → 14,048 sent (88.4%). Four injected events, four caught: T20 silent `@audit` drop (Gate B), T25 signature change dirtying two dependents and blocking finalize (Gate B propagation), T35 guard removed with identical statement count (Gate C), T36 mutation of a locked module (Gate A).

**Try it without installing anything:** the repo ships `stepcheck-studio-preview.html`, a single self-contained file that replays the real benchmark run. Scrub the 50 turns, jump to T20/T25/T35/T36, read the patch diff and the DSSE attestation, watch the dependency graph go amber and red. Works on a phone.

**Hook it up to Claude Code:**
```
claude mcp add --transport http stepcheck http://127.0.0.1:8420/mcp/
```
**Cursor:** add to `.cursor/mcp.json`:
```json
{ "mcpServers": { "stepcheck": { "url": "http://127.0.0.1:8420/mcp/" } } }
```
Tools exposed: `init_project_session`, `checkout_context_frame`, `commit_verified_step`, `lock_module_invariants`, `check_omission_risks`, `get_token_savings`.

Honest limits: callable invariants execute the agent's staged code in-process (isolated namespace with a step/time guard, not a security sandbox; containerize for untrusted agents). The executable `call:` invariants are Python-only; TypeScript/JavaScript, Go, Rust and Java get the structural guards and signature contracts. Feedback on the invariant syntax is what I most want.

### Embedding the replay as a live demo

The preview is one HTML file with inline CSS/JS and the benchmark data embedded. No build, no server, no CDN.

**GitHub Pages:**
```bash
mkdir -p docs && cp stepcheck-studio-preview.html docs/index.html
git add docs && git commit -m "docs: interactive replay" && git push
# Settings → Pages → Source: Deploy from branch → main /docs
# live at https://lalithasutam.github.io/stepcheck-dev/   (deep link: https://lalithasutam.github.io/stepcheck-dev/#t25)
```
**Vercel:**
```bash
mkdir -p site && cp stepcheck-studio-preview.html site/index.html
npx vercel site --prod --yes      # static deploy, no framework detection needed
```
Link straight to a moment with the hash: `#t20`, `#t25`, `#t35`, `#t36`. Regenerate after any benchmark change with `stepcheck preview`.

---

## 3. The three commands when you open the laptop

**1. Verify, build, serve everything on one port**
```bash
cd stepcheck-dev && pip install -e . && (cd frontend && npm install && npm run build) && (cd backend && python -m pytest -q) && stepcheck up
```
Expect `376 passed`, then the gateway banner. Open http://127.0.0.1:8420/studio/ for the Studio UI; it's in demo replay until you pass `?session=<id>` from `POST /v1/step/init`.

**2. Connect Claude Code (or Cursor) to the MCP server** (second terminal)
```bash
claude mcp add --transport http stepcheck http://127.0.0.1:8420/mcp/ && claude
```
In the session: ask it to call `init_project_session` on a Python repo path, then `checkout_context_frame` with a focus and `commit_verified_step` with a patch. For Cursor, put `{"mcpServers":{"stepcheck":{"url":"http://127.0.0.1:8420/mcp/"}}}` in `.cursor/mcp.json` instead.

**2a. Gate a PR headlessly** — `stepcheck ci backend` re-runs every module through Gates A/B/C, executes all mined and hand-written invariants, and refuses attestation drift or `DIRTY_OMISSION_RISK` nodes with exit 1; `.github/workflows/ci.yml` does this on Ubuntu + Windows for every push and PR.

**2b. Audit your own sessions (30 seconds, no setup)**
```bash
stepcheck audit            # reads ~/.claude/projects/*.jsonl → terminal summary + stepcheck-audit.html
```
It reports your real cache-cliff re-bills and any edits that dropped a decorator or guard, with the retry loop that followed.

**3. Deploy the interactive replay**
```bash
mkdir -p docs && cp stepcheck-studio-preview.html docs/index.html && git add -A && git commit -m "launch: replay + kit" && git push
```
Then enable Pages on `main /docs`. If anything in the benchmark changes first, run `stepcheck benchmark && stepcheck review && stepcheck preview` before step 3 so the numbers in this file, the report and the replay agree.
