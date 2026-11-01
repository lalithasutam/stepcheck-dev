# StepCheck Dev — launch kit

Every number below is read from the repo as it stands, not rounded up:

| Metric | Value | Source |
| --- | --- | --- |
| Kernel + gateway | see `wc -l backend/kernel/*.py backend/server.py` (≈1,900 LOC after the mining + audit pass) | `wc -l` |
| Tests | 95, all at the public seams (kernel API, HTTP/MCP, CLI), zero mocks of internals, ~3–14 s depending on OS (includes the live 50-turn benchmark gate and a real uvicorn MCP round-trip) | `python -m pytest -q` |
| 50-turn benchmark | 132,779 raw → 15,662 compacted tokens, 88.2% saved, $0.3514 at $3.00/MTok | `benchmarks/results.json` |
| Real-log audit | 116 Claude Code sessions, 5,330 assistant turns, 67 cache-cliff resumes re-writing 4,950,678 tokens, $13.37 paid above cache-read price | `docs/audit.html` (file names and session IDs anonymized) |
| Catches | T20 Gate B `INTRA_NODE_SYMBOL_DROPPED` · T25 Gate B `INTER_NODE_DIRTY` (accepted, `api`+`workers` dirtied, finalize blocked) · T35 Gate C `call:charge(account="x", amount_cents=0) raises ValueError` (auto-mined — payments.py has no annotations) · T36 Gate A locked mutation | `stepcheck benchmark` |

Don't quote 88.7%, 88.5% or 0.29s anywhere. Those were earlier runs; the T25 signature-change turn costs a little more than an append, and the suite now runs the benchmark itself.

---

## 1. Show HN

**Title (80 chars):**
Show HN: StepCheck – AST skeletons and 3 commit gates vs. agent context rot

**Alt title:**
Show HN: Cut a coding agent's context bill 88% and catch the turn-35 regression

**Post:**

I kept watching long agent sessions go bad the same way. Around turn 30 the model quietly deletes a decorator it stopped reading, the tests it still runs pass, and the bill is climbing because every turn re-reads every file. If you're past Anthropic's 5-minute cache window between turns (real refactors are), you pay full input rate for all of it again.

I measured it on my own logs: across 116 real Claude Code sessions and 5,330 assistant turns, `stepcheck audit` found $13.37 paid above cache-read price on turns resumed after the cache expired. In the repo's 50-turn benchmark, StepCheck cuts tokens by 88.2%, and 59 passing tests at the public seams back the kernel.

StepCheck is a small deterministic layer between the agent and the model that fixes both halves.

Context: the repo gets compiled into an OKF graph, one Markdown frame per module with strict YAML frontmatter (exports, deps, preserved symbols, invariants, attestations). The agent checks out one node at a time. With `focus=[charge]` it gets that function verbatim and the rest of the module as an AST skeleton: signatures, decorators, docstrings, bodies replaced with `...`, runs of constants folded to one line. Dependencies come as interface skeletons only. The agent commits a patch of AST ops (append / replace_symbol / delete_symbol) and the kernel folds it into canonical state. Telemetry charges the patch, not the module. Over the 50-turn benchmark that's 132,779 raw tokens vs 15,662 sent. 88.2%.

Correctness: every commit runs three gates before it lands.
- Gate A, mechanical: parses, exported names dependents import still exist, locked modules refuse everything.
- Gate B, omission: AST symbol fingerprinting. Drop a `@audit` decorator the frame lists in `preserved_symbols[]` and you get `OmissionError(INTRA_NODE_SYMBOL_DROPPED)`. Change an exported signature and the dependents flip to `DIRTY_OMISSION_RISK`; the session can't finalize until each one is checked out and re-verified.
- Gate C, logical: invariants in the frame's frontmatter, evaluated against `src` (normalized via `ast.unparse`, so whitespace can't trip them and comments can't satisfy them), `tree`, and `ns`, the staged module exec-loaded in an isolated namespace with project imports resolved to canonical sources. `call:charge("acct", 0) raises ValueError` is a one-liner, and you usually don't write it: leading `if …: raise` guards are mined into invariants automatically at index time. Runs under a step/wall-clock guard so a runaway loop is a deterministic LogicalError, not a hung process.

A passing commit appends a DSSE-style SHA-256 envelope to the frame. Replay the same session on another machine and you get byte-identical envelopes.

Two doors: a BYOK proxy for `/v1/chat/completions` and `/v1/messages` that prunes dead-end turns and injects the compact frame, and a Streamable HTTP MCP server at `/mcp` for Claude Code / Cursor. One port, `stepcheck up`.

What I'd like feedback on: the invariant language (string, AST, callable, is that the right ladder?), and whether anyone has a long-session trace they'd let me run through the gates.

Repo and a zero-install interactive replay of the benchmark (scrub turns, watch the graph go amber at T25, red at T20/T35/T36):

- Repo: https://github.com/lalithasutam/stepcheck-dev
- 50-turn interactive replay: https://lalithasutam.github.io/stepcheck-dev/ (jump to a moment: [T20](https://lalithasutam.github.io/stepcheck-dev/#t20), [T25](https://lalithasutam.github.io/stepcheck-dev/#t25), [T35](https://lalithasutam.github.io/stepcheck-dev/#t35), [T36](https://lalithasutam.github.io/stepcheck-dev/#t36))
- 116-session anonymized audit receipt: https://lalithasutam.github.io/stepcheck-dev/audit.html

---

## 2. Social

### X / Twitter thread

1/ Agents don't fail at turn 3. They fail at turn 35, when they stop re-reading the decorator they're about to delete. Tests pass. Bill climbs. Built a fix: StepCheck. 🧵

2/ The bill first. Past the 5-min cache window every turn re-reads every touched file at full rate. Over 50 turns on a 6-module repo that's 132,779 tokens. StepCheck sent 15,662. 88.2% less. Same edits, same gates passed.

3/ How: the repo compiles to OKF frames. Checkout with focus=[charge] gets that function in full and everything else as an AST skeleton. Deps arrive as interfaces only. Commits are AST patches folded into canonical state. You pay for the patch.

4/ Correctness: 3 deterministic gates on every commit.
A mechanical (parse, exports, locks)
B omission (symbol fingerprinting + dirty propagation)
C logical (invariants over normalized src, the AST, and the exec-loaded module)

5/ T20 in the benchmark: agent rewrites charge(), silently drops @audit. Gate B: INTRA_NODE_SYMBOL_DROPPED. T35: guard removed, statement count unchanged. payments.py has zero annotations; Gate C runs the invariant it mined from the guard itself, charge(amount_cents=0) doesn't raise. Rejected.

6/ T25 is the one I like. Legit signature change on payments.charge. Accepted. But api and workers go amber (DIRTY_OMISSION_RISK) and finalize is refused until both are re-verified. The thing agents never do on their own.

7/ Every passing commit gets a DSSE-style SHA-256 envelope. Deterministic across machines. 1,700 LOC, 32 tests at two seams, no mocks of internals.

8/ Try the interactive replay, no install, works on your phone: https://lalithasutam.github.io/stepcheck-dev/
Repo: [repo link]
`pip install -e . && stepcheck up` gives you the proxy, MCP server and Studio UI on one port.

### r/ClaudeAI · r/cursor post

**Title:** I built a deterministic "context firewall" MCP server for Claude Code / Cursor. 88.2% fewer tokens over 50 turns, and it caught the turn-35 regression. Interactive replay inside, no install.

Long sessions in Claude Code and Cursor have two problems that feed each other: the context fills with stale re-reads (and past the 5-minute cache window you pay full price for every one), and somewhere around turn 30 the model stops actually reading the code it's editing and drops something it shouldn't. A deleted decorator, a removed guard clause. Syntax is fine, tests still pass.

StepCheck is an MCP server (Streamable HTTP, `/mcp`) plus a BYOK proxy that sits between the agent and the model. The agent checks out one module frame at a time as an AST skeleton with only the function it's editing in full, commits a small AST patch, and the kernel runs three deterministic gates before anything lands: mechanical, omission (symbol fingerprinting + dependency dirty propagation), and logical (callable invariants like `call:charge("acct", 0) raises ValueError` executed against the staged module in an isolated namespace).

Numbers from the 50-turn benchmark in the repo, not estimates: 132,779 raw tokens → 15,662 sent (88.2%). Four injected events, four caught: T20 silent `@audit` drop (Gate B), T25 signature change dirtying two dependents and blocking finalize (Gate B propagation), T35 guard removed with identical statement count (Gate C), T36 mutation of a locked module (Gate A).

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

Honest limits: callable invariants execute the agent's staged code in-process (isolated namespace with a step/time guard, not a security sandbox; containerize for untrusted agents). Python projects only for now. Feedback on the invariant syntax is what I most want.

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
Expect `95 passed`, then the gateway banner. Open http://127.0.0.1:8420/studio/ for the Studio UI; it's in demo replay until you pass `?session=<id>` from `POST /v1/step/init`.

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
