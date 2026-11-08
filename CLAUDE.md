# StepCheck Dev — agent rules

Read `GLOSSARY.md` for the vocabulary. These rules bind Claude Code and Cursor
in this repo. The MCP section applies whenever an MCP server named `stepcheck`
is connected (`claude mcp list` / `.cursor/mcp.json`); if it isn't, say so once
and work normally.

## StepCheck MCP workflow (enforced when `stepcheck` is connected)

Tools: `init_project_session`, `checkout_context_frame`, `commit_verified_step`,
`lock_module_invariants`, `check_omission_risks`, `get_token_savings`.

1. **Open the session first.** Before touching any tracked Python module, call
   `init_project_session(project_root=<absolute repo path>)` once and keep the
   returned `session_id` for the whole task. Then call
   `lock_module_invariants(session_id, node_id)` on core / foundational modules
   (anything many nodes depend on and the task does not intend to change). A
   locked module rejects every mutation at Gate A; that is the point.

2. **Never read tracked modules whole.** Do not use the built-in Read / cat /
   file-view tools to pull a tracked `.py` into context. Call
   `checkout_context_frame(session_id, node_id, focus=[<symbols you will edit>])`
   instead. You get the focused defs verbatim, the rest of the module as an AST
   skeleton, and dependencies as interface skeletons. `focus=[]` is a pure
   skeleton for orientation. If a frame comes back `auto_skeletonized`, pick
   names from its symbol index and re-checkout with `focus=[…]`. Stay under
   the 4,000-token payload budget; never request several unfocused frames in a
   row. Files the kernel does not track (configs, docs, tests you are writing,
   non-Python) may be read normally.

3. **All code changes go through the gates.** Submit every edit to a tracked
   module as `commit_verified_step(session_id, node_id, patch=[…])` with ops
   `{"op":"append","code":…}`, `{"op":"replace_symbol","name":…,"code":…}`
   (decorators included in `code`) or `{"op":"delete_symbol","name":…}`.
   Do not write tracked modules with the editor tools and do not pass
   `source=` for whole-module rewrites unless the user asks for one. Read the
   verdict: `accepted:false` with `gate` A/B/C is a real rejection; fix the
   patch, never retry the same patch, and never use `allow_deletion=true` to
   silence Gate B without saying so in the summary. Preserve every symbol
   listed in the frame's `preserved_symbols[]`; keep `# okf-invariant:` lines and
   leading `if …: raise` guards (they are auto-mined into invariants; removing one
   is a Gate C rejection unless the user asked for it and you pass `allow_deletion`).

4. **Close cleanly.** Before declaring a task done call
   `check_omission_risks(session_id)`. If `dirty` is non-empty, check out each
   listed node (`focus=[]` is enough to see what changed) and re-commit it so it
   returns to VERIFIED; `can_finalize` must be `true`. Then call
   `get_token_savings(session_id)` and print its `raw_bloated_tokens`,
   `compacted_okf_tokens`, `tokens_saved`, `dollars_saved` and
   `omissions_blocked` in the final summary, together with the attestation
   `sha256` of each commit you landed.

## Repo conventions (always)

- Tests live only at the two public seams (`backend/tests/`): Seam 1 is the
  `StateKernel` Python API, Seam 2 is the HTTP/MCP boundary in
  `backend/server.py`. Never mock internal modules, AST parsers, YAML, hashes.
  `_`-prefixed modules in `backend/kernel/` are implementation, not interface.
- Red → Green: a failing test at a seam before the implementation.
- Run `cd backend && python -m pytest -q` before finishing; 321 tests must pass,
  including the ≥85% benchmark gate. If you change the benchmark, regenerate
  with `stepcheck benchmark && stepcheck review && stepcheck preview` and keep
  README / LAUNCH figures in sync with `benchmarks/results.json`.
- Frontend lives in `frontend/` (Vite base `/studio/`); `npm run build` must
  pass with zero TypeScript errors.
