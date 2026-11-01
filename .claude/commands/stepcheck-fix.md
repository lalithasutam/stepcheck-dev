---
description: Fix an issue strictly through the StepCheck gates — focused checkout, Red→Green seam test, surgical patch commit, clear DIRTY dependents, finalize with the savings receipt
---

Fix this issue using only StepCheck MCP tools for every tracked Python module: `$ARGUMENTS`

Rules (see `CLAUDE.md`): never Read/cat a tracked `.py`, never edit one with the editor tools, every change lands as a `commit_verified_step` patch. Files the kernel does not track (configs, docs, the test you are writing) may be read and written normally.

1. **Session.** Reuse the `session_id` from `/stepcheck-session`; run it if there is none.
2. **Red.** Write or extend a test at a public seam in `backend/tests/` — Seam 1 is the `StateKernel` Python API, Seam 2 is the HTTP/MCP boundary in `backend/server.py`. Run it and confirm it fails for the right reason before touching any module. Never mock internal modules, parsers, YAML or hashes.
3. **Locate.** `checkout_context_frame(session_id, node_id, focus=[])` for orientation (skeleton + symbol index), then re-checkout with `focus=[<only the symbols you will edit>]`. Stay under the 4,000-token payload budget and never request several unfocused frames in a row. Note the frame's `preserved_symbols[]`, `invariants[]` and `invariants_auto_mined[]` — the patch must keep them.
4. **Patch.** `commit_verified_step(session_id, node_id, patch=[...])` with `{"op":"replace_symbol","name":…,"code":…}` (decorators and attached leading comments are part of the symbol), `{"op":"append","code":…}` (lands before a trailing `if __name__ == "__main__":` guard) or `{"op":"delete_symbol","name":…}`. Module-level imports cannot be patched: use local imports inside the function. Read every verdict: `accepted:false` with `gate` A/B/C is a real rejection — fix the patch, never resend the same one, never pass `allow_deletion=true` to silence Gate B or C unless the user asked for the deletion and you say so. Keep `# okf-invariant:` lines and leading `if …: raise` guards. Record each attestation `sha256`.
5. **Green.** Run the new test, then the whole suite: `cd backend && python -m pytest -q`.
6. **Dirty dependents.** `check_omission_risks(session_id)`. For every id in `dirty`, `checkout_context_frame(focus=[])`, adapt the caller to the changed signature (or re-commit an identical `replace_symbol` if nothing needs to change) until it returns `dirty: []` and `can_finalize: true`.
7. **Close.** `get_token_savings(session_id)`. The summary states `raw_bloated_tokens`, `compacted_okf_tokens`, `tokens_saved`, `dollars_saved`, `omissions_blocked`, the attestation `sha256` of every commit landed, and every gate rejection you hit with what you changed in response.
