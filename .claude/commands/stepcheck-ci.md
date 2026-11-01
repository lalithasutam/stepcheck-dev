---
description: Gate a commit — `stepcheck ci .` and the full pytest suite must pass (zero DIRTY nodes, zero SHA-256 drift) before anything is committed or pushed
---

Pre-commit gate for this repository. Optional commit message: `$ARGUMENTS`

1. **Kernel gate.** From the repo root (project venv) run `stepcheck ci .`. It must end with `stepcheck ci: PASS`. It is ephemeral — it writes nothing under `.stepcheck/`. On `FAIL`, quote the phase and the first problem verbatim and stop:
   - `parse` — a module does not parse; the message names the file and line.
   - `attestations` — a node holds `DIRTY_OMISSION_RISK` (a dependency's exports changed: check it out and re-verify it, see `/stepcheck-fix` step 6), or a file's on-disk bytes differ from its latest attested `sha256` (it was edited outside the gates: open a fresh session and re-commit it through `commit_verified_step`, or revert the edit).
   - `gates` — a module failed Gate A/B/C against its own invariants; the message names module and violation.
2. **Tests.** `cd backend && python -m pytest -q`; every test must pass, and the count must match the figure in `README.md`, `LAUNCH.md` and `CLAUDE.md` (update them in the same commit if it changed).
3. **Tree.** `git status --short`: nothing under `.stepcheck/`, no `.claude/settings.local.json`, no stray receipts with private paths.
4. **Commit.** Only when 1–3 pass: if a message was given, `git add -A && git commit -m "<message>"`; push to `origin main` only if the user asked for a push. With no message, stop and report "ready to commit".
