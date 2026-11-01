---
description: Audit local Claude Code transcripts — cache-cliff waste and Read-tool bloat versus AST skeleton checkouts — and summarise the receipt
---

Run StepCheck's audit over local agent transcripts. Arguments (optional): `$ARGUMENTS` — a `.jsonl` transcript or a directory of them (default `~/.claude/projects/`), plus `--limit N` for the N most recent files.

1. Run `stepcheck audit $ARGUMENTS --out <scratch dir>/stepcheck-audit.html` from the repo root (project venv). Write the receipt outside the tree unless the user asks otherwise: the checked-in `stepcheck-audit.html` is the clean sample fixture and must not be overwritten.
2. Summarise the terminal output:
   - sessions and assistant turns audited (say so if it fell back to the bundled sample);
   - **cache-cliff waste** — turns resumed more than 5 minutes after the previous one, tokens re-written at full input rate, and the dollars paid above cache-read price;
   - **AST read bloat** — tokens pulled with the Read tool versus the same files as `focus=[]` skeleton checkouts (percentage and dollars);
   - **regressions a gate would have blocked** — edits that dropped a decorator or a leading guard, with their retry loops.
3. Give the receipt path. The header shows the log directory as `~/…`; the body still contains session ids and file names from other projects, so do not commit or publish a receipt without anonymising it first (`docs/audit.html` is the published, anonymised example).
