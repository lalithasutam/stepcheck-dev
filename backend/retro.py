"""`stepcheck retro` and `stepcheck diff`: the gates run over git history and over a
working tree, with nothing landed and nothing written.

retro  walks the last N non-merge commits with batch plumbing (`git log`, `git diff-tree`,
       one `git cat-file --batch` for every blob) and judges each modified supported source
       file's transition parent -> child through `StateKernel.judge_transition` (Gates A/B/C
       in an in-memory single-module session). Findings are classified:
         Tier 1 — silent regressions, shown by default: a guard dropped, flipped or neutered
                  inside a surviving function, an exception handler widened or swallowing
                  (Gate C), a body replaced by a stub (Gate B BODY_STUBBED), a decorator or
                  `@overload` stripped from a surviving symbol.
         Tier 2 — structural removals, counted in the footer and listed with --all: a whole
                  symbol or signature deleted, a mass-deletion refactor, a call into a
                  dependency removed.
       Test files are skipped unless --all; generated paths always.
diff   judges the working tree (or --staged, the index; or --base <ref>, a PR) against the
       baseline blobs the same way, as a table, as Markdown for a PR comment, or as JSON.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from kernel import StateKernel, _okf

TEST_PATH = re.compile(r"(^|/)(tests?|testing|__tests__|spec)(/|$)|(^|/)(test_[^/]*|[^/]*_test|conftest)\.[a-z]+$|\.(spec|test)\.[a-z]+$", re.I)
_SYMBOL_IN = re.compile(r"preserved symbol '([^']+)'|symbol '([^']+)' body|invariant '([^']+)'|invariant \"([^\"]+)\"")
TIER1_CODES = {"INTRA_NODE_BODY_STUBBED"}


# ------------------------------------------------------------------ git plumbing


def git(root: Path, *args: str, binary: bool = False, stdin: bytes | None = None, check: bool = True):
    done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, input=stdin, timeout=600)
    if check and done.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {done.stderr.decode('utf-8', 'replace').strip()[:200]}")
    return done.stdout if binary else done.stdout.decode("utf-8", "replace")


def repo_root(path: Path) -> Path | None:
    done = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return Path(done.stdout.strip()) if done.returncode == 0 and done.stdout.strip() else None


_RAW_ENTRY = re.compile(r"^:(\d+) (\d+) ([0-9a-f]+) ([0-9a-f]+) M$")


def recent_commits(root: Path, n: int) -> list[dict]:
    """The last `n` non-merge commits reachable from HEAD, newest first, each with the
    files it modified in place as (path, parent blob, child blob) — one `git log --raw`
    for the whole walk, not one `diff-tree` per commit."""
    out = git(root, "log", "--no-merges", f"-n{n}", "--raw", "-z", "--no-renames",
              "--format=%x01%H%x1f%ct%x1f%s%x02", check=False)  # every commit counts, modified files are filtered below
    rows = []
    for chunk in out.split("\x01")[1:]:
        header, _, raw = chunk.partition("\x02")
        parts = header.split("\x1f")
        if len(parts) != 3 or not parts[0]:
            continue
        files: list[tuple[str, str, str]] = []
        fields = [f.strip("\n") for f in raw.split("\0")]
        i = 0
        while i + 1 < len(fields):
            m = _RAW_ENTRY.match(fields[i])
            if m and fields[i + 1]:
                files.append((fields[i + 1], m.group(3), m.group(4)))
                i += 2
            else:
                i += 1
        rows.append({"sha": parts[0], "time": int(parts[1]), "subject": parts[2], "files": files})
    return rows


def modified_files(root: Path, commit: str) -> list[tuple[str, str, str]]:
    """(path, parent blob, child blob) for every file one commit modified in place."""
    raw = git(root, "diff-tree", "-r", "-z", "--no-commit-id", "--diff-filter=M", "--no-renames", commit)
    fields = raw.split("\0")
    out = []
    i = 0
    while i + 1 < len(fields):
        m = _RAW_ENTRY.match(fields[i])
        if m:
            out.append((fields[i + 1], m.group(3), m.group(4)))
        i += 2
    return out


def cat_blobs(root: Path, specs: list[str]) -> dict[str, bytes]:
    """One `git cat-file --batch` for every blob sha or `<rev>:<path>` spec."""
    if not specs:
        return {}
    raw = git(root, "cat-file", "--batch", binary=True, stdin=("\n".join(specs) + "\n").encode("utf-8"))
    out: dict[str, bytes] = {}
    pos = 0
    for spec in specs:
        nl = raw.find(b"\n", pos)
        if nl < 0:
            break
        header = raw[pos:nl].decode("utf-8", "replace").split(" ")
        if len(header) >= 3 and header[1] == "blob":
            size = int(header[2])
            out[spec] = raw[nl + 1: nl + 1 + size]
            pos = nl + 1 + size + 1
        else:  # "missing"
            pos = nl + 1
    return out


def is_test_path(rel: str) -> bool:
    return bool(TEST_PATH.search(rel.replace("\\", "/")))


def supported(rel: str) -> bool:
    return _okf.language(rel) != "other" and not _okf.is_generated_path(rel)


def decode(raw: bytes) -> str | None:
    try:
        return _okf.decode_source(raw)
    except UnicodeDecodeError:
        return None


# ------------------------------------------------------------------ judging


def classify(verdict, before_text: str, after_text: str) -> tuple[str, str]:
    """(tier, symbol) for a rejection: "1" silent regression, "2" structural removal,
    "env" probes could not run here, "parse" the text does not parse."""
    gate, err = verdict.gate, verdict.error
    text = str(err)
    subtype = getattr(err, "subtype", None)
    m = _SYMBOL_IN.search(text)
    sym = next((g for g in (m.groups() if m else ()) if g), "module")
    if gate == "A":
        return "parse", sym
    if gate == "C":
        if subtype == "ENVIRONMENT" or "failed to load for callable invariants" in text:
            return "env", sym  # the single-module session has no siblings to import: the probes could not run
        if sym.startswith("guard:"):
            sym = sym.split(":", 2)[1]
        elif sym.startswith("call:"):
            sym = sym[5:].split("(")[0]
        return "1", sym
    # Gate B
    if subtype in TIER1_CODES:
        return "1", sym
    if subtype == "INTRA_NODE_SYMBOL_DROPPED":
        if sym.startswith("@"):  # a decorator: Tier 1 when the decorated symbol survives
            owner = sym.split(" on ", 1)[1].split(" x")[0] if " on " in sym else None
            if owner and re.search(rf"^\s*(?:async\s+)?(?:def|class)\s+{re.escape(owner.split('.')[-1])}\b", after_text, re.M):
                return "1", owner
            return "2", owner or sym
        if sym.startswith(("def ", "class ")):
            return "2", sym.split(" ", 1)[1]
        if sym.startswith("call:"):
            return "2", sym[5:]
        return "2", sym
    return "2", sym


def contract(kernel: StateKernel, rel: str, source: str, root: Path, run_probes: bool) -> list[str]:
    """What a judgement holds the module to: every mined invariant with probes, every
    guard clause structurally without them."""
    return kernel.mined_invariants(rel, source, root=root) if run_probes else kernel.structural_guards(rel, source, root=root)


def guard_diff(kernel: StateKernel, rel: str, before: str, after: str, root: Path, run_probes: bool = True) -> tuple[list[str], list[str]]:
    b, a = set(contract(kernel, rel, before, root, run_probes)), set(contract(kernel, rel, after, root, run_probes))
    return sorted(b - a), sorted(a - b)


def judge(kernel: StateKernel, root: Path, rel: str, before: str, after: str, run_probes: bool = True) -> dict | None:
    """One transition through the gates; None when it is accepted."""
    t0 = time.perf_counter()
    v = kernel.judge_transition(rel, before, after, root=root, run_probes=run_probes)
    ms = (time.perf_counter() - t0) * 1000
    if v.accepted:
        return None
    tier, symbol = classify(v, before, after)
    row = {"path": rel, "symbol": symbol, "gate": v.gate, "subtype": getattr(v.error, "subtype", None),
           "tier": tier, "message": str(v.error)[:300], "ms": round(ms, 1)}
    if tier in ("1", "2"):
        removed, added = guard_diff(kernel, rel, before, after, root, run_probes)
        row["guards_removed"], row["guards_added"] = removed[:6], added[:6]
    return row


def _judge_one(kernel: StateKernel, root: Path, path: str, before: str, after: str, run_probes: bool) -> tuple[int, dict | None]:
    """(guards on record for `before`, finding or None) — the unit a worker computes."""
    return len(contract(kernel, path, before, root, run_probes)), judge(kernel, root, path, before, after, run_probes=run_probes)


def _judge_batch(args) -> list[tuple[int, int, dict | None]]:
    """A worker process: judge a batch of (index, path, before, after) transitions."""
    root, items, run_probes = args
    os.environ.setdefault("STEPCHECK_HOOK_AUTOSTART", "0")
    kernel = StateKernel(ephemeral=True)
    out = []
    for i, path, before, after in items:
        try:
            guards, row = _judge_one(kernel, Path(root), path, before, after, run_probes)
        except Exception as exc:  # noqa: BLE001 — one odd blob must not sink the walk
            guards, row = 0, {"path": path, "symbol": "module", "gate": "A", "subtype": None, "tier": "parse",
                              "message": f"{type(exc).__name__}: {str(exc)[:200]}", "ms": 0}
        out.append((i, guards, row))
    return out


def default_jobs() -> int:
    """Worker processes for a walk: the machine's cores up to 8, 1 when it has one."""
    env = os.environ.get("STEPCHECK_RETRO_JOBS")
    if env and env.isdigit():
        return max(1, int(env))
    return max(1, min(8, (os.cpu_count() or 2) - 1))


def judge_history(root: Path, commits: int = 50, include_all: bool = False, time_budget: float | None = None,
                  run_probes: bool = False, jobs: int | None = None) -> dict:
    """Every commit's modified source files through the gates. `time_budget` (seconds)
    stops early for a teaser and says so. Structural by default (`run_probes=False`): a
    historical blob has no sibling modules on disk for the sandbox, and every Tier 1 catch
    is an AST fact; `--probes` adds the runtime `call:` transition checks. Transitions are
    independent, so `jobs` worker processes judge them side by side (1: in this process)."""
    t0 = time.perf_counter()
    kernel = StateKernel(ephemeral=True)
    rows = recent_commits(root, commits)
    plan: list[tuple[dict, str, str, str]] = []
    skipped = {"tests": 0, "generated_or_other": 0, "undecodable": 0}
    for c in rows:
        for path, old, new in c.get("files", ()):
            if not supported(path):
                skipped["generated_or_other"] += 1
                continue
            if is_test_path(path) and not include_all:
                skipped["tests"] += 1
                continue
            plan.append((c, path, old, new))
    blobs = cat_blobs(root, sorted({b for _c, _p, o, n in plan for b in (o, n)}))
    git_ms = (time.perf_counter() - t0) * 1000
    findings: list[dict] = []
    judged = 0
    guards_audited = 0
    env = parse_skipped = 0
    unparsable: list[dict] = []
    truncated = False
    work: list[tuple[int, str, str, str]] = []
    for i, (c, path, old, new) in enumerate(plan):
        before, after = decode(blobs.get(old, b"")), decode(blobs.get(new, b""))
        if before is None or after is None or not before.strip():
            skipped["undecodable"] += 1
            continue
        work.append((i, path, before, after))
    jobs = jobs if jobs is not None else default_jobs()
    if time_budget is not None:
        jobs = 1  # a teaser stops on the clock, which only an in-process walk can watch
    results: dict[int, tuple[int, dict | None]] = {}
    if jobs <= 1 or len(work) < 4:
        for i, path, before, after in work:
            if time_budget is not None and time.perf_counter() - t0 > time_budget:
                truncated = True
                break
            results[i] = _judge_one(kernel, root, path, before, after, run_probes)
    else:
        from concurrent.futures import ProcessPoolExecutor

        # the biggest texts first, dealt round-robin, so every worker carries a similar load
        order = sorted(work, key=lambda w: -(len(w[2]) + len(w[3])))
        batches = [order[k::jobs] for k in range(jobs)]
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            for batch_out in pool.map(_judge_batch, [(str(root), b, run_probes) for b in batches if b]):
                for i, guards, row in batch_out:
                    results[i] = (guards, row)
    for i, (c, path, _old, _new) in enumerate(plan):
        if i not in results:
            continue
        judged += 1
        guards, row = results[i]
        guards_audited += guards
        if row is None:
            continue
        if row["tier"] == "env":
            env += 1
            continue
        if row["tier"] == "parse":
            parse_skipped += 1
            unparsable.append({"sha": c["sha"][:7], "path": path, "message": row["message"][:200]})
            continue
        row.update({"sha": c["sha"], "short": c["sha"][:7], "time": c["time"], "when": when(c["time"]), "subject": c["subject"]})
        findings.append(row)
    findings.sort(key=lambda f: (-f["time"], f["path"]))
    return {"root": str(root), "commits_scanned": len(rows), "files_planned": len(plan), "files_judged": judged,
            "guards_audited": guards_audited, "run_probes": run_probes, "jobs": jobs,
            "skipped": skipped, "environment_skipped": env, "unparsable_skipped": parse_skipped, "unparsable": unparsable,
            "truncated_by_time_budget": truncated, "git_ms": round(git_ms, 1), "seconds": round(time.perf_counter() - t0, 2),
            "tier1": [f for f in findings if f["tier"] == "1"], "tier2": [f for f in findings if f["tier"] == "2"]}


def judge_worktree(root: Path, base: str | None = None, staged: bool = False) -> dict:
    """The working tree (or the index with `staged`, or the tree against `base`) through
    the gates, file by file, against the baseline blob of each modified file."""
    t0 = time.perf_counter()
    kernel = StateKernel(ephemeral=True)
    if base and "..." in base:
        a, b = base.split("...", 1)
        base = git(root, "merge-base", a, b or "HEAD").strip()
    base_rev = base or "HEAD"
    if staged:
        names = git(root, "diff", "--cached", "--name-status", "-z", "--no-renames", base_rev, check=False)
    else:
        names = git(root, "diff", "--name-status", "-z", "--no-renames", base_rev, check=False)
    fields = [f for f in names.split("\0")]
    changed: list[tuple[str, str]] = []
    i = 0
    while i + 1 < len(fields):
        status, path = fields[i], fields[i + 1]
        i += 2
        if status and path:
            changed.append((status[0], path))
    plan = [(st, p) for st, p in changed if st in ("M", "A") and supported(p)]
    specs = [f"{base_rev}:{p}" for st, p in plan if st == "M"] + ([f":0:{p}" for st, p in plan] if staged else [])
    blobs = cat_blobs(root, specs)
    rows: list[dict] = []
    judged = guards = 0
    for st, p in plan:
        if staged:
            after_raw = blobs.get(f":0:{p}")
        else:
            try:
                after_raw = (root / p).read_bytes()
            except OSError:
                after_raw = None
        after = decode(after_raw) if after_raw is not None else None
        if after is None:
            continue
        if st == "A":  # a new file: the parse is its only contract
            v = kernel.judge_transition(p, after, after, root=root)
            if not v.accepted and v.gate == "A":
                rows.append({"path": p, "symbol": "module", "gate": "A", "tier": "parse", "message": str(v.error)[:300], "status": st})
            continue
        before = decode(blobs.get(f"{base_rev}:{p}", b""))
        if before is None or not before.strip():
            continue
        judged += 1
        guards += len(kernel.mined_invariants(p, before, root=root))
        row = judge(kernel, root, p, before, after)
        if row is not None:
            row["status"] = st
            rows.append(row)
    return {"root": str(root), "base": base_rev, "staged": staged, "files_changed": len(changed), "files_judged": judged,
            "guards_audited": guards, "seconds": round(time.perf_counter() - t0, 2),
            "tier1": [r for r in rows if r["tier"] == "1"], "tier2": [r for r in rows if r["tier"] == "2"],
            "parse": [r for r in rows if r["tier"] == "parse"], "environment": [r for r in rows if r["tier"] == "env"]}


# ------------------------------------------------------------------ rendering


def when(ts: int) -> str:
    d = dt.datetime.fromtimestamp(ts, dt.timezone.utc)
    delta = dt.datetime.now(dt.timezone.utc) - d
    days = delta.days
    rel = ("today" if days <= 0 else "yesterday" if days == 1 else f"{days} days ago" if days < 60
           else f"{days // 30} months ago" if days < 730 else f"{days // 365} years ago")
    return f"{d:%Y-%m-%d} ({rel})"


def _badge(row: dict) -> str:
    code = row.get("subtype") or ("GUARD" if row["gate"] == "C" else row["gate"])
    return f"Gate {row['gate']} · {code.replace('INTRA_NODE_', '')}"


def _guard_lines(row: dict, width: int = 110) -> list[str]:
    out = []
    for g in row.get("guards_removed", []):
        out.append(f"      - {g[:width]}")
    for g in row.get("guards_added", [])[:2]:
        out.append(f"      + {g[:width]}")
    if not out:
        out.append(f"      ! {row['message'][:width]}")
    return out


def render_history(r: dict, show_all: bool = False) -> str:
    mode = "structural gates; --probes adds the runtime call: checks" if not r.get("run_probes") else "structural + runtime probes"
    lines = [f"stepcheck retro — {r['root']}", f"  {r['commits_scanned']} commits, {r['files_judged']} file transitions judged, "
             f"{r['guards_audited']:,} guards audited in {r['seconds']} s (git plumbing {r['git_ms']:.0f} ms; {r.get('jobs', 1)} worker(s); {mode})", ""]
    if r["tier1"]:
        lines.append(f"  Tier 1 — silent regressions ({len(r['tier1'])}):")
        for f in r["tier1"]:
            lines.append(f"  {f['short']}  {f['when']}  {f['path']} :: {f['symbol']}  [{_badge(f)}]")
            lines.append(f"      {f['subject'][:90]}")
            lines += _guard_lines(f)
    else:
        lines.append("  Tier 1 — silent regressions: none")
    if show_all and r["tier2"]:
        lines.append("")
        lines.append(f"  Tier 2 — structural removals ({len(r['tier2'])}):")
        for f in r["tier2"]:
            lines.append(f"  {f['short']}  {f['when']}  {f['path']} :: {f['symbol']}  [{_badge(f)}]")
            lines.append(f"      {f['subject'][:90]}")
            lines += _guard_lines(f)
    lines.append("")
    foot = [f"{len(r['tier2'])} structural removal(s)" + ("" if show_all else " hidden (--all shows them)"),
            f"{r['skipped']['tests']} test file(s) skipped" + ("" if show_all else " (--all includes them)"),
            f"{r['environment_skipped']} probe(s) needed packages this interpreter lacks", f"{r['unparsable_skipped']} unparsable"]
    if r.get("truncated_by_time_budget"):
        foot.append("stopped at the time budget")
    lines.append("  " + "; ".join(foot))
    return "\n".join(lines)


def render_worktree(r: dict) -> str:
    label = "index" if r["staged"] else "working tree"
    lines = [f"stepcheck diff — {label} vs {r['base']} in {r['root']}",
             f"  {r['files_changed']} changed file(s), {r['files_judged']} judged, {r['guards_audited']:,} guards audited in {r['seconds']} s"]
    for tier, title in (("tier1", "silent regressions"), ("tier2", "structural removals"), ("parse", "does not parse")):
        if r[tier]:
            lines.append(f"  {title} ({len(r[tier])}):")
            for f in r[tier]:
                lines.append(f"    {f['path']} :: {f['symbol']}  [{_badge(f)}]")
                lines += _guard_lines(f)
    if not (r["tier1"] or r["tier2"] or r["parse"]):
        lines.append("  clean: no gate violation")
    if r["environment"]:
        lines.append(f"  {len(r['environment'])} module(s) whose probes need packages this interpreter lacks")
    return "\n".join(lines)


def render_markdown(r: dict) -> str:
    bad = r["tier1"] + r["tier2"] + r["parse"]
    if not bad:
        return (f"**StepCheck** ✅ clean — {r['files_judged']} changed module(s) verified through Gates A/B/C against `{r['base']}`, "
                f"{r['guards_audited']:,} guard invariants audited, 0 violations.")
    out = [f"**StepCheck** ❌ {len(r['tier1'])} silent regression(s), {len(r['tier2'])} structural removal(s), {len(r['parse'])} parse failure(s) "
           f"against `{r['base']}` ({r['files_judged']} module(s) judged, {r['guards_audited']:,} guards audited)", "",
           "| file :: symbol | gate | what changed |", "| --- | --- | --- |"]
    for f in bad:
        detail = "; ".join(f"- `{g}`" for g in f.get("guards_removed", [])[:3]) or f["message"][:160].replace("|", "\\|")
        out.append(f"| `{f['path']}` :: `{f['symbol']}` | {_badge(f)} | {detail} |")
    out.append("")
    out.append('A contract change that was asked for is declared with `stepcheck allow <file> <symbol> --reason "..."` before the edit.')
    return "\n".join(out)


# ------------------------------------------------------------------ CLI entry points


def cmd_retro(args) -> int:
    root = repo_root(Path(args.path).resolve())
    if root is None:
        print(f"stepcheck retro: {Path(args.path).resolve()} is not inside a git repository", file=sys.stderr)
        return 2
    r = judge_history(root, commits=args.commits, include_all=args.all, run_probes=bool(getattr(args, "probes", False)),
                      jobs=getattr(args, "jobs", None))
    if args.json:
        print(json.dumps(r, indent=1, default=str))
    else:
        print(render_history(r, show_all=args.all))
    return 0


def cmd_diff(args) -> int:
    root = repo_root(Path(args.path).resolve())
    if root is None:
        print(f"stepcheck diff: {Path(args.path).resolve()} is not inside a git repository", file=sys.stderr)
        return 2
    try:
        r = judge_worktree(root, base=args.base, staged=args.staged)
    except RuntimeError as exc:
        print(f"stepcheck diff: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(r, indent=1, default=str))
    elif args.markdown:
        print(render_markdown(r))
    else:
        print(render_worktree(r))
    return 1 if (r["tier1"] or r["parse"]) else 0


def teaser(root: Path, budget_s: float = 1.0) -> str | None:
    """A one-line taste of `retro` for `stepcheck connect`, capped at `budget_s`."""
    try:
        if repo_root(root) is None or not recent_commits(root, 1):
            return None
        r = judge_history(root, commits=20, time_budget=budget_s)
    except Exception:  # noqa: BLE001 — a teaser never breaks setup
        return None
    n1 = len(r["tier1"])
    tail = " (partial: stopped at 1 s)" if r["truncated_by_time_budget"] else ""
    if n1:
        first = r["tier1"][0]
        return (f"  retro    : {n1} silent regression(s) in the last {r['commits_scanned']} commits{tail} — e.g. {first['short']} "
                f"{first['path']} :: {first['symbol']} [{_badge(first)}]. Run `stepcheck retro .` for the full report.")
    return f"  retro    : no silent regression in the last {r['commits_scanned']} commits ({r['guards_audited']:,} guards audited{tail}). Try `stepcheck retro . --commits 50`."


__all__ = ["cmd_retro", "cmd_diff", "judge_history", "judge_worktree", "render_history", "render_worktree", "render_markdown", "teaser"]
_ = io  # (kept for callers that redirect stdout around cmd_* in tests)
