"""Slice-by-slice table from the enterprise_scale.<label>.json receipts (one column per label,
default Slice 35 / 36 / 37); writes receipts/enterprise_scale.json (the combined receipt the
paper cites).
usage: compare_enterprise_scale.py [label ...]        e.g. compare_enterprise_scale.py slice35 slice36 slice37"""
import json
import sys
from pathlib import Path

R = Path(__file__).resolve().parent / "receipts"
LABELS = sys.argv[1:] or ["slice35", "slice36", "slice37"]


def load(label):
    p = R / f"enterprise_scale.{label}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


RUNS = [load(lb) for lb in LABELS]
FULL = [load(lb + "-fullrepo") for lb in LABELS]


def ms(d):
    return (f"p50 {d['p50']} / p95 {d['p95']} / max {d['max']} ms; <25 ms {d['under_25ms_pct']}%, <50 ms {d['under_50ms_pct']}%"
            if d and d.get("n") else "—")


def mono(r, key):
    m = (r or {}).get("results", {}).get("1_monoliths") or {}
    return ms(m.get(key)) if m else "—"


def repo(r, fn):
    x = (r or {}).get("results", {}).get("2_repository") or {}
    if not x:
        return "—"
    if "init_session_crash" in x:
        return f"CRASH after {x['seconds_before_crash']} s: {x['init_session_crash'][:70]}"
    try:
        return fn(x)
    except (KeyError, TypeError):
        return "—"


def first(runs, section):
    for r in runs:
        v = (r or {}).get("results", {}).get(section)
        if v:
            return v
    return {}


def ci(x):
    return f"{x['ci']['cold']['seconds']} s / {x['ci']['warm']['seconds']} s, exit {x['ci']['warm']['exit']}"


rows = []
m = first(RUNS, "1_monoliths")
rows.append([f"Monolith files ({m.get('files')} files, {m.get('loc_total', 0):,} LOC): dry-run commit, one function edited",
             *[mono(r, "dry_run_commit") for r in RUNS]])
rows.append(["Monolith files: landed commit", *[mono(r, "landed_commit") for r in RUNS]])
rows.append(["Monolith files: init_session", *[mono(r, "init") for r in RUNS]])
rows.append(["Monolith files: focused checkout", *[mono(r, "checkout") for r in RUNS]])
x = first(RUNS, "2_repository")
rows.append([f"django package ({x.get('tracked_files')} files, {x.get('loc', 0):,} LOC): cold init_session",
             *[repo(r, lambda x: f"{x['init_session_s']} s ({x['init_files_per_s']} files/s)") for r in RUNS]])
rows.append(["django package: peak memory (tracemalloc / RSS) / session file",
             *[repo(r, lambda x: f"{x['tracemalloc_peak_mb']} MB / {x['peak_rss_mb']} MB / {x.get('session_file_mb', '?')} MB") for r in RUNS]])
rows.append(["django package: in-process PreToolUse Edit hook on db/models/sql/query.py", *[repo(r, lambda x: ms(x["hook_edit_ms"])) for r in RUNS]])
rows.append(["django package: PreToolUse Read hook", *[repo(r, lambda x: ms(x["hook_read_ms"])) for r in RUNS]])
rows.append(["django package: fresh-process session rehydrate + locate", *[repo(r, lambda x: f"{x['fresh_process_rehydrate_ms']} ms") for r in RUNS]])
rows.append(["django package: stepcheck ci cold / warm", *[repo(r, ci) for r in RUNS]])
xf = first(FULL, "2_repository")
rows.append([f"full django tree ({xf.get('tracked_files')} files, {xf.get('loc', 0):,} LOC): cold init_session",
             *[repo(r, lambda x: f"{x['init_session_s']} s ({x['init_files_per_s']} files/s)") for r in FULL]])
rows.append(["full django tree: peak memory / session file", *[repo(r, lambda x: f"{x['tracemalloc_peak_mb']} MB / {x['session_file_mb']} MB") for r in FULL]])
rows.append(["full django tree: PreToolUse Edit hook", *[repo(r, lambda x: ms(x["hook_edit_ms"])) for r in FULL]])
rows.append(["full django tree: fresh-process session rehydrate + locate", *[repo(r, lambda x: f"{x['fresh_process_rehydrate_ms']} ms") for r in FULL]])
rows.append(["full django tree: stepcheck ci cold / warm", *[repo(r, ci) for r in FULL]])


def noise(r):
    n = (r or {}).get("results", {}).get("3_noise") or {}
    return (f"{n.get('noise_tracked_count')} noise files tracked of {n.get('files_in_tree')} "
            f"({len(n.get('gitignored_tracked', []))} gitignored), init {n.get('init_ms')} ms" if n else "—")


rows.append(["Noise tree (migrations, _pb2, .min.js, .d.ts, vendor, dist, build, .gitignored)", *[noise(r) for r in RUNS]])


def resil(r):
    z = (r or {}).get("results", {}).get("4_resilience") or {}
    out = []
    for k in ("nesting_120", "nesting_400"):
        v = z.get(k, {})
        out.append(f"{k}: {'crash' if 'crash' in v else v.get('commit', '?')}")
    c = z.get("circular_wildcard", {})
    out.append(f"circular+*: {'crash' if 'crash' in c else 'ok'}")
    b = z.get("bom_crlf", {})
    out.append(f"BOM/CRLF: {'ok' if b.get('commit_accepted') else 'crash' if 'crash' in b else '?'}")
    return "; ".join(out) if z else "—"


rows.append(["Resilience", *[resil(r) for r in RUNS]])
columns = [{"label": lb, "kernel_commit": (r or {}).get("kernel_commit"), "backend_dirty": (r or {}).get("backend_dirty")}
           for lb, r in zip(LABELS, RUNS)]
out = {"labels": LABELS, "columns": columns, "table": rows,
       # the two-column fields the Slice 36 receipt carried, kept for readers of that shape
       "before": LABELS[0], "after": LABELS[-1], "before_kernel": columns[0]["kernel_commit"],
       "after_kernel": columns[-1]["kernel_commit"], "after_dirty": columns[-1]["backend_dirty"]}
(R / "enterprise_scale.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
heads = [f"{c['label']} ({c['kernel_commit']}{' +dirty' if c['backend_dirty'] else ''})" for c in columns]
print("| Measurement | " + " | ".join(heads) + " |")
print("| --- | " + " | ".join("---" for _ in heads) + " |")
for r in rows:
    print("| " + " | ".join(str(c) for c in r) + " |")
