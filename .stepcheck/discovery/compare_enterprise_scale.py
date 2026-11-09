"""Before (Slice 35) vs after (Slice 36) table from the enterprise_scale.*.json receipts;
writes receipts/enterprise_scale.json (the combined receipt the paper cites).
usage: compare_enterprise_scale.py [before_label] [after_label]"""
import json
import sys
from pathlib import Path

R = Path(__file__).resolve().parent / "receipts"
before, after = (sys.argv[1] if len(sys.argv) > 1 else "slice35"), (sys.argv[2] if len(sys.argv) > 2 else "slice36")


def load(label):
    p = R / f"enterprise_scale.{label}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


B, A = load(before), load(after)
Bf, Af = load(before + "-fullrepo"), load(after + "-fullrepo")
rows = []


def ms(d):
    return f"p50 {d['p50']} / p95 {d['p95']} / max {d['max']} ms; <25 ms {d['under_25ms_pct']}%, <50 ms {d['under_50ms_pct']}%" if d and d.get("n") else "—"


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


m = (B or {}).get("results", {}).get("1_monoliths") or (A or {}).get("results", {}).get("1_monoliths") or {}
rows.append([f"Monolith files ({m.get('files')} files, {m.get('loc_total', 0):,} LOC): dry-run commit, one function edited", mono(B, "dry_run_commit"), mono(A, "dry_run_commit")])
rows.append(["Monolith files: landed commit", mono(B, "landed_commit"), mono(A, "landed_commit")])
rows.append(["Monolith files: init_session", mono(B, "init"), mono(A, "init")])
rows.append(["Monolith files: focused checkout", mono(B, "checkout"), mono(A, "checkout")])
x = (A or {}).get("results", {}).get("2_repository") or (B or {}).get("results", {}).get("2_repository") or {}
rows.append([f"django package ({x.get('tracked_files')} files, {x.get('loc', 0):,} LOC): cold init_session",
             repo(B, lambda x: f"{x['init_session_s']} s ({x['init_files_per_s']} files/s)"), repo(A, lambda x: f"{x['init_session_s']} s ({x['init_files_per_s']} files/s)")])
rows.append(["django package: peak memory (tracemalloc / RSS)", repo(B, lambda x: f"{x['tracemalloc_peak_mb']} MB / {x['peak_rss_mb']} MB"),
             repo(A, lambda x: f"{x['tracemalloc_peak_mb']} MB / {x['peak_rss_mb']} MB")])
rows.append(["django package: in-process PreToolUse Edit hook on db/models/sql/query.py", repo(B, lambda x: ms(x["hook_edit_ms"])), repo(A, lambda x: ms(x["hook_edit_ms"]))])
rows.append(["django package: PreToolUse Read hook", repo(B, lambda x: ms(x["hook_read_ms"])), repo(A, lambda x: ms(x["hook_read_ms"]))])
rows.append(["django package: fresh-process session rehydrate", repo(B, lambda x: f"{x['fresh_process_rehydrate_ms']} ms"), repo(A, lambda x: f"{x['fresh_process_rehydrate_ms']} ms")])
rows.append(["django package: stepcheck ci cold / warm", repo(B, lambda x: f"{x['ci']['cold']['seconds']} s / {x['ci']['warm']['seconds']} s, exit {x['ci']['warm']['exit']}"),
             repo(A, lambda x: f"{x['ci']['cold']['seconds']} s / {x['ci']['warm']['seconds']} s, exit {x['ci']['warm']['exit']}")])
xf = (Af or {}).get("results", {}).get("2_repository") or (Bf or {}).get("results", {}).get("2_repository") or {}
rows.append([f"full django tree ({xf.get('tracked_files')} files, {xf.get('loc', 0):,} LOC): cold init_session",
             repo(Bf, lambda x: f"{x['init_session_s']} s ({x['init_files_per_s']} files/s)"), repo(Af, lambda x: f"{x['init_session_s']} s ({x['init_files_per_s']} files/s)")])
rows.append(["full django tree: peak memory / session file", repo(Bf, lambda x: f"{x['tracemalloc_peak_mb']} MB / {x['session_file_mb']} MB"),
             repo(Af, lambda x: f"{x['tracemalloc_peak_mb']} MB / {x['session_file_mb']} MB")])
rows.append(["full django tree: PreToolUse Edit hook", repo(Bf, lambda x: ms(x["hook_edit_ms"])), repo(Af, lambda x: ms(x["hook_edit_ms"]))])
rows.append(["full django tree: stepcheck ci cold / warm", repo(Bf, lambda x: f"{x['ci']['cold']['seconds']} s / {x['ci']['warm']['seconds']} s, exit {x['ci']['warm']['exit']}"),
             repo(Af, lambda x: f"{x['ci']['cold']['seconds']} s / {x['ci']['warm']['seconds']} s, exit {x['ci']['warm']['exit']}")])


def noise(r):
    n = (r or {}).get("results", {}).get("3_noise") or {}
    return f"{n.get('noise_tracked_count')} noise files tracked of {n.get('files_in_tree')} ({len(n.get('gitignored_tracked', []))} gitignored), init {n.get('init_ms')} ms" if n else "—"


rows.append(["Noise tree (migrations, _pb2, .min.js, .d.ts, vendor, dist, build, .gitignored)", noise(B), noise(A)])


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


rows.append(["Resilience", resil(B), resil(A)])
out = {"before": before, "after": after, "before_kernel": (B or {}).get("kernel_commit"), "after_kernel": (A or {}).get("kernel_commit"),
       "after_dirty": (A or {}).get("backend_dirty"), "table": rows}
(R / "enterprise_scale.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
print(f"| Measurement | Before ({before}, {out['before_kernel']}) | After ({after}, {out['after_kernel']}{' +dirty' if out['after_dirty'] else ''}) |")
print("| --- | --- | --- |")
for r in rows:
    print("| " + " | ".join(str(c) for c in r) + " |")
