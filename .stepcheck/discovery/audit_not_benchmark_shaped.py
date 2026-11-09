"""Zero-trust audit: is anything in Slices 35-37 benchmark-shaped, hardcoded to a corpus, or
fast because a check is silently skipped? Measurement only — nothing in backend/ is modified.
Receipt: receipts/not_benchmark_shaped_audit.json.

1. Static kernel purity: every line added to backend/ since the base commit (default 36c6280,
   v0.3.4; the working tree is diffed, so uncommitted Slice 37 counts) is scanned for
   corpus-specific literals; every exclusion pattern and every Gate A / ci exemption rule is
   printed verbatim for inspection.
2. Monolith fault-injection sensitivity: in the 15 largest cached modules, real faults are
   synthesised in guarded functions at the top, middle and bottom of each file (guard drop,
   relational flip, guard-action neuter, body stub) and committed through the fast path;
   catch rate and latency when blocking are reported.
3. Bisimulation: for >= 150 edits (monolith benign / multi-function / method / constant edits,
   every Audit-2 fault, SWE-bench gold patches), the fast path (stitched tree, segment reuse,
   memory + disk cache) is compared with a cold path (every in-memory cache cleared, empty
   disk cache, no stitched tree) and with a from-scratch analysis of the edited source, and
   Gate C is re-run with every probe in scope. Verdict, gate and invariant-set divergences
   are counted.
4. Zero-shot out-of-distribution trees never referenced by benchmark_enterprise_scale.py:
   fastapi, tornado, scrapy (shallow clones under _cache/ood) and the Martian online tree
   (Python + Rust): cold init, `stepcheck ci`, hook Edit latency, one clean edit, one
   injected guard fault.

usage: audit_not_benchmark_shaped.py [--base 36c6280] [--quick]
"""
from __future__ import annotations

import ast
import copy
import datetime as dt
import inspect
import io
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
RECEIPT = HERE / "receipts" / "not_benchmark_shaped_audit.json"
BASE = sys.argv[sys.argv.index("--base") + 1] if "--base" in sys.argv else "36c6280"
QUICK = "--quick" in sys.argv
if "--offline" not in sys.argv:
    sys.argv.append("--offline")  # the SWE-bench rows and base files come from the offline cache only
HOME = Path(tempfile.mkdtemp(prefix="sc-nbs-home-"))
os.environ["STEPCHECK_HOME"] = str(HOME)
os.environ["STEPCHECK_HOOK_AUTOSTART"] = "0"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(BACKEND))

import audit_loopholes as L  # noqa: E402  (unified-diff applier; imports verify_external_benchmarks as X)
import verify_external_benchmarks as X  # noqa: E402
_argv = sys.argv
sys.argv = [sys.argv[0]]
import benchmark_enterprise_scale as B  # noqa: E402  (largest_cached_modules, edit_one_function)
sys.argv = _argv

from kernel import StateKernel, _gates, _okf  # noqa: E402
import cli  # noqa: E402
import hooks  # noqa: E402

PY = sys.executable
T0 = time.time()


def say(*a) -> None:
    print(*a, flush=True)


def pct(values, q):
    s = sorted(values)
    return round(s[round(q * (len(s) - 1))], 1) if s else None


def lat(ms: list[float]) -> dict:
    return {"n": len(ms), "p50": pct(ms, .5), "p95": pct(ms, .95), "max": round(max(ms), 1) if ms else None}


def make_project(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="sc-nbs-"))
    for rel, src in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(src, encoding="utf-8", newline="\n")
    return root


def clear_kernel_caches() -> None:
    """Every in-memory memo the fast path leans on; the disk cache is avoided by a fresh root."""
    for name in ("_CONTENT_CACHE", "_SEGMENT_FACTS", "_PARSE_CACHE", "_SEGMENT_TABLES", "_SCOPE_CACHE",
                 "_RESOLVE_CACHE", "_LIGHT_FACTS", "_MODULE_MAP_CACHE", "_STMT_COUNT_CACHE"):
        d = getattr(_okf, name, None)
        if isinstance(d, dict):
            d.clear()
    for name in ("_SYNTAX_MEMO",):
        from kernel import _ts
        d = getattr(_ts, name, None)
        if isinstance(d, dict):
            d.clear()


# =============================================================== AUDIT 1: static purity

CORPUS_LITERALS = ["django", "matplotlib", "sympy", "astropy", "geos", "alphametics", "canitedit", "requests", "flask",
                   "swe-bench", "swebench", "bugsinpy", "martian", "scikit", "sklearn", "pandas", "numpy", "pytest-dev",
                   "pylint", "sphinx", "xarray", "seaborn", "psf/", "pallets"]


def benchmark_filenames() -> list[str]:
    """Every path-like string literal the enterprise benchmark names (its monolith corpus is
    discovered by size, so only the django/noise/resilience paths are literal)."""
    tree = ast.parse((HERE / "benchmark_enterprise_scale.py").read_text(encoding="utf-8"))
    out: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and re.search(r"\.(py|ts|js|go|rs|java|tsx)$", n.value):
            out.add(n.value.rsplit("/", 1)[-1])
    return sorted(out - {"__init__.py"})  # `__init__.py` is the language, not the benchmark


def added_lines(base: str) -> list[tuple[str, int, str]]:
    diff = subprocess.run(["git", "diff", base, "--", "backend/"], cwd=REPO, capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout
    out: list[tuple[str, int, str]] = []
    path, new_no = None, 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
            continue
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if m:
            new_no = int(m.group(1))
            continue
        if path is None or line.startswith(("---", "diff ", "index ")):
            continue
        if line.startswith("+"):
            out.append((path, new_no, line[1:]))
            new_no += 1
        elif line.startswith(" "):
            new_no += 1
    return out


def scan_literals(lines: list[tuple[str, int, str]], words: list[str]) -> list[dict]:
    hits = []
    for path, no, text in lines:
        low = text.lower()
        for w in words:
            if w.lower() in low:
                stripped = text.strip()
                where = ("comment" if stripped.startswith("#") or ("#" in text and text.index("#") < low.index(w.lower()))
                         else "docstring/prose" if (stripped.startswith(('"""', "'''", '"', "'")) or stripped.endswith(('"""', "'''")))
                         else "code")
                hits.append({"file": path, "line": no, "literal": w, "where": where, "text": text.strip()[:160]})
    return hits


def scan_tree_literals(words: list[str]) -> list[dict]:
    hits = []
    for p in sorted(BACKEND.rglob("*.py")):
        rel = str(p.relative_to(REPO)).replace("\\", "/")
        if "/tests/" in rel or "/benchmarks/" in rel:
            continue
        for no, text in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            low = text.lower()
            for w in words:
                if w.lower() in low:
                    stripped = text.strip()
                    where = "comment" if stripped.startswith("#") or ("#" in text and text.index("#") < low.index(w.lower())) else "code/prose"
                    hits.append({"file": rel, "line": no, "literal": w, "where": where, "text": stripped[:160]})
    return hits


def source_of(obj) -> str:
    try:
        return inspect.getsource(obj)
    except (OSError, TypeError):
        return "<source unavailable>"


def module_constants(path: Path, name_re: str) -> dict[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            if re.search(name_re, n.targets[0].id):
                out[n.targets[0].id] = ast.unparse(n.value)[:600]
    return out


def audit_static() -> dict:
    say(f"\n[1] static purity: git diff {BASE} -- backend/ (working tree)")
    lines = added_lines(BASE)
    files = sorted({p for p, _, _ in lines})
    words = CORPUS_LITERALS + benchmark_filenames()
    hits = scan_literals(lines, words)
    non_test = [h for h in hits if "/tests/" not in h["file"]]
    say(f"    {len(lines)} added lines in {len(files)} files; literal hits: {len(hits)} ({len(non_test)} outside tests)")
    for h in non_test:
        say(f"      {h['file']}:{h['line']} [{h['where']}] «{h['literal']}»  {h['text']}")
    tree_hits = scan_tree_literals(CORPUS_LITERALS)
    say(f"    whole backend/ (tests and benchmarks excluded) literal hits: {len(tree_hits)}")
    for h in tree_hits:
        say(f"      {h['file']}:{h['line']} [{h['where']}] «{h['literal']}»  {h['text']}")
    exclusions = {
        "_okf constants": module_constants(BACKEND / "kernel" / "_okf.py", r"EXCLUDED|GENERATED|MIGRATION|SUFFIX|_IMPORT_START|_PLAIN_YAML|ROOT_PACKAGE|LAZY|RULES_VERSION"),
        "cli constants": module_constants(BACKEND / "cli.py", r"_NEWER_GRAMMAR|_FM_|_CI_"),
        "kernel constants": module_constants(BACKEND / "kernel" / "__init__.py", r"LAZY_THRESHOLD|CHECKOUT_TOKEN_BUDGET"),
        "is_generated_path": source_of(_okf.is_generated_path),
        "_migration_dirs": source_of(_okf._migration_dirs),
        "_without_migrations": source_of(_okf._without_migrations),
        "tracked_files": source_of(_okf.tracked_files),
        "_git_visible": source_of(_okf._git_visible),
        "set_root_package / rooted_name / _package_of": source_of(_okf.set_root_package) + source_of(_okf.rooted_name) + source_of(_okf._package_of),
        "module_map": source_of(_okf.module_map),
    }
    gate_src = source_of(_gates.gate_a)
    exemptions = {
        "gate_a early returns (each `if` that returns before the dependents loop)": [
            ln.strip() for ln in gate_src.splitlines()
            if re.match(r"\s*(if |elif |return (None|tree)|light = |bound, star)", ln) and "raise" not in ln
        ],
        "_star_imports": source_of(_gates._star_imports),
        "_load_failure_subtype (ENVIRONMENT)": source_of(_gates._load_failure_subtype),
        "gate_c early return": [ln.strip() for ln in source_of(_gates.gate_c).splitlines() if "nothing on record" in ln or "if not invariants and not guard_invariants" in ln],
        "verify_node": source_of(StateKernel.verify_node),
        "_ci_parse classification": [ln.strip() for ln in source_of(cli._ci_parse).splitlines() if "_NEWER_GRAMMAR" in ln or "IndentationError" in ln or "_CI_UNPARSEABLE" in ln],
        "cmd_ci skip / ENV rules": [ln.strip() for ln in source_of(cli.cmd_ci).splitlines()
                                   if any(k in ln for k in ("stable", "ATTESTED", "ENVIRONMENT", "ENV", "unparsable", "attested"))],
        "init_session lazy rule": [ln.strip() for ln in source_of(StateKernel.init_session).splitlines() if "lazy" in ln.lower()][:8],
    }
    say("    exclusion patterns and exemption rules (verbatim):")
    for k, v in exclusions.items():
        say(f"    -- {k}")
        for ln in (v if isinstance(v, str) else json.dumps(v, indent=1)).splitlines():
            say(f"         {ln}")
    for k, v in exemptions.items():
        say(f"    -- {k}")
        for ln in (v if isinstance(v, str) else "\n".join(v)).splitlines():
            say(f"         {ln}")
    return {"base": BASE, "added_lines": len(lines), "files_touched": files, "literals_scanned": words,
            "literal_hits_in_diff": hits, "literal_hits_outside_tests": len(non_test),
            "literal_hits_whole_backend_non_test": tree_hits, "exclusions": exclusions, "exemptions": exemptions}


# =============================================================== AUDIT 2: fault injection


def guarded_functions(tree: ast.Module):
    """(dotted name, def node, leading-guard `if` node) for every top-level def or method whose
    first non-docstring statement is `if cond: raise …` / `if cond: return …` (the kernel's
    guard shape); no `else`, a single-statement body."""
    out = []

    def leading_guard(fn):
        body = fn.body
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
            body = body[1:]
        if body and isinstance(body[0], ast.If) and not body[0].orelse and len(body[0].body) == 1 \
                and isinstance(body[0].body[0], (ast.Raise, ast.Return)):
            return body[0]
        return None

    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            g = leading_guard(stmt)
            if g is not None:
                out.append((stmt.name, stmt, g))
        elif isinstance(stmt, ast.ClassDef):
            for m in stmt.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    g = leading_guard(m)
                    if g is not None:
                        out.append((f"{stmt.name}.{m.name}", m, g))
    return out


FLIPS = [("<=", "<"), (">=", ">"), ("==", "!="), ("!=", "=="), (" is not ", " is "), (" is ", " is not "), ("<", "<="), (">", ">=")]


def synth_faults(src: str, fn, guard) -> dict[str, str | None]:
    """fault kind -> mutated source (None when the shape does not allow it)."""
    lines = src.splitlines(keepends=True)
    out: dict[str, str | None] = {}
    g0, g1 = guard.lineno - 1, guard.end_lineno  # the if statement's lines
    indent = re.match(r"\s*", lines[g0]).group(0)
    # guard drop
    body_lines = lines[:g0] + lines[g1:]
    remaining = [n for n in fn.body if n is not guard]
    if not remaining:
        body_lines = lines[:g0] + [f"{indent}pass\n"] + lines[g1:]
    out["guard_drop"] = "".join(body_lines)
    # relational flip, single-line test only
    t = guard.test
    if t.lineno == t.end_lineno:
        line = lines[t.lineno - 1]
        seg = line[t.col_offset: t.end_col_offset]
        new_seg = None
        for a, b in FLIPS:
            if a in seg:
                new_seg = seg.replace(a, b, 1)
                break
        out["relational_flip"] = ("".join(lines[: t.lineno - 1]) + line[: t.col_offset] + new_seg + line[t.end_col_offset:]
                                  + "".join(lines[t.lineno:])) if new_seg else None
    else:
        out["relational_flip"] = None
    # guard action neuter
    act = guard.body[0]
    a0, a1 = act.lineno - 1, act.end_lineno
    aindent = re.match(r"\s*", lines[a0]).group(0)
    repl = f"{aindent}pass\n" if isinstance(act, ast.Raise) else f"{aindent}return None\n"
    out["action_neuter"] = "".join(lines[:a0]) + repl + "".join(lines[a1:])
    # body stub wipe (docstring kept)
    first = fn.body[0]
    keep_doc = isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant)
    start = (fn.body[1].lineno - 1) if keep_doc and len(fn.body) > 1 else fn.body[0].lineno - 1
    bindent = re.match(r"\s*", lines[fn.body[-1].lineno - 1]).group(0) if not keep_doc else re.match(r"\s*", lines[first.lineno - 1]).group(0)
    out["stub_wipe"] = "".join(lines[:start]) + f"{bindent}...\n" + "".join(lines[fn.end_lineno:])
    for k, v in list(out.items()):
        if v is not None:
            try:
                ast.parse(v)
            except SyntaxError:
                out[k] = None
    return out


def pick_positions(cands, n_lines: int):
    """guarded functions nearest the top, the middle and the bottom of the file."""
    if not cands:
        return []
    by_line = sorted(cands, key=lambda c: c[1].lineno)
    mid = min(by_line, key=lambda c: abs(c[1].lineno - n_lines / 2))
    picks = [("top", by_line[0]), ("middle", mid), ("bottom", by_line[-1])]
    seen, out = set(), []
    for pos, c in picks:
        if c[0] not in seen:
            seen.add(c[0])
            out.append((pos, c))
    return out


def audit_faults(monoliths) -> tuple[dict, list[dict]]:
    say("\n[2] monolith fault-injection sensitivity (fast path, dry-run commits)")
    k = StateKernel()
    rows, edits_for_bisim = [], []
    for label, src, loc, fns in monoliths:
        tree = ast.parse(src)
        picks = pick_positions(guarded_functions(tree), loc)
        if not picks:
            rows.append({"module": label, "loc": loc, "note": "no leading-guard function found"})
            say(f"    {label[:40]:<40} {loc:>6} LOC  no leading-guard function")
            continue
        root = make_project({"mod.py": src})
        sid = k.init_session(root)
        warm = B.edit_one_function(src, 0)
        if warm:
            k.commit(sid, "mod", source=warm[1], dry_run=True)  # warm the held tree / memo the benchmark also warms
        for pos, (name, fn, guard) in picks:
            for kind, mutated in synth_faults(src, fn, guard).items():
                if mutated is None or mutated == src:
                    rows.append({"module": label, "function": name, "position": pos, "fault": kind, "skipped": "shape"})
                    continue
                stitched0 = _okf.PERF["stitched"]
                t0 = time.perf_counter()
                v = k.commit(sid, "mod", source=mutated, dry_run=True)
                ms = (time.perf_counter() - t0) * 1000
                rows.append({"module": label, "loc": loc, "function": name, "position": pos, "fault": kind,
                             "blocked": not v.accepted, "gate": v.gate, "ms": round(ms, 1),
                             "stitched": _okf.PERF["stitched"] > stitched0, "error": str(v.error)[:160] if v.error else None})
                edits_for_bisim.append({"label": f"{label} / {name} / {kind}", "kind": f"fault:{kind}", "before": src, "after": mutated})
        done = [r for r in rows if r.get("module") == label and "blocked" in r]
        say(f"    {label[:40]:<40} {loc:>6} LOC  {len(picks)} guarded fns  "
            f"{sum(r['blocked'] for r in done)}/{len(done)} faults blocked  p50 {pct([r['ms'] for r in done], .5)} ms")
    tested = [r for r in rows if "blocked" in r]
    by_kind = {}
    for kind in ("guard_drop", "relational_flip", "action_neuter", "stub_wipe"):
        rs = [r for r in tested if r["fault"] == kind]
        by_kind[kind] = {"n": len(rs), "blocked": sum(r["blocked"] for r in rs),
                         "rate_pct": round(100 * sum(r["blocked"] for r in rs) / len(rs), 1) if rs else None,
                         "gates": {g: sum(1 for r in rs if r["gate"] == g) for g in ("A", "B", "C")},
                         "latency_when_blocking": lat([r["ms"] for r in rs if r["blocked"]])}
    by_pos = {pos: {"n": len([r for r in tested if r["position"] == pos]),
                    "blocked": sum(r["blocked"] for r in tested if r["position"] == pos)} for pos in ("top", "middle", "bottom")}
    accepted = [r for r in tested if not r["blocked"]]
    summary = {"faults_tested": len(tested), "blocked": sum(r["blocked"] for r in tested),
               "catch_rate_pct": round(100 * sum(r["blocked"] for r in tested) / len(tested), 1) if tested else None,
               "stitched_path_used_pct": round(100 * sum(r["stitched"] for r in tested) / len(tested), 1) if tested else None,
               "latency_when_blocking": lat([r["ms"] for r in tested if r["blocked"]]),
               "by_fault": by_kind, "by_position": by_pos, "accepted_faults": accepted, "rows": rows}
    say(f"    => {summary['blocked']}/{summary['faults_tested']} faults blocked ({summary['catch_rate_pct']}%), "
        f"stitched path on {summary['stitched_path_used_pct']}%, latency when blocking {summary['latency_when_blocking']}")
    for kind, d in by_kind.items():
        say(f"       {kind:<16} {d['blocked']}/{d['n']} ({d['rate_pct']}%) gates {d['gates']} {d['latency_when_blocking']}")
    for r in accepted:
        say(f"       ACCEPTED FAULT: {r['module'][:40]} {r['function']} {r['fault']} ({r['position']})")
    return summary, edits_for_bisim


# =============================================================== AUDIT 3: bisimulation


def facts_of(k: StateKernel, sid: str, rel: str) -> dict:
    n = next(n for n in k.graph(sid)["nodes"] if n["path"].replace("\\", "/") == rel)
    return {"invariants": sorted(n["invariants"]), "mined": sorted(n["invariants_auto_mined"]),
            "exports": list(n["exports"]), "preserved": sorted(n["preserved_symbols"]), "deps": list(n["deps"])}


def constant_edit(src: str) -> str | None:
    tree = ast.parse(src)
    lines = src.splitlines(keepends=True)
    for s in tree.body:
        if isinstance(s, ast.Assign) and isinstance(s.value, ast.Constant) and s.lineno == s.end_lineno:
            v = s.value
            if isinstance(v.value, bool) or v.value is None:
                continue
            if isinstance(v.value, int):
                new = str(v.value + 1)
            elif isinstance(v.value, str) and "\n" not in v.value:
                new = repr(v.value + "x")
            else:
                continue
            line = lines[s.lineno - 1]
            lines[s.lineno - 1] = line[: v.col_offset] + new + line[v.end_col_offset:]
            out = "".join(lines)
            try:
                ast.parse(out)
                return out
            except SyntaxError:
                return None
    return None


def swebench_pairs() -> list[dict]:
    raw = X.fetch(L.SWE_URL)
    if raw is None:
        return []
    out = []
    for r in [r["row"] for r in json.loads(raw)["rows"]]:
        files = L.split_patch(r["patch"])
        code = [p for p in files if p.endswith(".py")]
        if len(files) != 1 or len(code) != 1:
            continue
        rel = code[0]
        before_b = X.fetch(f"https://raw.githubusercontent.com/{r['repo']}/{r['base_commit']}/{rel}")
        if before_b is None:
            continue
        before = before_b.decode("utf-8")
        after = L.apply_hunks(before, files[rel]["hunks"])
        if after is None or not X.parses(before) or not X.parses(after):
            continue
        out.append({"label": f"SWE-bench/{r['instance_id']}", "kind": "swebench_gold", "before": before, "after": after, "rel": rel})
    return out


def bisim_one(edit: dict) -> dict:
    rel = edit.get("rel", "mod.py")
    nid_of = lambda k, sid: next(n["node_id"] for n in k.graph(sid)["nodes"] if n["path"].replace("\\", "/") == rel)  # noqa: E731
    # --- fast: warm session (held tree cached by init), stitched + incremental + memory cache, disk cache writable
    root_fast = make_project({rel: edit["before"]})
    k_fast = StateKernel()
    sid = k_fast.init_session(root_fast)
    nid = nid_of(k_fast, sid)
    held = facts_of(k_fast, sid, rel)
    p0 = dict(_okf.PERF)
    t0 = time.perf_counter()
    v_fast = k_fast.commit(sid, nid, source=edit["after"])
    fast_ms = (time.perf_counter() - t0) * 1000
    fast_perf = {k_: _okf.PERF[k_] - p0[k_] for k_ in ("stitched", "analysis_incremental", "analysis_full", "analysis_memory_hits", "analysis_disk_hits")}
    fast_facts = facts_of(k_fast, sid, rel) if v_fast.accepted else None
    # --- fast, cached: a second kernel on the same root (the disk cache now holds the edited text's facts)
    k_cached = StateKernel()
    root_cached = make_project({rel: edit["before"]})
    shutil.copytree(root_fast / ".stepcheck" / "cache", root_cached / ".stepcheck" / "cache", dirs_exist_ok=True)
    sid_c = k_cached.init_session(root_cached)
    v_cached = k_cached.commit(sid_c, nid_of(k_cached, sid_c), source=edit["after"])
    cached_facts = facts_of(k_cached, sid_c, rel) if v_cached.accepted else None
    # --- cold: fresh root (no disk cache), every memo cleared right before the commit (no stitched tree)
    root_cold = make_project({rel: edit["before"]})
    k_cold = StateKernel()
    sid_cold = k_cold.init_session(root_cold)
    nid_cold = nid_of(k_cold, sid_cold)
    clear_kernel_caches()
    v_cold = k_cold.commit(sid_cold, nid_cold, source=edit["after"])
    # --- Gate C with every probe in scope (no edit-scope skipping), against the held invariants
    all_probes_error = None
    try:
        _gates.gate_c(nid_cold, held["invariants"], edit["after"], {}, mined=held["mined"],
                      project_paths={nid_cold: rel}, previous_source=None, tree=None)
    except Exception as exc:  # noqa: BLE001
        all_probes_error = exc
    env_only = getattr(all_probes_error, "subtype", None) == "ENVIRONMENT"
    cold_accepted = v_cold.accepted and (all_probes_error is None or env_only)
    cold_gate = v_cold.gate if not v_cold.accepted else ("C" if (all_probes_error is not None and not env_only) else None)
    # --- from scratch: a brand-new analysis of the edited text (no `previous`, no caches)
    clear_kernel_caches()
    k_scratch = StateKernel(ephemeral=True)
    root_scratch = make_project({rel: edit["after"]})
    sid_s = k_scratch.init_session(root_scratch)
    scratch_facts = facts_of(k_scratch, sid_s, rel)

    row = {"label": edit["label"], "kind": edit["kind"], "fast_accepted": v_fast.accepted, "fast_gate": v_fast.gate,
           "fast_ms": round(fast_ms, 1), "fast_perf": fast_perf, "cached_accepted": v_cached.accepted, "cached_gate": v_cached.gate,
           "cold_accepted": cold_accepted, "cold_gate": cold_gate, "cold_commit_gate": v_cold.gate,
           "all_probes_env_only": env_only, "all_probes_error": str(all_probes_error)[:160] if all_probes_error else None}
    div = []
    if v_fast.accepted != cold_accepted:
        div.append("accepted")
    if v_fast.gate != cold_gate:
        div.append("gate")
    if v_fast.accepted != v_cached.accepted or v_fast.gate != v_cached.gate:
        div.append("cached-verdict")
    if v_fast.accepted:
        if set(fast_facts["invariants"]) != set(scratch_facts["invariants"]):
            div.append("invariants-vs-scratch")
        if fast_facts["exports"] != scratch_facts["exports"] or set(fast_facts["preserved"]) != set(scratch_facts["preserved"]):
            div.append("exports/preserved-vs-scratch")
        if cached_facts is not None and set(cached_facts["invariants"]) != set(scratch_facts["invariants"]):
            div.append("cached-invariants-vs-scratch")
        row["invariants_fast"], row["invariants_scratch"] = len(fast_facts["invariants"]), len(scratch_facts["invariants"])
        if "invariants-vs-scratch" in div:
            row["only_fast"] = sorted(set(fast_facts["invariants"]) - set(scratch_facts["invariants"]))[:10]
            row["only_scratch"] = sorted(set(scratch_facts["invariants"]) - set(fast_facts["invariants"]))[:10]
    row["divergence"] = div
    for r in (root_fast, root_cached, root_cold, root_scratch):
        shutil.rmtree(r, ignore_errors=True)
    return row


def audit_bisim(monoliths, fault_edits: list[dict]) -> dict:
    say("\n[3] bisimulation: fast (stitched + segment reuse + memory/disk cache) vs cold vs from-scratch")
    edits: list[dict] = []
    for label, src, loc, fns in monoliths:
        benign = [e for e in (B.edit_one_function(src, i) for i in range(5)) if e]
        seen = set()
        for name, new in benign:
            if new not in seen:
                seen.add(new)
                edits.append({"label": f"{label} / {name}", "kind": "method_edit" if "." in name else "function_edit", "before": src, "after": new})
        if len(benign) >= 2:  # two functions edited in one commit
            second = B.edit_one_function(benign[0][1], 3)
            if second and second[1] != benign[0][1]:
                edits.append({"label": f"{label} / {benign[0][0]} + {second[0]}", "kind": "multi_function_edit", "before": src, "after": second[1]})
        c = constant_edit(src)
        if c:
            edits.append({"label": f"{label} / module constant", "kind": "module_constant_edit", "before": src, "after": c})
    edits += fault_edits
    swe = swebench_pairs()
    edits += swe
    if QUICK:
        edits = edits[::3]
    say(f"    {len(edits)} edits: " + ", ".join(f"{k_}={sum(1 for e in edits if e['kind'] == k_)}" for k_ in sorted({e['kind'] for e in edits})))
    rows = []
    for i, e in enumerate(edits):
        try:
            rows.append(bisim_one(e))
        except Exception as exc:  # noqa: BLE001
            rows.append({"label": e["label"], "kind": e["kind"], "crash": f"{type(exc).__name__}: {str(exc)[:160]}", "divergence": ["crash"]})
        if (i + 1) % 25 == 0:
            say(f"    … {i + 1}/{len(edits)} edits, divergences so far {sum(1 for r in rows if r['divergence'])}")
    diverging = [r for r in rows if r["divergence"]]
    env_only = [r for r in rows if r.get("all_probes_env_only")]
    summary = {"edits": len(rows), "divergences": len(diverging), "divergence_rows": diverging,
               "environment_only_all_probe_failures": len(env_only),
               "by_kind": {k_: {"n": sum(1 for r in rows if r["kind"] == k_), "divergences": sum(1 for r in rows if r["kind"] == k_ and r["divergence"]),
                                "fast_accepted": sum(1 for r in rows if r["kind"] == k_ and r.get("fast_accepted"))}
                           for k_ in sorted({r["kind"] for r in rows})},
               "fast_path_use": {"stitched_pct": round(100 * sum(1 for r in rows if r.get("fast_perf", {}).get("stitched")) / len(rows), 1) if rows else None,
                                 "incremental_pct": round(100 * sum(1 for r in rows if r.get("fast_perf", {}).get("analysis_incremental")) / len(rows), 1) if rows else None},
               "fast_latency_ms": lat([r["fast_ms"] for r in rows if "fast_ms" in r]), "rows": rows}
    say(f"    => {len(rows)} edits, {len(diverging)} divergences; fast path stitched on {summary['fast_path_use']['stitched_pct']}% "
        f"and incremental on {summary['fast_path_use']['incremental_pct']}%; all-probe Gate C environment-only failures {len(env_only)}")
    for k_, d in summary["by_kind"].items():
        say(f"       {k_:<22} n={d['n']:<4} divergences={d['divergences']:<3} fast-accepted={d['fast_accepted']}")
    for r in diverging:
        say(f"       DIVERGENCE {r['label'][:60]}: {r['divergence']} fast={r.get('fast_accepted')}/{r.get('fast_gate')} "
            f"cold={r.get('cold_accepted')}/{r.get('cold_gate')} {r.get('only_fast', '')} {r.get('only_scratch', '')} {r.get('crash', '')}")
    return summary


# =============================================================== AUDIT 4: OOD repositories


def ood_roots() -> list[tuple[str, Path]]:
    cands = [("fastapi", HERE / "_cache" / "ood" / "fastapi"), ("tornado", HERE / "_cache" / "ood" / "tornado"),
             ("scrapy", HERE / "_cache" / "ood" / "scrapy"), ("martian/online (py+rs)", HERE / "_cache" / "martian" / "online")]
    return [(n, p) for n, p in cands if p.is_dir()]


def pick_guarded_file(root: Path, files: list[Path]):
    best = None
    for p in files:
        if p.suffix != ".py":
            continue
        try:
            src = p.read_text(encoding="utf-8")
            tree = ast.parse(src)
        except (UnicodeDecodeError, SyntaxError, ValueError):
            continue
        g = guarded_functions(tree)
        if g and (best is None or len(src) > len(best[1])):
            best = (p, src, g)
    return best


def audit_ood() -> dict:
    say("\n[4] zero-shot out-of-distribution trees (never referenced by benchmark_enterprise_scale.py)")
    out = {}
    for name, root in ood_roots():
        shutil.rmtree(root / ".stepcheck", ignore_errors=True)  # a cold start: no frames, no cache, no sessions
        files = _okf.tracked_files(root)
        loc = sum(p.read_bytes().count(b"\n") for p in files)
        k = StateKernel()
        t0 = time.perf_counter()
        sid = k.init_session(root)
        init_s = time.perf_counter() - t0
        n_nodes = len(k.node_paths(sid))
        lazy = any(not n["materialized"] for n in k.graph(sid)["nodes"])
        buf = io.StringIO()
        t0 = time.perf_counter()
        with redirect_stdout(buf):
            rc = cli.main(["ci", str(root)])
        ci_s = time.perf_counter() - t0
        ci_last = buf.getvalue().strip().splitlines()[-1][:200] if buf.getvalue().strip() else ""
        ci_fail_lines = [ln.strip()[:200] for ln in buf.getvalue().splitlines() if ln.strip().startswith("FAIL")][:5]
        row = {"root": str(root), "tracked_files": len(files), "loc": loc, "nodes": n_nodes, "lazy_index": lazy,
               "init_s": round(init_s, 2), "ci": {"exit": rc, "seconds": round(ci_s, 1), "last_line": ci_last, "fail_lines": ci_fail_lines}}
        picked = pick_guarded_file(root, files)
        if picked:
            p, src, guarded = picked
            rel = str(p.relative_to(root)).replace("\\", "/")
            located = k.locate(sid, p)
            nid = located["node_id"] if located else None
            anchor = next((ln for ln in src.splitlines() if ln.strip().startswith("def ")), None)
            if nid and anchor:
                event = {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(root), "stepcheck_session_id": sid,
                         "tool_input": {"file_path": str(p), "old_string": anchor, "new_string": anchor + "\n    _stepcheck_probe = 0"}}
                hook_ms = []
                decision = None
                for _ in range(5):
                    t0 = time.perf_counter()
                    d = hooks.decide(event, k)
                    hook_ms.append((time.perf_counter() - t0) * 1000)
                    decision = (d.get("hookSpecificOutput") or {}).get("permissionDecision", "allow (no opinion)")
                clean = B.edit_one_function(src, 1)
                v_clean = k.commit(sid, nid, source=clean[1], dry_run=True) if clean else None
                name_, fn, guard = max(guarded, key=lambda c: c[1].lineno)
                faults = synth_faults(src, fn, guard)
                fault_rows = {}
                for kind, mutated in faults.items():
                    if mutated is None:
                        continue
                    t0 = time.perf_counter()
                    v = k.commit(sid, nid, source=mutated, dry_run=True)
                    fault_rows[kind] = {"blocked": not v.accepted, "gate": v.gate, "ms": round((time.perf_counter() - t0) * 1000, 1)}
                row.update({"edited_file": rel, "file_loc": src.count("\n") + 1, "hook_edit_ms": lat(hook_ms), "hook_decision": decision,
                            "clean_edit_accepted": v_clean.accepted if v_clean else None,
                            "clean_edit_error": (str(v_clean.error)[:160] if v_clean and v_clean.error else None),
                            "fault_function": name_, "faults": fault_rows,
                            "fault_catch_rate_pct": round(100 * sum(f["blocked"] for f in fault_rows.values()) / len(fault_rows), 1) if fault_rows else None})
        out[name] = row
        say(f"    {name:<22} {len(files):>5} files {loc:>8} LOC  init {row['init_s']} s{' (lazy)' if lazy else ''}  ci exit {rc} in {row['ci']['seconds']} s"
            f"  hook p50 {row.get('hook_edit_ms', {}).get('p50')} ms  clean edit {row.get('clean_edit_accepted')}  faults caught {row.get('fault_catch_rate_pct')}% "
            f"{ {k_: v['gate'] for k_, v in row.get('faults', {}).items()} }")
        if ci_fail_lines:
            for ln in ci_fail_lines:
                say(f"         ci: {ln}")
        say(f"         ci: {ci_last}")
    return out


# =============================================================== main


def main() -> int:
    head, dirty = L.git_head()
    say(f"NOT-BENCHMARK-SHAPED AUDIT — kernel {head}{' (+uncommitted backend changes)' if dirty else ''}, base {BASE}")
    receipt = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "kernel_commit": head, "backend_dirty": dirty,
               "base": BASE, "quick": QUICK}
    receipt["1_static_purity"] = audit_static()
    monoliths = B.largest_cached_modules(15)
    receipt["monoliths"] = [{"module": lb, "loc": loc, "functions": fns} for lb, _s, loc, fns in monoliths]
    faults, fault_edits = audit_faults(monoliths)
    receipt["2_fault_injection"] = faults
    receipt["3_bisimulation"] = audit_bisim(monoliths, fault_edits)
    receipt["4_ood_repositories"] = audit_ood()
    receipt["seconds"] = round(time.time() - T0, 1)
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(receipt, indent=1, default=str), encoding="utf-8")
    s1, s2, s3 = receipt["1_static_purity"], receipt["2_fault_injection"], receipt["3_bisimulation"]
    say("\nVERDICT")
    say(f"  1 static purity:   {s1['literal_hits_outside_tests']} corpus literal(s) in the diff outside tests, "
        f"{len(s1['literal_hits_whole_backend_non_test'])} in the whole non-test backend (listed above)")
    say(f"  2 fault injection: {s2['blocked']}/{s2['faults_tested']} blocked ({s2['catch_rate_pct']}%), "
        f"latency when blocking {s2['latency_when_blocking']}, {len(s2['accepted_faults'])} accepted fault(s)")
    say(f"  3 bisimulation:    {s3['edits']} edits, {s3['divergences']} divergence(s)")
    say(f"  4 OOD:             " + "; ".join(f"{n}: ci exit {r['ci']['exit']}, faults {r.get('fault_catch_rate_pct')}%" for n, r in receipt["4_ood_repositories"].items()))
    say(f"receipt: {RECEIPT}  ({receipt['seconds']} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
