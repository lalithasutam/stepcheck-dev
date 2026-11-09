"""Three external benchmarks against the frozen Slice 35 kernel — measurement only.

1. SWE-ABS (OpenAgentLab/SWE-Bench_Verified_ABS, Hugging Face). Every row carries a strengthened
   `test_patch` (`test_patch != original_test_patch` for all 500), so the sample is stratified over
   repos: up to --per-repo single-file Python instances each. For each: the gold fix through
   StateKernel.commit (strict / declared), then SWE-ABS Stage-II-style plausible mutants synthesized
   on the functions the gold patch touched — guard drops, boundary flips, early-return neuters,
   exception widening / swallowing, body stubs, post-guard body corruption — judged strict in
   memory with the gate latency recorded. No pre-generated mutants are published by SWE-ABS
   (Stage II generates them per run), so these are synthesized here; they are NOT mapped against
   the lines the original test patch asserts (that needs test execution).
2. Martian Code Review Bench (withmartian/code-review-benchmark, offline/). For every golden PR in
   a StepCheck language (Python, Go, TypeScript/JS, Java; Discourse is Ruby and is skipped), the
   PR's modified files at base_sha form a project, the head_sha versions are staged strict, and
   every Gate A/B/C finding is recorded. Findings are compared with the golden comments lexically
   (a golden comment that names the finding's file stem or a changed symbol), by category.
3. BugsInPy (soarsmu/BugsInPy, projects/). >= 50 single-file bug fixes sampled round-robin over the
   17 projects; buggy -> fixed through StateKernel.commit strict / declared, every strict rejection
   classified: Type 1 the bug lived in a guard predicate, Type 2 a symbol / mass deletion, Type 3 a
   mined `call:` probe locked the buggy return value, else other.

Downloads are cached under external_cache/ (HTTP) and _cache/ (git clones) and are read as data only.
usage: evaluate_three_external_benchmarks.py [--offline] [--per-repo 8] [--bugs-per-project 4]
Receipt: receipts/three_external_benchmarks.json
"""
from __future__ import annotations

import ast
import datetime as dt
import difflib
import json
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CACHE = HERE / "_cache"
RECEIPT = HERE / "receipts" / "three_external_benchmarks.json"
sys.path.insert(0, str(HERE))
import verify_external_benchmarks as X  # noqa: E402
import audit_loopholes as A  # noqa: E402
import paper_honest_evaluation as P  # noqa: E402

from kernel import StateKernel, _okf  # noqa: E402

PER_REPO = int(sys.argv[sys.argv.index("--per-repo") + 1]) if "--per-repo" in sys.argv else 8
BUGS_PER_PROJECT = int(sys.argv[sys.argv.index("--bugs-per-project") + 1]) if "--bugs-per-project" in sys.argv else 4
SUPPORTED = {".py": "python", ".go": "go", ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".java": "java"}


def git_head() -> tuple[str, bool]:
    head = subprocess.run(["git", "rev-parse", "--short=7", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "backend"], cwd=REPO, capture_output=True, text=True).stdout.strip())
    return head, dirty


def ok(v) -> bool:
    return bool(getattr(v, "accepted", False))


def verdict(v) -> dict:
    return {"accepted": v.accepted, "gate": v.gate, "subtype": getattr(v.error, "subtype", None),
            "error": str(v.error)[:220] if v.error else None,
            "environment": (not v.accepted) and X.classify(v).startswith("environment")}


def touched_functions(before: str, after: str) -> list[tuple[str, ast.AST]]:
    """(dotted name, def node) of every function / method in `after` whose span overlaps a changed line."""
    sm = difflib.SequenceMatcher(None, before.splitlines(), after.splitlines())
    changed: set[int] = set()
    for tag, _i1, _i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            changed.update(range(j1 + 1, max(j2, j1 + 1) + 1))
    tree = ast.parse(after)
    out = []
    for name, fn in _okf._py_symbols(tree.body):
        if any(fn.lineno <= ln <= fn.end_lineno for ln in changed):
            out.append((name, fn))
    return out


# --------------------------------------------------------------- mutants (SWE-ABS Stage II style)


def _stub(src: str, fn) -> str | None:
    body = fn.body[X._body_start(fn):]
    if len(body) < 2:
        return None
    lines = src.splitlines(keepends=True)
    first = body[0].lineno
    indent = re.match(r"\s*", lines[first - 1]).group(0)
    new = "".join(lines[: first - 1]) + f"{indent}...\n" + "".join(lines[fn.end_lineno:])
    return new if X.parses(new) else None


def _post_guard(src: str, fn) -> tuple[str, str] | None:
    """One in-place operator / constant corruption after the guards of `fn` (any def)."""
    body = fn.body[X._body_start(fn):]
    lead = P._leading_guards(fn)
    off = P._guard_test_ids(fn)
    for stmt in body[lead:]:
        if P._is_guard(stmt):
            continue
        for node in ast.walk(stmt):
            if id(node) in off:
                continue
            if isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in (ast.Eq, ast.NotEq, ast.LtE, ast.GtE, ast.Lt, ast.Gt):
                new = A._flip_compare(src, node)
                if new and X.parses(new):
                    return f"comparison `{(ast.get_source_segment(src, node) or '')[:40]}` flipped", new
            if isinstance(node, ast.BinOp) and type(node.op) in (ast.Add, ast.Sub):
                seg = ast.get_source_segment(src, node) or ""
                lseg = ast.get_source_segment(src, node.left) or ""
                pos = seg.find(lseg) + len(lseg)
                old_op, new_op = ("+", "-") if isinstance(node.op, ast.Add) else ("-", "+")
                k = seg.find(old_op, pos)
                if k >= 0:
                    new = A._replace(src, node, seg[:k] + new_op + seg[k + 1:])
                    if X.parses(new):
                        return f"`{seg.strip()[:40]}`: `{old_op}` -> `{new_op}`", new
            if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool) and node.value > 1:
                new = A._replace(src, node, str(node.value + 1))
                if X.parses(new):
                    return f"constant {node.value} -> {node.value + 1}", new
    return None


def synthesize(after: str, touched: list[tuple[str, ast.AST]]) -> list[tuple[str, str, str, str]]:
    """(class, function, description, mutant source) for the touched functions only."""
    out = []
    names = {n for n, _fn in touched}
    for name, fn in touched:
        for kind, fault in X.guard_faults(after, fn.lineno):
            if fault is not None:
                out.append((kind, name, kind.replace("_", " "), fault[1]))
        stub = _stub(after, fn)
        if stub:
            out.append(("stub_body", name, "body -> `...`", stub))
        pg = _post_guard(after, fn)
        if pg:
            out.append(("post_guard_body", name, pg[0], pg[1]))
    for op, fn_name, desc, new in A.mutants(after, cap=50):
        if fn_name in {n.split(".")[-1] for n in names} and op not in ("a_decorator_strip",):
            out.append((op[2:], fn_name, desc, new))
    seen, uniq = set(), []
    for item in out:
        if item[3] not in seen and item[3] != after:
            seen.add(item[3])
            uniq.append(item)
    return uniq


# --------------------------------------------------------------- 1. SWE-ABS


def swe_abs(k: StateKernel) -> dict:
    rows = []
    for off in range(0, 500, 100):
        raw = X.fetch("https://datasets-server.huggingface.co/rows?dataset=OpenAgentLab%2FSWE-Bench_Verified_ABS"
                      f"&config=default&split=test&offset={off}&length=100")
        if raw is None:
            break
        rows += [r["row"] for r in json.loads(raw)["rows"]]
    strengthened = [r for r in rows if r["test_patch"] != r["original_test_patch"]]
    by_repo: dict[str, list] = {}
    for r in strengthened:
        files = A.split_patch(r["patch"])
        if len(files) == 1 and next(iter(files)).endswith(".py"):
            by_repo.setdefault(r["repo"], []).append(r)
    picked: list[dict] = []
    queues = [v[:PER_REPO] for _k, v in sorted(by_repo.items())]
    while any(queues):
        for q in queues:
            if q:
                picked.append(q.pop(0))
    tasks, skipped = [], []
    for r in picked:
        rel = next(iter(A.split_patch(r["patch"])))
        before_b = X.fetch(f"https://raw.githubusercontent.com/{r['repo']}/{r['base_commit']}/{rel}")
        if before_b is None:
            skipped.append((r["instance_id"], "base file not fetched"))
            continue
        before = before_b.decode("utf-8", "replace")
        after = A.apply_hunks(before, A.split_patch(r["patch"])[rel]["hunks"])
        if after is None or not X.parses(before) or not X.parses(after):
            skipped.append((r["instance_id"], "gold patch did not apply / parse"))
            continue
        tasks.append({"instance": r["instance_id"], "repo": r["repo"], "path": rel, "before": before, "after": after,
                      "difficulty": r.get("difficulty")})
    gold_rows, mut_rows = [], []
    for t in tasks:
        root = X.make_project({t["path"]: t["before"]})
        sid = k.init_session(root)
        nid = X.node_ids(k, sid)[t["path"]]["node_id"]
        t0 = time.perf_counter()
        strict = k.commit(sid, nid, source=t["after"], dry_run=True)
        ms = (time.perf_counter() - t0) * 1000
        declared = strict if strict.accepted else k.commit(sid, nid, source=t["after"], dry_run=True, allow_deletion=True)
        gold_rows.append({"instance": t["instance"], "repo": t["repo"], "module": t["path"], "ms": round(ms, 1),
                          "strict": verdict(strict), "declared": verdict(declared)})
        # mutants on the patched functions, judged against the gold `after` as the adopted state
        root2 = X.make_project({t["path"]: t["after"]})
        sid2 = k.init_session(root2)
        nid2 = X.node_ids(k, sid2)[t["path"]]["node_id"]
        base = k.commit(sid2, nid2, source=t["after"], dry_run=True)
        if not base.accepted:
            continue
        for cls, fn, desc, mutant in synthesize(t["after"], touched_functions(t["before"], t["after"])):
            t1 = time.perf_counter()
            v = k.commit(sid2, nid2, source=mutant, dry_run=True)
            mut_rows.append({"instance": t["instance"], "class": cls, "function": fn, "description": desc[:100],
                             "ms": round((time.perf_counter() - t1) * 1000, 1), **verdict(v),
                             "blocked": (not v.accepted) and not X.classify(v).startswith("environment")})
    n = len(gold_rows)
    env = [g for g in gold_rows if g["declared"]["environment"]]
    strict_ok = sum(g["strict"]["accepted"] for g in gold_rows)
    declared_ok = sum(g["declared"]["accepted"] for g in gold_rows)
    by_class: dict[str, dict] = {}
    for m in mut_rows:
        d = by_class.setdefault(m["class"], {"n": 0, "blocked": 0, "gates": {}, "ms": []})
        d["n"] += 1
        d["blocked"] += m["blocked"]
        d["ms"].append(m["ms"])
        if m["blocked"]:
            key = f"Gate {m['gate']} {m['subtype'] or ''}".strip()
            d["gates"][key] = d["gates"].get(key, 0) + 1
    for d in by_class.values():
        d["median_ms"] = round(statistics.median(d["ms"]), 1) if d["ms"] else None
        d["pct"] = round(100 * d["blocked"] / d["n"], 1) if d["n"] else None
        del d["ms"]
    return {
        "rows_fetched": len(rows), "strengthened_rows": len(strengthened),
        "single_file_python_strengthened": sum(len(v) for v in by_repo.values()),
        "sampled": len(picked), "evaluated": n, "skipped": skipped, "repos": sorted({t["repo"] for t in tasks}),
        "gold": {"strict_pass": strict_ok, "strict_pct": round(100 * strict_ok / n, 1) if n else None,
                 "declared_pass": declared_ok, "declared_pct": round(100 * declared_ok / n, 1) if n else None,
                 "environment": len(env), "median_commit_ms": round(statistics.median([g["ms"] for g in gold_rows]), 1) if gold_rows else None,
                 "strict_rejections": [{"instance": g["instance"], "gate": g["strict"]["gate"], "error": g["strict"]["error"]}
                                       for g in gold_rows if not g["strict"]["accepted"]]},
        "mutants": {"n": len(mut_rows), "blocked": sum(m["blocked"] for m in mut_rows),
                    "pct": round(100 * sum(m["blocked"] for m in mut_rows) / len(mut_rows), 1) if mut_rows else None,
                    "median_ms": round(statistics.median([m["ms"] for m in mut_rows]), 1) if mut_rows else None,
                    "p95_ms": round(sorted(m["ms"] for m in mut_rows)[int(0.95 * (len(mut_rows) - 1))], 1) if mut_rows else None,
                    "under_25ms_pct": round(100 * sum(m["ms"] < 25 for m in mut_rows) / len(mut_rows), 1) if mut_rows else None,
                    "by_class": dict(sorted(by_class.items())),
                    "missed_examples": [f"{m['instance']}::{m['function']} — {m['class']}: {m['description']}" for m in mut_rows if not m["blocked"]][:15]},
        "gold_rows": gold_rows, "mutant_rows": mut_rows,
    }


# --------------------------------------------------------------- 2. Martian


def _gh_json(url: str):
    raw = X.fetch(url)
    return json.loads(raw) if raw else None


def _parse_diff(diff: str) -> dict[str, dict]:
    files = A.split_patch(diff)
    out = {}
    for path, spec in files.items():
        out[path] = {"new_file": spec["new_file"], "hunks": spec["hunks"],
                     "deleted": bool(re.search(rf"^diff --git a/{re.escape(path)} b/{re.escape(path)}\n(?:.*\n){{0,3}}?deleted file", diff, re.M))}
    return out


def martian(k: StateKernel) -> dict:
    golden_dir = CACHE / "martian" / "offline" / "golden_comments"
    if not golden_dir.exists():
        return {"error": "offline/golden_comments not found under _cache/martian"}
    prs = []
    for f in sorted(golden_dir.glob("*.json")):
        for e in json.loads(f.read_text(encoding="utf-8")):
            prs.append({"dataset": f.stem, **e})
    rows = []
    for pr in prs:
        m = re.match(r"https://github.com/([^/]+)/([^/]+)/pull/(\d+)", pr["url"])
        if not m:
            continue
        owner, repo, num = m.groups()
        row = {"dataset": pr["dataset"], "url": pr["url"], "golden": pr["comments"], "note": pr.get("az_comment") or "",
               "files_evaluated": [], "findings": [], "skipped_files": []}
        if pr["dataset"] == "discourse":
            row["status"] = "skipped: Ruby is outside StepCheck's languages"
            rows.append(row)
            continue
        meta = _gh_json(f"https://api.github.com/repos/{owner}/{repo}/pulls/{num}")
        if not meta or "base" not in meta:
            row["status"] = f"skipped: PR metadata not fetched ({(meta or {}).get('message', 'no response')[:60]})"
            rows.append(row)
            continue
        base_sha, head_sha = meta["base"]["sha"], meta["head"]["sha"]
        head_repo = (meta.get("head") or {}).get("repo") or {}
        head_full = head_repo.get("full_name") or f"{owner}/{repo}"
        diff_b = X.fetch(f"https://github.com/{owner}/{repo}/pull/{num}.diff")
        if diff_b is None:
            row["status"] = "skipped: PR diff not fetched"
            rows.append(row)
            continue
        files = _parse_diff(diff_b.decode("utf-8", "replace"))
        project_before: dict[str, str] = {}
        project_after: dict[str, str] = {}
        for path, spec in files.items():
            ext = os.path.splitext(path)[1]
            if ext not in SUPPORTED or spec["new_file"] or spec["deleted"]:
                row["skipped_files"].append((path, "new / deleted / unsupported language"))
                continue
            if re.search(r"(^|/)(tests?|__tests__|spec)/|\.test\.|\.spec\.|_test\.(go|py)$|Test\.java$", path):
                row["skipped_files"].append((path, "test file"))
                continue
            before_b = X.fetch(f"https://raw.githubusercontent.com/{owner}/{repo}/{base_sha}/{path}")
            after_b = X.fetch(f"https://raw.githubusercontent.com/{head_full}/{head_sha}/{path}")
            if before_b is None or after_b is None:
                row["skipped_files"].append((path, "base or head version not fetched"))
                continue
            before_t, after_t = before_b.decode("utf-8", "replace"), after_b.decode("utf-8", "replace")
            if ext == ".py" and not (X.parses(before_t) and X.parses(after_t)):
                row["skipped_files"].append((path, "does not parse under this Python (3.12+ syntax such as PEP 695 generics)"))
                continue
            project_before[path] = before_t
            project_after[path] = after_t
        if not project_before:
            row["status"] = "skipped: no evaluable files"
            rows.append(row)
            continue
        root = X.make_project(project_before)
        try:
            sid = k.init_session(root)
        except Exception as exc:  # noqa: BLE001 — a file the indexer cannot parse
            row["status"] = f"skipped: kernel could not index the base files ({type(exc).__name__}: {str(exc)[:80]})"
            rows.append(row)
            continue
        nodes = X.node_ids(k, sid)
        for path, after in project_after.items():
            node = nodes.get(path)
            if node is None:
                row["skipped_files"].append((path, "not tracked by the kernel"))
                continue
            base = k.commit(sid, node["node_id"], source=project_before[path], dry_run=True)
            if not base.accepted:
                row["skipped_files"].append((path, f"baseline rejected: {X.classify(base)}"))
                continue
            v = k.commit(sid, node["node_id"], source=after, dry_run=True)
            lang = SUPPORTED[os.path.splitext(path)[1]]
            changed = []
            if lang == "python":
                try:
                    changed = [n for n, _ in touched_functions(project_before[path], after)]
                except SyntaxError:
                    changed = []
            row["files_evaluated"].append({"path": path, "language": lang, "changed_symbols": changed[:12], "accepted": v.accepted})
            if not v.accepted:
                row["findings"].append({"path": path, "language": lang, "gate": v.gate, "code": getattr(v.error, "subtype", None),
                                        "error": str(v.error)[:220], "changed_symbols": changed[:12],
                                        "environment": X.classify(v).startswith("environment")})
        row["status"] = "evaluated"
        rows.append(row)
    # lexical overlap: a golden comment that names the finding's file stem or a changed symbol
    cats = ("bug", "api", "data", "security", "concurrency", "perf", "test_gap", "style", "doc_defect", "speculative")
    golden_by_cat = {c: 0 for c in cats}
    matched_by_cat = {c: 0 for c in cats}
    for row in rows:
        if row.get("status") != "evaluated":
            continue
        for g in row["golden"]:
            c = g["category"] if g["category"] in golden_by_cat else "speculative"
            golden_by_cat[c] += 1
            text = g["comment"].lower()
            hit = False
            for f in row["findings"]:
                stem = os.path.splitext(os.path.basename(f["path"]))[0].lower()
                names = [s.split(".")[-1].lower() for s in f["changed_symbols"]]
                if (stem in text and len(stem) > 3) or any(n in text and len(n) > 3 for n in names):
                    hit = True
            matched_by_cat[c] += hit
            g["lexically_matched_by_a_finding"] = hit
    evaluated = [r for r in rows if r.get("status") == "evaluated"]
    langs: dict[str, int] = {}
    for r in evaluated:
        for f in r["files_evaluated"]:
            langs[f["language"]] = langs.get(f["language"], 0) + 1
    return {
        "prs_total": len(rows), "prs_evaluated": len(evaluated), "prs_skipped": {r["url"]: r["status"] for r in rows if r.get("status") != "evaluated"},
        "files_evaluated": sum(len(r["files_evaluated"]) for r in evaluated), "files_by_language": langs,
        "prs_flagged": sum(1 for r in evaluated if r["findings"]), "prs_passed_cleanly": sum(1 for r in evaluated if not r["findings"]),
        "findings": sum(len(r["findings"]) for r in evaluated),
        "findings_by_gate": {g: sum(1 for r in evaluated for f in r["findings"] if f["gate"] == g) for g in ("A", "B", "C")},
        "findings_environment": sum(1 for r in evaluated for f in r["findings"] if f["environment"]),
        "golden_comments_in_evaluated_prs": sum(golden_by_cat.values()),
        "golden_by_category": golden_by_cat, "lexical_overlap_by_category": matched_by_cat,
        "match_rule": "a golden comment lexically names the finding's file stem or a symbol the edit changed (no LLM judge)",
        "rows": rows,
    }


# --------------------------------------------------------------- 3. BugsInPy


def _kv(text: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in re.finditer(r'^(\w+)="([^"]*)"', text, re.M)}


def classify_rejection(v: dict) -> str:
    err = (v.get("error") or "")
    if v.get("environment") or "failed to load for callable invariants" in err:
        return "environment (module failed to load here: a third-party import is missing)"
    if v["gate"] == "B" or (v["gate"] == "A" and "export" in err):
        return "Type 2: symbol / signature / mass deletion (Gate B, or Gate A export contract)"
    if v["gate"] == "C" and "the call now returns" in err:
        return "Type 3: mined call: probe locked the buggy return value"
    if v["gate"] == "C" and ("'call:" in err or "\"call:" in err):
        return "Type 1: bug lived in a guard predicate (runtime call: probe)"
    if v["gate"] == "C" and "guard:" in err:
        return "Type 1: bug lived in a guard predicate (structural guard:)"
    if v["gate"] == "C":
        return "Type 1/other: Gate C frame invariant"
    if v.get("environment"):
        return "environment (module failed to load here)"
    return f"other: Gate {v['gate']}"


def bugsinpy(k: StateKernel) -> dict:
    projects_dir = CACHE / "bugsinpy" / "projects"
    if not projects_dir.exists():
        return {"error": "projects/ not found under _cache/bugsinpy"}
    per_project: dict[str, list[dict]] = {}
    for proj in sorted(os.listdir(projects_dir)):
        pdir = projects_dir / proj
        info = _kv((pdir / "project.info").read_text(encoding="utf-8", errors="replace")) if (pdir / "project.info").exists() else {}
        gh = info.get("github_url", "").rstrip("/")
        m = re.match(r"https://github.com/([^/]+/[^/]+)", gh)
        if not m or not (pdir / "bugs").is_dir():
            continue
        slug = m.group(1)
        for bid in sorted((pdir / "bugs").iterdir(), key=lambda p: int(p.name) if p.name.isdigit() else 0):
            patch_f, info_f = bid / "bug_patch.txt", bid / "bug.info"
            if not patch_f.exists() or not info_f.exists():
                continue
            patch = patch_f.read_text(encoding="utf-8", errors="replace")
            files = re.findall(r"^diff --git a/(\S+) b/", patch, re.M)
            code = [f for f in files if f.endswith(".py") and "/tests/" not in f and not os.path.basename(f).startswith("test")]
            if len(files) != 1 or len(code) != 1:
                continue
            binfo = _kv(info_f.read_text(encoding="utf-8", errors="replace"))
            per_project.setdefault(proj, []).append({"project": proj, "slug": slug, "bug": bid.name, "path": code[0],
                                                     "buggy": binfo.get("buggy_commit_id"), "fixed": binfo.get("fixed_commit_id")})
    picked: list[dict] = []
    queues = [v[:BUGS_PER_PROJECT] for _k, v in sorted(per_project.items())]
    while any(queues):
        for q in queues:
            if q:
                picked.append(q.pop(0))
    rows, skipped = [], []
    for b in picked:
        bb = X.fetch(f"https://raw.githubusercontent.com/{b['slug']}/{b['buggy']}/{b['path']}")
        fb = X.fetch(f"https://raw.githubusercontent.com/{b['slug']}/{b['fixed']}/{b['path']}")
        if bb is None or fb is None:
            skipped.append((f"{b['project']}#{b['bug']}", "buggy or fixed file not fetched"))
            continue
        buggy, fixed = bb.decode("utf-8", "replace"), fb.decode("utf-8", "replace")
        if not (X.parses(buggy) and X.parses(fixed)) or buggy == fixed:
            skipped.append((f"{b['project']}#{b['bug']}", "does not parse or identical"))
            continue
        root = X.make_project({b["path"]: buggy})
        sid = k.init_session(root)
        nid = X.node_ids(k, sid)[b["path"]]["node_id"]
        strict = k.commit(sid, nid, source=fixed, dry_run=True)
        declared = strict if strict.accepted else k.commit(sid, nid, source=fixed, dry_run=True, allow_deletion=True)
        row = {"project": b["project"], "bug": b["bug"], "module": b["path"], "strict": verdict(strict), "declared": verdict(declared)}
        if not strict.accepted:
            row["root_cause"] = classify_rejection(row["strict"])
        rows.append(row)
    n = len(rows)
    causes: dict[str, int] = {}
    for r in rows:
        if "root_cause" in r:
            causes[r["root_cause"]] = causes.get(r["root_cause"], 0) + 1
    return {
        "projects": sorted(per_project), "single_file_bugs_available": sum(len(v) for v in per_project.values()),
        "sampled": len(picked), "evaluated": n, "skipped": skipped,
        "strict_pass": sum(r["strict"]["accepted"] for r in rows), "strict_pct": round(100 * sum(r["strict"]["accepted"] for r in rows) / n, 1) if n else None,
        "declared_pass": sum(r["declared"]["accepted"] for r in rows), "declared_pct": round(100 * sum(r["declared"]["accepted"] for r in rows) / n, 1) if n else None,
        "strict_rejection_root_causes": dict(sorted(causes.items())),
        "strict_rejections": [{"bug": f"{r['project']}#{r['bug']}", "module": r["module"], "cause": r["root_cause"], "gate": r["strict"]["gate"],
                               "error": r["strict"]["error"]} for r in rows if "root_cause" in r],
        "rows": rows,
    }


# --------------------------------------------------------------- main


def main() -> int:
    t0 = time.perf_counter()
    head, dirty = git_head()
    k = StateKernel(ephemeral=True)
    results: dict = {}
    for key, fn in (("swe_abs", swe_abs), ("martian", martian), ("bugsinpy", bugsinpy)):
        t = time.perf_counter()
        results[key] = fn(k)
        results[key]["_seconds"] = round(time.perf_counter() - t, 1)
        print(f"  [{key}] done in {results[key]['_seconds']}s", flush=True)

    def load(name):
        p = HERE / "receipts" / name
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    audit, hold = load("loophole_audit.json"), load("swe_holdout.json")
    swe_b = (audit or {}).get("results", {}).get("1_swebench", {}).get("b_gold_patches", {})
    hold_b = (hold or {}).get("b_gold_patches", {})

    s, m, b = results["swe_abs"], results["martian"], results["bugsinpy"]
    table = [
        ["SWE-ABS gold fixes (strengthened split, single-file)", str(s.get("evaluated")),
         f"strict {s['gold']['strict_pass']}/{s['evaluated']} ({s['gold']['strict_pct']}%), declared {s['gold']['declared_pass']}/{s['evaluated']} ({s['gold']['declared_pct']}%)",
         f"median gated commit {s['gold']['median_commit_ms']} ms; repos {len(s.get('repos', []))}"] if "gold" in s else ["SWE-ABS", "—", s.get("error", ""), ""],
        ["SWE-ABS Stage-II-style mutants on patched functions", str(s["mutants"]["n"]),
         f"blocked {s['mutants']['blocked']}/{s['mutants']['n']} ({s['mutants']['pct']}%)",
         f"median {s['mutants']['median_ms']} ms, p95 {s['mutants']['p95_ms']} ms, under 25 ms {s['mutants']['under_25ms_pct']}%"] if "mutants" in s else ["", "", "", ""],
        ["Martian Code Review Bench PRs (Python/Go/TS/Java)", f"{m.get('prs_evaluated')}/{m.get('prs_total')}",
         f"flagged {m.get('prs_flagged')}, passed cleanly {m.get('prs_passed_cleanly')}; findings {m.get('findings')} (gates {m.get('findings_by_gate')})",
         f"files {m.get('files_evaluated')} {m.get('files_by_language')}; golden comments in evaluated PRs {m.get('golden_comments_in_evaluated_prs')}, "
         f"lexical overlap {sum((m.get('lexical_overlap_by_category') or {}).values())}"] if "error" not in m else ["Martian", "—", m["error"], ""],
        ["BugsInPy bug fixes (buggy -> fixed)", str(b.get("evaluated")),
         f"strict {b.get('strict_pass')}/{b.get('evaluated')} ({b.get('strict_pct')}%), declared {b.get('declared_pass')}/{b.get('evaluated')} ({b.get('declared_pct')}%)",
         f"strict rejection root causes {b.get('strict_rejection_root_causes')}"] if "error" not in b else ["BugsInPy", "—", b["error"], ""],
        ["SWE-bench Verified rows 0-24 (loophole_audit.json)", str(swe_b.get("patches")),
         f"strict {swe_b.get('strict_pass_rate_pct')}%, declared {swe_b.get('declared_pass_rate_pct')}%", ""],
        ["SWE-bench Verified rows 25-44 holdout (swe_holdout.json)", str(hold_b.get("patches")),
         f"strict {hold_b.get('strict_pass_rate_pct')}%, declared {hold_b.get('declared_pass_rate_pct')}%", ""],
    ]
    receipt = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "generator": ".stepcheck/discovery/evaluate_three_external_benchmarks.py",
               "kernel_commit": head, "backend_dirty": dirty, "params": {"per_repo": PER_REPO, "bugs_per_project": BUGS_PER_PROJECT},
               "table": table, "results": results, "sources": X.SOURCES, "runtime_s": round(time.perf_counter() - t0, 1)}
    RECEIPT.write_text(json.dumps(receipt, indent=1, default=str), encoding="utf-8")

    print(f"\nTHREE EXTERNAL BENCHMARKS — StepCheck {head}{' (+dirty backend)' if dirty else ''}")
    print("| Benchmark | N | Result | Detail |")
    print("| --- | ---: | --- | --- |")
    for r in table:
        print("| " + " | ".join(str(x).replace("|", "\\|") for x in r) + " |")
    if "mutants" in s:
        print("\nSWE-ABS mutants by class:")
        for cls, d in s["mutants"]["by_class"].items():
            print(f"  {cls:<28} {d['blocked']}/{d['n']} ({d['pct']}%)  median {d['median_ms']} ms  {d['gates']}")
        for ex in s["mutants"]["missed_examples"][:8]:
            print("  missed:", ex)
        for g in s["gold"]["strict_rejections"]:
            print("  gold strict rejection:", g["instance"], g["gate"], (g["error"] or "")[:140])
    if "error" not in m:
        print("\nMartian golden categories (golden / lexically touched by a StepCheck finding):")
        for c, n in m["golden_by_category"].items():
            print(f"  {c:<12} {n:>3} / {m['lexical_overlap_by_category'][c]}")
        for url, why in list(m["prs_skipped"].items())[:12]:
            print("  skipped:", url, "—", why)
        for r in [r for r in m["rows"] if r.get("status") == "evaluated" and r["findings"]][:10]:
            for f in r["findings"][:3]:
                print(f"  finding: {r['url'].rsplit('/', 3)[-3]}#{r['url'].rsplit('/', 1)[-1]} {f['path']} Gate {f['gate']} {f['code'] or ''} — {f['error'][:110]}")
    if "error" not in b:
        print("\nBugsInPy strict rejections:")
        for r in b["strict_rejections"][:20]:
            print(f"  {r['bug']:<18} {r['cause'][:52]:<52} {(r['error'] or '')[:110]}")
    print(f"receipt: {RECEIPT}  ({receipt['runtime_s']} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
