"""Brutally honest failure boundaries of StepCheck vs Skylos 4.50.1 — four new adversarial
categories on psf/requests + pallets/flask (and the Aider polyglot references), then one summary
table that also folds in the existing receipts (external_benchmark_certification.json,
loophole_audit.json, skylos_vs_stepcheck.json) with precision, recall, false-positive rate and
the blind spots named.

Nothing under backend/ is modified: every verdict is a dry-run StateKernel.commit in an
ephemeral kernel against a temp copy of the package.

A. Post-guard algorithmic corruption in class METHODS: imports, signatures, decorators and every
   guard stay; one arithmetic / constant / comparison in a non-guard statement after the guards
   changes (`+` -> `-`, `200` -> `500`, `==` -> `!=`). Catch = Gate B/C rejection; the receipt
   says whether a runtime `call:` probe or a structural `guard:` clause spoke.
B. Dropped impure side-effect statement: one `obj.method(...)` call statement or one
   `self.attr = ...` assignment after the guards is deleted; >= 2 statements and all guards stay.
C. Semantically equivalent guard refactors (false-positive probe): a mined `if …: raise` guard is
   rewritten to a logically identical form (`x is None` -> `None is x`, `x <= 0` -> `0 >= x`,
   `not a or not b` -> `not (a and b)`, `len(x) == 0` -> `not x`); a strict rejection is a
   FALSE POSITIVE.
D. Polyglot guard mutations (TS/JS, Go, Rust, Java): relational flips inside a guard condition and
   whole-guard deletions, beyond the body stubs the audit already covers.

Skylos: `skylos <project> -a --ai-defects --json --no-upload --no-grep-verify`; a catch is any new
finding in the mutated file versus the before-scan (generous to Skylos; the same rule as
skylos_vs_stepcheck.json). StepCheck: strict `commit(source=after, dry_run=True)` rejected at Gate
B or C (Gate A or an accepted commit is a miss).

usage: paper_honest_evaluation.py [--offline] [--workers N] [--no-skylos]
Receipt: receipts/paper_honest_eval.json
"""
from __future__ import annotations

import ast
import datetime as dt
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RECEIPTS = HERE / "receipts"
RECEIPT = RECEIPTS / "paper_honest_eval.json"
sys.path.insert(0, str(HERE))
import verify_external_benchmarks as X  # noqa: E402
import audit_loopholes as A  # noqa: E402
import benchmark_vs_skylos as B  # noqa: E402

from kernel import StateKernel  # noqa: E402

CAP = {"A": 25, "B": 25, "C": 25, "D": 20}
WORKERS = int(sys.argv[sys.argv.index("--workers") + 1]) if "--workers" in sys.argv else 3
NO_SKYLOS = "--no-skylos" in sys.argv


def git_head() -> tuple[str, bool]:
    head = subprocess.run(["git", "rev-parse", "--short=7", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "backend"], cwd=REPO, capture_output=True, text=True).stdout.strip())
    return head, dirty


# ------------------------------------------------------------------ Python helpers


def _is_guard(stmt: ast.stmt) -> bool:
    if isinstance(stmt, ast.Assert):
        return True
    return isinstance(stmt, ast.If) and bool(stmt.body) and isinstance(stmt.body[-1], (ast.Raise, ast.Return))


def _leading_guards(fn) -> int:
    body = fn.body[X._body_start(fn):]
    i = 0
    while i < len(body) and _is_guard(body[i]):
        i += 1
    return i


def _guard_test_ids(fn) -> set[int]:
    """Every AST node inside the test of a guard (`if …: raise`) or an assert: off limits."""
    ids: set[int] = set()
    for n in ast.walk(fn):
        test = None
        if isinstance(n, ast.If) and n.body and isinstance(n.body[-1], ast.Raise):
            test = n.test
        elif isinstance(n, ast.Assert):
            test = n.test
        if test is not None:
            ids |= {id(x) for x in ast.walk(test)}
    return ids


def _functions(tree, methods_only: bool):
    out = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            out += [(f"{node.name}.{m.name}", m) for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
        elif not methods_only and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((node.name, node))
    return out


_ARITH = {ast.Add: ("+", "-"), ast.Sub: ("-", "+"), ast.Mult: ("*", "+"), ast.Mod: ("%", "+"), ast.FloorDiv: ("//", "*")}


def category_a(src: str, cap: int) -> list[tuple[str, str, str]]:
    """(method, description, mutated source): post-guard corruption inside class methods."""
    tree = ast.parse(src)
    out = []
    for name, fn in _functions(tree, methods_only=True):
        if len(out) >= cap:
            break
        body = fn.body[X._body_start(fn):]
        lead = _leading_guards(fn)
        off = _guard_test_ids(fn)
        if len(body) < 3 or not off:  # the method must carry at least one guard (leading or mid-body) that stays intact
            continue
        done = False
        for stmt in body[lead:]:
            if done:
                break
            if _is_guard(stmt):
                continue
            for node in ast.walk(stmt):
                if id(node) in off:
                    continue
                new = desc = None
                if isinstance(node, ast.BinOp) and type(node.op) in _ARITH:
                    seg = ast.get_source_segment(src, node) or ""
                    old_op, new_op = _ARITH[type(node.op)]
                    m = re.search(rf"(?<![=!<>+\-*/%]){re.escape(old_op)}(?![=+\-*/])", seg)
                    if m and ast.get_source_segment(src, node.left) is not None:
                        lseg = ast.get_source_segment(src, node.left) or ""
                        pos = seg.find(lseg) + len(lseg)
                        m2 = re.compile(re.escape(old_op)).search(seg, pos)
                        if m2:
                            new = A._replace(src, node, seg[: m2.start()] + new_op + seg[m2.end():])
                            desc = f"`{seg.strip()[:50]}`: `{old_op}` -> `{new_op}`"
                elif isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool) and node.value > 1:
                    new = A._replace(src, node, str(node.value + 300))
                    desc = f"constant {node.value} -> {node.value + 300}"
                elif isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in (ast.Eq, ast.NotEq, ast.LtE, ast.GtE):
                    new = A._flip_compare(src, node)
                    desc = f"comparison `{(ast.get_source_segment(src, node) or '')[:50]}` flipped"
                if new is not None and new != src and X.parses(new):
                    out.append((name, desc, new))
                    done = True
                    break
    return out


def _delete_stmt(src: str, stmt: ast.stmt, siblings: int) -> str | None:
    lines = src.splitlines(keepends=True)
    if siblings > 1:
        new = "".join(lines[: stmt.lineno - 1]) + "".join(lines[stmt.end_lineno:])
    else:
        indent = re.match(r"\s*", lines[stmt.lineno - 1]).group(0)
        new = "".join(lines[: stmt.lineno - 1]) + f"{indent}pass\n" + "".join(lines[stmt.end_lineno:])
    return new if X.parses(new) else None


def category_b(src: str, cap: int) -> list[tuple[str, str, str]]:
    """(function, description, mutated source): one side-effect statement dropped after the guards."""
    tree = ast.parse(src)
    out = []
    for name, fn in _functions(tree, methods_only=False):
        if len(out) >= cap:
            break
        body = fn.body[X._body_start(fn):]
        lead = _leading_guards(fn)
        if len(body) - 1 < 2:
            continue
        for stmt in body[lead:]:
            if _is_guard(stmt) or stmt is body[-1] and isinstance(stmt, ast.Return):
                continue
            desc = None
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                callee = ast.unparse(stmt.value.func)
                if callee in ("print",) or callee.startswith(("super(", "logging.")):
                    continue
                desc = f"dropped call `{(ast.get_source_segment(src, stmt) or callee)[:60]}`"
            elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Attribute):
                desc = f"dropped state mutation `{(ast.get_source_segment(src, stmt) or '')[:60]}`"
            if desc:
                new = _delete_stmt(src, stmt, len(body))
                if new is not None and new != src:
                    out.append((name, desc, new))
                    break
    return out


_MIRROR = {ast.LtE: ">=", ast.GtE: "<=", ast.Lt: ">", ast.Gt: "<", ast.Eq: "==", ast.NotEq: "!="}


def _equivalent(src: str, test: ast.expr) -> tuple[str, str] | None:
    """(kind, new test text) for one logically identical rewrite, or None."""
    seg = ast.get_source_segment(src, test)
    if seg is None:
        return None
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        left, right, op = test.left, test.comparators[0], test.ops[0]
        l_s, r_s = ast.get_source_segment(src, left), ast.get_source_segment(src, right)
        if l_s is None or r_s is None:
            return None
        if isinstance(op, ast.Is) and isinstance(right, ast.Constant) and right.value is None:
            return "is None -> None is", f"None is {l_s}"
        if isinstance(op, ast.IsNot) and isinstance(right, ast.Constant) and right.value is None:
            return "is not None -> None is not", f"None is not {l_s}"
        if isinstance(op, ast.Eq) and isinstance(left, ast.Call) and ast.unparse(left.func) == "len" and isinstance(right, ast.Constant) and right.value == 0:
            return "len(x) == 0 -> not x", f"not {ast.get_source_segment(src, left.args[0])}"
        if type(op) in _MIRROR and isinstance(right, ast.Constant) and not isinstance(right.value, bool):
            return f"mirrored comparison ({_MIRROR[type(op)]})", f"{r_s} {_MIRROR[type(op)]} {l_s}"
    if isinstance(test, ast.BoolOp) and len(test.values) == 2 and all(
            isinstance(v, ast.UnaryOp) and isinstance(v.op, ast.Not) for v in test.values):
        a, b = (ast.get_source_segment(src, v.operand) for v in test.values)
        if a and b:
            if isinstance(test.op, ast.Or):
                return "not a or not b -> not (a and b)", f"not ({a} and {b})"
            return "not a and not b -> not (a or b)", f"not ({a} or {b})"
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) and isinstance(test.operand, ast.Call) \
            and ast.unparse(test.operand.func) == "isinstance" and len(test.operand.args) == 2 \
            and isinstance(test.operand.args[1], (ast.Name, ast.Attribute)):
        x, t = (ast.get_source_segment(src, a) for a in test.operand.args)
        if x and t:
            return "isinstance(x, T) -> isinstance(x, (T,))", f"not isinstance({x}, ({t},))"
    if isinstance(test, ast.Call) and ast.unparse(test.func) == "isinstance" and len(test.args) == 2 \
            and isinstance(test.args[1], (ast.Name, ast.Attribute)):
        x, t = (ast.get_source_segment(src, a) for a in test.args)
        if x and t:
            return "isinstance(x, T) -> isinstance(x, (T,))", f"isinstance({x}, ({t},))"
    return None


def category_c(src: str, mined: list[str], cap: int) -> list[tuple[str, str, str]]:
    """(function, description, rewritten source): a mined guard in an equivalent form."""
    tree = ast.parse(src)
    guarded = {inv.split(":", 2)[1] for inv in mined if inv.startswith("guard:")}
    out = []
    for name, fn in _functions(tree, methods_only=False):
        if len(out) >= cap:
            break
        if name not in guarded and name.split(".")[-1] not in guarded:
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.If) and node.body and isinstance(node.body[-1], ast.Raise):
                eq = _equivalent(src, node.test)
                if eq is None:
                    continue
                kind, text = eq
                new = A._replace(src, node.test, text)
                if X.parses(new) and new != src:
                    out.append((name, f"{kind}: `{ast.get_source_segment(src, node.test)}` -> `{text}`", new))
                    break
    return out


# ------------------------------------------------------------------ polyglot (D)

_REL = [("<=", "<"), (">=", ">"), ("===", "!=="), ("!==", "==="), ("==", "!="), ("!=", "=="), ("<", "<="), (">", ">=")]
_GUARD_RX = {
    "javascript": re.compile(r"if\s*\((?P<cond>[^{;]*?)\)\s*(?P<open>\{)?\s*throw\b"),
    "java": re.compile(r"if\s*\((?P<cond>[^{;]*?)\)\s*(?P<open>\{)?\s*throw\b"),
    "go": re.compile(r"if\s+(?P<cond>[^{]+?)\s*(?P<open>\{)\s*(?:return\b|panic\()"),
    "rust": re.compile(r"if\s+(?P<cond>[^{]+?)\s*(?P<open>\{)\s*(?:return\s+Err|panic!|return\b)"),
}


def _flip_cond(cond: str) -> tuple[str, str] | None:
    for old, new in _REL:
        pattern = {"<": r"(?<![<>=!])<(?![<=])", ">": r"(?<![<>=!-])>(?![>=])", "==": r"(?<![=!<>])==(?!=)",
                   "!=": r"!=(?!=)", "<=": r"<=", ">=": r">=", "===": r"===", "!==": r"!=="}[old]
        m = re.search(pattern, cond)
        if m:
            return cond[: m.start()] + new + cond[m.end():], f"`{old}` -> `{new}`"
    return None


def _enclosing_function(mod, src: str, pos: int) -> str | None:
    best = None
    for d in A.functions(mod, src):
        close = A.match_brace(src, d.body_open, "x")
        if close is not None and d.body_open <= pos <= close:
            if best is None or d.body_open > best[0]:
                best = (d.body_open, d.dotted)
    return best[1] if best else None


def category_d(lang: str, rel: str, src: str, mod, cap: int) -> list[tuple[str, str, str]]:
    """(function, description, mutated source): guard flips and deletions in one polyglot file."""
    out: list[tuple[str, str, str]] = []
    flips, deletions = [], []
    for m in _GUARD_RX[lang].finditer(src):
        fn = _enclosing_function(mod, src, m.start()) or "?"
        cond = m.group("cond")
        flipped = _flip_cond(cond)
        if flipped:
            new_cond, what = flipped
            new = src[: m.start("cond")] + new_cond + src[m.end("cond"):]
            flips.append((fn, f"guard `{cond.strip()[:50]}`: {what}", new))
        # deletion: a braced block `if (...) { ... }` or a one-line `if (...) throw ...;`
        if m.group("open"):
            close = A.match_brace(src, m.start("open"), lang)
            if close is not None:
                tail = src[close + 1:]
                if re.match(r"\s*else\b", tail):  # an if/else is not a pure guard
                    continue
                deletions.append((fn, f"guard `{cond.strip()[:50]}` deleted", src[: m.start()] + src[close + 1:]))
        else:
            end = src.find(";", m.end())
            if end > 0:
                deletions.append((fn, f"guard `{cond.strip()[:50]}` deleted", src[: m.start()] + src[end + 1:]))
    for pool in (flips, deletions):
        for item in pool:
            if len(out) < cap and item[2] != src:
                out.append(item)
    return out


# ------------------------------------------------------------------ verdicts


def _gate_detail(v) -> dict:
    err = str(v.error) if v.error else ""
    spoke = "call:" if "'call:" in err or "\"call:" in err else ("guard:" if "guard:" in err else None)
    return {"accepted": v.accepted, "gate": v.gate, "subtype": getattr(v.error, "subtype", None),
            "invariant_kind": spoke if v.gate == "C" else None, "error": err[:200],
            "environment": (not v.accepted) and X.classify(v).startswith("environment")}


def stepcheck_judge(k: StateKernel, sid: str, nid: str, before: str, after: str) -> dict:
    base = k.commit(sid, nid, source=before, dry_run=True)
    if not base.accepted:
        return {"accepted": None, "gate": None, "note": f"baseline rejected: {X.classify(base)}", "caught": False}
    t0 = time.perf_counter()
    v = k.commit(sid, nid, source=after, dry_run=True)
    d = _gate_detail(v)
    d["ms"] = round((time.perf_counter() - t0) * 1000, 1)
    d["caught"] = (not v.accepted) and v.gate in ("B", "C") and not d["environment"]
    return d


def main() -> int:
    t_start = time.perf_counter()
    head, dirty = git_head()
    k = StateKernel(ephemeral=True)
    cases: list[dict] = []

    # --- Python categories on requests / flask: every candidate first, then a balanced pick
    pools: dict[str, dict[str, list[dict]]] = {c: {} for c in "ABC"}
    for key, (repo, _old, new, pkg, modules) in X.PACKAGES.items():
        files = {rel: s for rel, s in X.package_files(repo, new, pkg, modules).items() if X.parses(s)}
        root = X.make_project(files, pkg)
        sid = k.init_session(root)
        nodes = X.node_ids(k, sid)
        for rel, src in files.items():
            node = nodes.get(f"{pkg}/{rel}")
            if node is None:
                continue
            per_module = 6  # spread the cases over modules, not one file
            for cat, found in (("A", category_a(src, per_module)), ("B", category_b(src, 3)),
                               ("C", category_c(src, node["invariants_auto_mined"], per_module))):
                for fn, desc, after in found:
                    pools[cat].setdefault(key, []).append(
                        {"category": cat, "label": f"{repo}@{new}", "root": root, "rel": f"{pkg}/{rel}", "module": rel,
                         "function": fn, "description": desc, "before": src, "after": after, "node_id": node["node_id"],
                         "sid": sid, "lang": "python",
                         "call_probe_on_target": any(i.startswith(f"call:{fn}(") for i in node["invariants"]),
                         "guards_mined_on_target": sum(1 for i in node["invariants_auto_mined"]
                                                       if i.startswith(f"guard:{fn}:") or i.startswith(f"guard:{fn}."))})
    for cat in "ABC":
        queues = [list(v) for v in pools[cat].values()]
        picked: list[dict] = []
        while len(picked) < CAP[cat] and any(queues):
            for q in queues:  # round-robin across packages
                if q and len(picked) < CAP[cat]:
                    picked.append(q.pop(0))
        cases += picked

    # --- D: polyglot references (the audit's picks, cached)
    tree_raw = X.fetch(A.POLY_TREE)
    if tree_raw is not None:
        paths = [t["path"] for t in json.loads(tree_raw)["tree"]]
        from kernel import _okf
        per_lang = CAP["D"] // 4
        for lang in ("javascript", "go", "rust", "java"):
            if lang == "java":
                cands = [p for p in paths if re.match(rf"{lang}/exercises/practice/[^/]+/\.meta/src/reference/java/[^/]+\.java$", p)]
            elif lang == "javascript":
                cands = [p for p in paths if re.match(rf"{lang}/exercises/practice/[^/]+/\.meta/proof\.ci\.js$", p)]
            else:
                cands = [p for p in paths if re.match(rf"{lang}/exercises/practice/[^/]+/\.meta/example\.{A.EXT[lang][1:]}$", p)]
            project: dict[str, str] = {}
            for p in cands[: A.PER_LANGUAGE * 8]:  # a wider pick than the audit: flips need guards to exist
                data = X.fetch(A.POLY_RAW + p)
                if data is None:
                    continue
                slug = p.split("/")[3]
                name = Path(p).name if lang == "java" else slug.replace("-", "_") + A.EXT[lang]
                project[f"{slug}/{name}"] = data.decode("utf-8")
            if not project:
                continue
            root = X.make_project(project)
            sid = k.init_session(root)
            nodes = X.node_ids(k, sid)
            got = 0
            for rel, src in project.items():
                node = nodes.get(rel)
                if node is None or got >= per_lang:
                    continue
                mod = _okf.lang_module(rel)
                for fn, desc, after in category_d(lang, rel, src, mod, per_lang - got):
                    cases.append({"category": "D", "label": f"Aider polyglot/{lang}", "root": root, "rel": rel, "module": rel,
                                  "function": fn, "description": desc, "before": src, "after": after, "node_id": node["node_id"],
                                  "sid": sid, "lang": lang, "call_probe_on_target": False,
                                  "guards_mined_on_target": sum(1 for i in node["invariants_auto_mined"] if i.startswith("guard:"))})
                    got += 1
    print(f"corpus: " + ", ".join(f"{c}={sum(x['category'] == c for x in cases)}" for c in "ABCD"), flush=True)

    # --- StepCheck
    for c in cases:
        c["stepcheck"] = stepcheck_judge(k, c["sid"], c["node_id"], c["before"], c["after"])
    print("  stepcheck verdicts done", flush=True)

    # --- Skylos
    if not NO_SKYLOS:
        roots = sorted({c["root"] for c in cases}, key=str)
        before: dict[Path, list[dict]] = {}
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for root, (finds, _s, err) in zip(roots, pool.map(B.skylos_scan, roots)):
                before[root] = finds
                if err:
                    print("  skylos before-scan error:", err, flush=True)

        def after_scan(c: dict) -> dict:
            copy = Path(tempfile.mkdtemp(prefix="sc-honest-after-"))
            shutil.copytree(c["root"], copy, dirs_exist_ok=True)
            (copy / c["rel"]).write_text(c["after"], encoding="utf-8", newline="\n")
            finds, seconds, err = B.skylos_scan(copy)
            shutil.rmtree(copy, ignore_errors=True)
            new = B.new_findings(before[c["root"]], finds, c["rel"])
            return {"caught": bool(new), "new_findings": [{k_: f[k_] for k_ in ("section", "rule_id", "name", "line")} for f in new][:6],
                    "seconds": round(seconds, 1), "error": err}

        done = 0
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for c, res in zip(cases, pool.map(after_scan, cases)):
                c["skylos"] = res
                done += 1
                if done % 20 == 0:
                    print(f"  skylos after-scans {done}/{len(cases)}", flush=True)
    else:
        for c in cases:
            c["skylos"] = {"caught": None, "new_findings": [], "skipped": True}

    # --- per-category summary
    def summarize(cat: str) -> dict:
        rows = [c for c in cases if c["category"] == cat]
        n = len(rows)
        sc = sum(c["stepcheck"]["caught"] for c in rows)
        sky = sum(bool(c["skylos"]["caught"]) for c in rows)
        kinds: dict[str, int] = {}
        for c in rows:
            if c["stepcheck"]["caught"]:
                key = f"Gate {c['stepcheck']['gate']}" + (f" {c['stepcheck']['invariant_kind']}" if c["stepcheck"].get("invariant_kind") else "") \
                    + (f" {c['stepcheck']['subtype']}" if c["stepcheck"].get("subtype") else "")
                kinds[key] = kinds.get(key, 0) + 1
        rules: dict[str, int] = {}
        for c in rows:
            for f in c["skylos"]["new_findings"]:
                rid = f["rule_id"] or f["section"]
                rules[rid] = rules.get(rid, 0) + 1
        return {"cases": n, "stepcheck_caught": sc, "stepcheck_pct": round(100 * sc / n, 1) if n else None,
                "skylos_caught": sky, "skylos_pct": round(100 * sky / n, 1) if n else None,
                "stepcheck_kinds": kinds, "skylos_rules": dict(sorted(rules.items(), key=lambda kv: -kv[1])),
                "baseline_skipped": sum("note" in c["stepcheck"] for c in rows),
                "missed_examples": [f"{c['module']}::{c['function']} — {c['description']}" for c in rows if not c["stepcheck"]["caught"]][:8],
                "targets_with_call_probe": sum(c["call_probe_on_target"] for c in rows)}

    summary = {cat: summarize(cat) for cat in "ABCD"}
    for lang in ("javascript", "go", "rust", "java"):
        rows = [c for c in cases if c["category"] == "D" and c["lang"] == lang]
        if rows:
            summary[f"D_{lang}"] = {"cases": len(rows), "stepcheck_caught": sum(c["stepcheck"]["caught"] for c in rows),
                                    "skylos_caught": sum(bool(c["skylos"]["caught"]) for c in rows)}

    # --- fold in the existing receipts
    def load(name):
        p = RECEIPTS / name
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    cert, audit, sky = load("external_benchmark_certification.json"), load("loophole_audit.json"), load("skylos_vs_stepcheck.json")
    paper = {"faults": {"stepcheck_tp": 0, "stepcheck_fn": 0, "skylos_tp": 0, "skylos_fn": 0},
             "legit": {"n": 0, "stepcheck_fp": 0, "skylos_fp": 0}}
    rows_md: list[list[str]] = []

    def add_fault_row(source, label, n, sc, sky_c, note=""):
        paper["faults"]["stepcheck_tp"] += sc
        paper["faults"]["stepcheck_fn"] += n - sc
        if sky_c is not None:
            paper["faults"]["skylos_tp"] += sky_c
            paper["faults"]["skylos_fn"] += n - sky_c
        rows_md.append([source, label, str(n), f"{sc}/{n} ({100 * sc / n:.1f}%)" if n else "—",
                        (f"{sky_c}/{n} ({100 * sky_c / n:.1f}%)" if n and sky_c is not None else "n/a"), note])

    if sky:
        for r in sky["table"]:
            if r["category"] in ("ALL", "subtle AST mutations (subtotal)"):
                continue
            add_fault_row("skylos_vs_stepcheck.json", r["category"], r["cases"], r["stepcheck_caught"], r["skylos_caught"])
    if cert:
        b = cert["b_gold_patches"]
        n_legit = b["patches"] - b.get("environment_rejections", 0)
        strict_rej = sum(1 for r in b["rows"] if not r["strict"] and not str(r.get("strict_rejection", "")).startswith("environment"))
        paper["legit"]["n"] += n_legit
        paper["legit"]["stepcheck_fp"] += strict_rej
        rows_md.append(["external_benchmark_certification.json", "legitimate human gold patches (CanItEdit + requests/flask tag diffs), strict",
                        str(n_legit), f"{strict_rej} false rejections ({100 * strict_rej / n_legit:.1f}% FPR)" if n_legit else "—", "n/a",
                        f"declared pass {b.get('declared_pass_rate_excluding_environment_pct')}%; reasons {json.dumps(b.get('strict_rejection_reasons'))}"])
        a = cert["a_causal_cone_and_compression"]
        rows_md.append(["external_benchmark_certification.json", "causal-cone recall / compression", str(a["checkouts"]),
                        f"accounted recall {a['cone_accounted_recall_pct']}%, verbatim {a['cone_verbatim_recall_pct']}%",
                        "n/a", f"compression {a['aggregate_compression_pct']}%, overshoots {a['checkouts_with_negative_compression']}"])
    if audit:
        for v in audit["verdicts"]:
            rows_md.append(["loophole_audit.json", f"{v['vector']} {v['test']}", "—", v["result"], "n/a", v["detail"][:120]])

    for cat, label in (("A", "A. post-guard algorithmic corruption in class methods"),
                       ("B", "B. dropped impure side-effect statement"),
                       ("D", "D. polyglot guard flips / deletions (TS, Go, Rust, Java)")):
        s = summary[cat]
        add_fault_row("paper_honest_eval.json", label, s["cases"], s["stepcheck_caught"],
                      None if NO_SKYLOS else s["skylos_caught"],
                      f"StepCheck via {s['stepcheck_kinds']}; targets with a call: probe {s['targets_with_call_probe']}")
    s = summary["C"]
    paper["legit"]["n"] += s["cases"]
    paper["legit"]["stepcheck_fp"] += s["stepcheck_caught"]
    if not NO_SKYLOS:
        paper["legit"]["skylos_fp"] += s["skylos_caught"]
    rows_md.append(["paper_honest_eval.json", "C. semantically equivalent guard refactors (false-positive probe)", str(s["cases"]),
                    f"{s['stepcheck_caught']} false rejections ({s['stepcheck_pct']}% FPR)",
                    "n/a" if NO_SKYLOS else f"{s['skylos_caught']} new findings ({s['skylos_pct']}%)",
                    f"rejections by {s['stepcheck_kinds']}"])

    f, lg = paper["faults"], paper["legit"]
    rec = f["stepcheck_tp"] / (f["stepcheck_tp"] + f["stepcheck_fn"]) if f["stepcheck_tp"] + f["stepcheck_fn"] else None
    prec = f["stepcheck_tp"] / (f["stepcheck_tp"] + lg["stepcheck_fp"]) if f["stepcheck_tp"] + lg["stepcheck_fp"] else None
    fpr = lg["stepcheck_fp"] / lg["n"] if lg["n"] else None
    sky_rec = f["skylos_tp"] / (f["skylos_tp"] + f["skylos_fn"]) if f["skylos_tp"] + f["skylos_fn"] else None
    sky_fpr = lg["skylos_fp"] / s["cases"] if (s["cases"] and not NO_SKYLOS) else None
    paper["metrics"] = {
        "stepcheck": {"recall": rec, "precision": prec, "false_positive_rate": fpr,
                      "fault_cases": f["stepcheck_tp"] + f["stepcheck_fn"], "legit_cases": lg["n"]},
        "skylos": {"recall_on_fault_cases_it_was_run_on": sky_rec, "fault_cases": f["skylos_tp"] + f["skylos_fn"],
                   "false_positive_rate_on_category_c": sky_fpr},
        "composition": "faults = skylos_vs_stepcheck corpus (239: certification guard drops + stub wipes + audit mutation "
                       "operators) + A + B + D; legitimate edits = certification gold patches judged strict (environment "
                       "rejections excluded) + C",
    }
    blind = {
        "stepcheck": [f"{c['category']}: {c['module']}::{c['function']} — {c['description']}" for c in cases
                      if c["category"] != "C" and not c["stepcheck"]["caught"]],
        "stepcheck_false_positives": [f"{c['module']}::{c['function']} — {c['description']} -> {c['stepcheck'].get('error', '')[:100]}"
                                      for c in cases if c["category"] == "C" and c["stepcheck"]["caught"]],
    }

    receipt = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "generator": ".stepcheck/discovery/paper_honest_evaluation.py",
        "kernel_commit": head, "backend_dirty": dirty, "python": platform.python_version(), "platform": platform.platform(),
        "skylos": {"version": B.skylos_version() if not NO_SKYLOS else None, "flags": B.SKYLOS_FLAGS, "catch_rule": "any new finding in the mutated file vs the before-scan"},
        "stepcheck": {"catch_rule": "strict dry-run commit rejected at Gate B or C"},
        "caps": CAP, "summary": summary, "paper_metrics": paper, "blind_spots": blind,
        "cases": [{k_: v for k_, v in c.items() if k_ not in ("before", "after", "root", "sid")} | {"root": str(c["root"])} for c in cases],
        "sources": X.SOURCES, "runtime_s": round(time.perf_counter() - t_start, 1),
    }
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(receipt, indent=1, default=str), encoding="utf-8")

    print(f"\nHONEST EVALUATION — StepCheck {head}{' (+dirty backend)' if dirty else ''} vs Skylos {receipt['skylos']['version']}")
    print("| Receipt | Category | Cases | StepCheck (strict Gate B/C) | Skylos 4.50.1 | Notes |")
    print("| --- | --- | ---: | --- | --- | --- |")
    for r in rows_md:
        print("| " + " | ".join(x.replace("|", "\\|") for x in r) + " |")
    m = paper["metrics"]["stepcheck"]
    print(f"\nStepCheck over {m['fault_cases']} fault cases + {m['legit_cases']} legitimate edits: "
          f"recall {100 * m['recall']:.1f}%, precision {100 * m['precision']:.1f}%, false-positive rate {100 * m['false_positive_rate']:.1f}%")
    ms = paper["metrics"]["skylos"]
    if ms["recall_on_fault_cases_it_was_run_on"] is not None:
        print(f"Skylos over {ms['fault_cases']} fault cases: recall {100 * ms['recall_on_fault_cases_it_was_run_on']:.1f}%"
              + (f"; false positives on C {100 * ms['false_positive_rate_on_category_c']:.1f}%" if ms["false_positive_rate_on_category_c"] is not None else ""))
    print(f"Blind spots (StepCheck misses): {len(blind['stepcheck'])}; false positives (C): {len(blind['stepcheck_false_positives'])}")
    for line in blind["stepcheck"][:12]:
        print("  miss:", line)
    for line in blind["stepcheck_false_positives"][:12]:
        print("  FP:  ", line)
    print(f"receipt: {RECEIPT}  ({receipt['runtime_s']} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
