"""External public-dataset certification of the StateKernel (Seam 1 only).

Data (fetched over HTTPS, cached under external_cache/, every payload's sha256 in the receipt):
  - nuprl/CanItEdit test split rows 0-39 (Hugging Face datasets-server): real `before` / `after`
    human edits of standalone Python programs.
  - psf/requests v2.32.2 -> v2.32.3 and pallets/flask 3.0.2 -> 3.0.3: real package modules at two
    consecutive release tags; the newer tag's module is the human "gold patch" of the older one.

Parts:
  a) Causal cone & compression: focused checkouts of real functions/methods. The cone ground truth
     is computed here by an independent AST walker (same-file calls, self./cls./Class. methods,
     bare decorators, module constants read, a method's __init__/__post_init__), not by the kernel.
  b) Zero-false-positive gold patches: commit the human `after` through StateKernel.commit();
     strict (allow_deletion=False) and declared (allow_deletion=True) pass rates; rejections are
     classified, environment = a third-party import missing from this interpreter.
  c) Fault interception: stub an unfocused body to `...`, drop a mined leading guard, break a
     signature a sibling module imports; rejection rate per fault and commit latency.
  d) Wild AST blind spots: guard-like idioms in the external functions vs what Gate C mined.

Gate C executes staged module code in-process (it is not a sandbox); the sources are pinned
public releases and a public benchmark. usage: verify_external_benchmarks.py [--offline]
Writes receipts/external_benchmark_certification.json and prints the summary table.
"""
from __future__ import annotations

import ast
import datetime as dt
import hashlib
import json
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CACHE = HERE / "external_cache"
RECEIPT = HERE / "receipts" / "external_benchmark_certification.json"


def _opt(flag: str) -> str | None:
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else None


# --kernel <checkout>: certify another checkout's kernel (e.g. a worktree at HEAD) with
# this same methodology; --out <file>: write that receipt elsewhere.
KERNEL_REPO = Path(_opt("--kernel")).resolve() if _opt("--kernel") else REPO
RECEIPT = Path(_opt("--out")).resolve() if _opt("--out") else RECEIPT
sys.path.insert(0, str(KERNEL_REPO / "backend"))

from kernel import StateKernel, _tokens  # noqa: E402

CANITEDIT = ("https://datasets-server.huggingface.co/rows?dataset=nuprl%2FCanItEdit&config=default"
             "&split=test&offset=0&length=40")
PACKAGES = {
    "requests": ("psf/requests", "v2.32.2", "v2.32.3", "requests",
                 ["__init__", "__version__", "_internal_utils", "adapters", "api", "auth", "certs", "compat",
                  "cookies", "exceptions", "help", "hooks", "models", "packages", "sessions", "status_codes",
                  "structures", "utils"]),
    "flask": ("pallets/flask", "3.0.2", "3.0.3", "flask",
              ["__init__", "__main__", "app", "blueprints", "cli", "config", "ctx", "debughelpers", "globals",
               "helpers", "logging", "sessions", "signals", "templating", "testing", "typing", "views",
               "wrappers"]),
}
SYMBOLS_PER_MODULE = 12
SOURCES: list[dict] = []
OFFLINE = "--offline" in sys.argv


def fetch(url: str) -> bytes | None:
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / hashlib.sha256(url.encode()).hexdigest()[:24]
    if path.exists():
        data = path.read_bytes()
    elif OFFLINE:
        return None
    else:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "stepcheck-external-cert"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
        except Exception:  # noqa: BLE001 — a missing path at one tag is expected
            return None
        path.write_bytes(data)
    SOURCES.append({"url": url, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    return data


def package_files(repo: str, tag: str, pkg: str, modules: list[str]) -> dict[str, str]:
    """relative path inside the package dir -> source, trying src/ then flat layouts."""
    out = {}
    for m in modules:
        for prefix in (f"src/{pkg}", pkg):
            data = fetch(f"https://raw.githubusercontent.com/{repo}/{tag}/{prefix}/{m}.py")
            if data is not None:
                out[f"{m}.py"] = data.decode("utf-8")
                break
    return out


def parses(src: str) -> bool:
    try:
        ast.parse(src)
        return True
    except SyntaxError:
        return False


# ------------------------------------------------------------------ projects


def make_project(files: dict[str, str], pkg: str | None = None) -> Path:
    root = Path(tempfile.mkdtemp(prefix="sc-ext-"))
    base = root / pkg if pkg else root
    base.mkdir(parents=True, exist_ok=True)
    for rel, src in files.items():
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text(src, encoding="utf-8", newline="\n")
    return root


def node_ids(k: StateKernel, sid: str) -> dict[str, dict]:
    return {n["path"].replace("\\", "/"): n for n in k.graph(sid)["nodes"]}


# ------------------------------------------------- (a) independent causal cone


def cone_truth(tree: ast.Module, focus: str) -> dict[str, set[str]]:
    funcs = {s.name: s for s in tree.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))}
    classes = {s.name: s for s in tree.body if isinstance(s, ast.ClassDef)}
    methods = {c: {m.name: m for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
               for c, cls in classes.items()}
    consts = {}
    for s in tree.body:
        if isinstance(s, (ast.Assign, ast.AnnAssign)):
            for t in (s.targets if isinstance(s, ast.Assign) else [s.target]):
                for n in ast.walk(t):
                    if isinstance(n, ast.Name):
                        consts[n.id] = s

    def node_of(sym: str):
        if "." in sym:
            c, m = sym.split(".", 1)
            return methods.get(c, {}).get(m)
        return funcs.get(sym)

    cone = {"callees": set(), "decorators": set(), "constants": set(), "class_state": set()}
    seen, stack = {focus}, [focus]
    while stack:
        sym = stack.pop()
        node = node_of(sym)
        if node is None:
            continue
        owner = sym.split(".")[0] if "." in sym else None
        found: list[tuple[str, str]] = []
        if owner:
            found += [("class_state", f"{owner}.{m}") for m in ("__init__", "__post_init__") if m in methods[owner]]
        for sub in ast.walk(node):
            for d in getattr(sub, "decorator_list", []):
                if isinstance(d, ast.Name) and d.id in funcs:
                    found.append(("decorators", d.id))
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load) and sub.id in consts and sub.id not in funcs:
                cone["constants"].add(sub.id)
            if isinstance(sub, ast.Call):
                fn = sub.func
                if isinstance(fn, ast.Name) and fn.id in funcs:
                    found.append(("callees", fn.id))
                elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                    recv = fn.value.id
                    cls = owner if recv in ("self", "cls") else recv
                    if cls in methods and fn.attr in methods[cls]:
                        found.append(("callees", f"{cls}.{fn.attr}"))
        for kind, target in found:
            if target != focus:
                cone[kind].add(target)
            if target not in seen:
                seen.add(target)
                stack.append(target)
    for kind in ("callees", "decorators"):
        cone[kind] -= cone["class_state"]
    return cone


def segment(src: str, node: ast.AST) -> str:
    return ast.get_source_segment(src, node) or ""


def part_a(modules: list[tuple[str, str, Path, str]]) -> dict:
    """modules: (label, project_root, rel path, source) of each external module."""
    rows, kinds = [], {k: {"members": 0, "verbatim": 0, "accounted": 0} for k in
                       ("callees", "decorators", "constants", "class_state")}
    raw_total = payload_total = 0
    k = StateKernel(ephemeral=True)
    for label, root, rel, src in modules:
        tree = ast.parse(src)
        sid = k.init_session(root)
        nid = node_ids(k, sid).get(rel, {}).get("node_id")
        if nid is None:
            continue
        syms = [s.name for s in tree.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]
        syms += [f"{c.name}.{m.name}" for c in tree.body if isinstance(c, ast.ClassDef)
                 for m in c.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
        raw = _tokens.count(src)
        funcs = {s.name: s for s in tree.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))}
        classes = {s.name: s for s in tree.body if isinstance(s, ast.ClassDef)}
        consts = {}
        for s in tree.body:
            if isinstance(s, (ast.Assign, ast.AnnAssign)):
                for t in (s.targets if isinstance(s, ast.Assign) else [s.target]):
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name):
                            consts[n.id] = s
        for sym in syms[:SYMBOLS_PER_MODULE]:
            p = k.checkout(sid, nid, focus=[sym])
            frame = p.frame_markdown
            note = frame.split("```", 1)[0]
            raw_total += raw
            payload_total += p.token_count
            cone = cone_truth(tree, sym)
            row = {"module": label, "focus": sym, "raw_tokens": raw, "payload_tokens": p.token_count,
                   "compression_pct": round(100 * (1 - p.token_count / raw), 1) if raw else None,
                   "auto_skeletonized": p.auto_skeletonized, "elided": list(p.elided), "missing": []}
            for kind, members in cone.items():
                for m in members:
                    if kind == "constants":
                        node = consts.get(m)
                    elif "." in m:
                        c, meth = m.split(".", 1)
                        node = next((x for x in classes[c].body if getattr(x, "name", None) == meth), None)
                    else:
                        node = funcs.get(m)
                    text = segment(src, node) if node is not None else ""
                    verbatim = bool(text) and text in frame
                    accounted = verbatim or re.search(rf"\b{re.escape(m)}\b", note) is not None
                    kinds[kind]["members"] += 1
                    kinds[kind]["verbatim"] += verbatim
                    kinds[kind]["accounted"] += accounted
                    if not accounted:
                        row["missing"].append(f"{kind}:{m}")
            rows.append(row)
    pct = [r["compression_pct"] for r in rows if r["compression_pct"] is not None]
    for v in kinds.values():
        v["verbatim_recall_pct"] = round(100 * v["verbatim"] / v["members"], 1) if v["members"] else None
        v["accounted_recall_pct"] = round(100 * v["accounted"] / v["members"], 1) if v["members"] else None
    members = sum(v["members"] for v in kinds.values())
    return {
        "checkouts": len(rows),
        "raw_tokens_total": raw_total, "payload_tokens_total": payload_total,
        "aggregate_compression_pct": round(100 * (1 - payload_total / raw_total), 1) if raw_total else None,
        "median_compression_pct": statistics.median(pct) if pct else None,
        "checkouts_with_negative_compression": sum(1 for x in pct if x < 0),
        "overshoot_median_tokens": statistics.median([r["payload_tokens"] - r["raw_tokens"] for r in rows
                                                      if r["payload_tokens"] > r["raw_tokens"]] or [0]),
        "auto_skeletonized": sum(r["auto_skeletonized"] for r in rows),
        "budget_backstop_elisions": sum(1 for r in rows if r["elided"]),
        "cone": kinds,
        "cone_members_total": members,
        "cone_verbatim_recall_pct": round(100 * sum(v["verbatim"] for v in kinds.values()) / members, 1) if members else None,
        "cone_accounted_recall_pct": round(100 * sum(v["accounted"] for v in kinds.values()) / members, 1) if members else None,
        "unaccounted_examples": [f"{r['module']}::{r['focus']} -> {m}" for r in rows for m in r["missing"]][:15],
        "rows": rows,
    }


# ------------------------------------------------------------ (b) gold patches


def classify(verdict) -> str:
    err = str(verdict.error)
    if verdict.gate == "C" and "failed to load" in err and ("ModuleNotFoundError" in err or "ImportError" in err):
        return "environment (third-party import missing here)"
    sub = getattr(verdict.error, "subtype", None)
    return f"Gate {verdict.gate}" + (f" {sub}" if sub else "")


def part_b(pairs: list[tuple[str, Path, str, str]]) -> dict:
    """pairs: (label, project root at `before`, rel path, after source)."""
    k = StateKernel(ephemeral=True)
    rows = []
    sessions: dict[Path, str] = {}
    for label, root, rel, after in pairs:
        sid = sessions.get(root) or sessions.setdefault(root, k.init_session(root))
        nid = node_ids(k, sid)[rel]["node_id"]
        t0 = time.perf_counter()
        v = k.commit(sid, nid, source=after)
        ms = (time.perf_counter() - t0) * 1000
        row = {"task": label, "strict": v.accepted, "strict_ms": round(ms, 1), "dirtied": v.dirtied}
        if not v.accepted:
            row["strict_rejection"] = classify(v)
            row["strict_error"] = str(v.error)[:240]
            v2 = k.commit(sid, nid, source=after, allow_deletion=True)
            row["declared"] = v2.accepted
            if not v2.accepted:
                row["declared_rejection"] = classify(v2)
                row["declared_error"] = str(v2.error)[:240]
        else:
            row["declared"] = True
        rows.append(row)
    n = len(rows)
    env = [r for r in rows if r.get("declared_rejection", "").startswith("environment")]
    reasons: dict[str, int] = {}
    for r in rows:
        if not r["strict"]:
            reasons[r["strict_rejection"]] = reasons.get(r["strict_rejection"], 0) + 1
    return {
        "patches": n,
        "strict_pass_rate_pct": round(100 * sum(r["strict"] for r in rows) / n, 1) if n else None,
        "declared_pass_rate_pct": round(100 * sum(r["declared"] for r in rows) / n, 1) if n else None,
        "declared_pass_rate_excluding_environment_pct":
            round(100 * sum(r["declared"] for r in rows) / (n - len(env)), 1) if n - len(env) else None,
        "environment_rejections": len(env),
        "strict_rejection_reasons": reasons,
        "rejected_examples": [{k_: r[k_] for k_ in ("task", "strict_rejection", "strict_error", "declared",
                                                    "declared_rejection") if k_ in r}
                              for r in rows if not r["declared"] or not r["strict"]][:20],
        "median_commit_ms": statistics.median([r["strict_ms"] for r in rows]) if rows else None,
        "rows": rows,
    }


# ---------------------------------------------------------------- (c) faults


def _body_start(fn: ast.FunctionDef) -> int:
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
            and isinstance(body[0].value.value, str):
        return 1
    return 0


def stub_fault(src: str) -> tuple[str, str] | None:
    """The largest real body (>= 2 statements) -> `...`, the way a copied frame skeleton reads."""
    tree = ast.parse(src)
    cands = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and len(node.body) - _body_start(node) >= 2:
            cands.append(node)
    if not cands:
        return None
    fn = max(cands, key=lambda n: (n.end_lineno - n.lineno, n.name))
    lines = src.splitlines(keepends=True)
    first = fn.body[0].lineno
    indent = re.match(r"\s*", lines[first - 1]).group(0)
    new = "".join(lines[: first - 1]) + f"{indent}...\n" + "".join(lines[fn.end_lineno:])
    return (fn.name, new) if parses(new) else None


def _replace_with_pass(src: str, stmt: ast.stmt) -> str | None:
    """`stmt`'s lines -> one `pass` at its indent (valid whether or not it was alone in its block)."""
    lines = src.splitlines(keepends=True)
    indent = re.match(r"\s*", lines[stmt.lineno - 1]).group(0)
    new = "".join(lines[: stmt.lineno - 1]) + f"{indent}pass\n" + "".join(lines[stmt.end_lineno:])
    return new if parses(new) else None


def _simple_return(stmt) -> bool:
    v = stmt.value
    return v is None or isinstance(v, ast.Constant) or (
        isinstance(v, (ast.List, ast.Tuple, ast.Set)) and not v.elts) or (isinstance(v, ast.Dict) and not v.keys)


def guard_faults(src: str, at_line: int | None = None) -> list[tuple[str, tuple[str, str] | None]]:
    """One realistic guard fault per kind, chosen without looking at what the kernel
    mined: the first matching clause in file order, in any function or method
    (or only in the def starting at `at_line`)."""
    tree = ast.parse(src)
    fns = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
           and (at_line is None or n.lineno == at_line)]
    fns.sort(key=lambda n: n.lineno)
    found: dict[str, tuple[str, str] | None] = {k_: None for k_ in
                                                ("drop_if_raise_guard", "drop_assert_guard",
                                                 "drop_early_return_guard", "neuter_except_raise")}
    for fn in fns:
        rest = fn.body[_body_start(fn):]
        lead = []
        for stmt in rest:
            if isinstance(stmt, (ast.Assert, ast.If)):
                lead.append(stmt)
                continue
            break
        for node in ast.walk(fn):
            kind = stmt = None
            if isinstance(node, ast.If) and node.body and isinstance(node.body[-1], ast.Raise):
                kind, stmt = "drop_if_raise_guard", node
            elif isinstance(node, ast.Assert):
                kind, stmt = "drop_assert_guard", node
            elif (isinstance(node, ast.If) and node in lead and len(node.body) == 1 and not node.orelse
                  and isinstance(node.body[0], ast.Return) and _simple_return(node.body[0])):
                kind, stmt = "drop_early_return_guard", node
            elif isinstance(node, ast.ExceptHandler) and isinstance(node.body[-1], ast.Raise):
                kind, stmt = "neuter_except_raise", node.body[-1]
            if kind and found[kind] is None and (new := _replace_with_pass(src, stmt)):
                found[kind] = (fn.name, new)
    return list(found.items())


def signature_fault(src: str, imported: set[str]) -> tuple[str, str] | None:
    """Add a required positional parameter to a top-level function a sibling imports by name."""
    tree = ast.parse(src)
    lines = src.splitlines(keepends=True)
    for fn in tree.body:
        if isinstance(fn, ast.FunctionDef) and fn.name in imported and not fn.args.vararg:
            line = lines[fn.lineno - 1]
            new_line = re.sub(rf"def {fn.name}\(", f"def {fn.name}(__stepcheck_required, ", line, count=1)
            new_line = new_line.replace("(__stepcheck_required, )", "(__stepcheck_required)")
            new = "".join(lines[: fn.lineno - 1]) + new_line + "".join(lines[fn.lineno:])
            if new_line != line and parses(new):
                return fn.name, new
    return None


def imported_names(files: dict[str, str], module: str) -> set[str]:
    out = set()
    for rel, src in files.items():
        if rel == f"{module}.py":
            continue
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[-1] == module:
                out |= {a.name for a in node.names}
    return out


def part_c(projects: list[tuple[str, Path, dict[str, str], str | None]]) -> dict:
    """projects: (label, root, {rel path in project: source}, package or None)."""
    k = StateKernel(ephemeral=True)
    rows = []
    mined_total = 0
    for label, root, files, pkg in projects:
        sid = k.init_session(root)
        nodes = node_ids(k, sid)
        for rel, src in files.items():
            node = nodes.get(rel)
            if node is None:
                continue
            nid = node["node_id"]
            module = Path(rel).stem
            pkg_files = {Path(r).name: s for r, s in files.items()} if pkg else {}
            faults = [("stub_unfocused_body", stub_fault(src))] + guard_faults(src)
            mined_total += len(node["invariants_auto_mined"])
            if pkg:
                faults.append(("break_imported_signature", signature_fault(src, imported_names(pkg_files, module))))
            for kind, fault in faults:
                if fault is None:
                    continue
                target, staged = fault
                t0 = time.perf_counter()
                v = k.commit(sid, nid, source=staged)
                ms = (time.perf_counter() - t0) * 1000
                intercepted = (not v.accepted) or bool(v.dirtied)
                rows.append({"module": f"{label}:{rel}", "fault": kind, "target": target, "accepted": v.accepted,
                             "gate": v.gate, "subtype": getattr(v.error, "subtype", None),
                             "dirtied": v.dirtied, "intercepted": intercepted, "ms": round(ms, 1),
                             "error": str(v.error)[:200] if v.error else None})
                if v.accepted:  # restore the canonical source for the next fault
                    k.commit(sid, nid, source=src, allow_deletion=True)
    guard_rows = [r for r in rows if r["fault"] not in ("stub_unfocused_body", "break_imported_signature")]
    out: dict = {"faults": len(rows), "mined_invariants_in_corpus": mined_total,
                 "guard_faults": len(guard_rows),
                 "guard_interception_rate_pct":
                     round(100 * sum(r["intercepted"] for r in guard_rows) / len(guard_rows), 1) if guard_rows else None,
                 "by_kind": {}}
    for kind in sorted({r["fault"] for r in rows}):
        rs = [r for r in rows if r["fault"] == kind]
        gates: dict[str, int] = {}
        for r in rs:
            key = "accepted (missed)" if r["accepted"] and not r["dirtied"] else (
                "accepted, dependents dirtied" if r["accepted"] else f"Gate {r['gate']} {r['subtype'] or ''}".strip())
            gates[key] = gates.get(key, 0) + 1
        out["by_kind"][kind] = {"n": len(rs), "intercepted": sum(r["intercepted"] for r in rs),
                                "interception_rate_pct": round(100 * sum(r["intercepted"] for r in rs) / len(rs), 1),
                                "outcomes": gates,
                                "median_ms": statistics.median([r["ms"] for r in rs]),
                                "missed_examples": [f"{r['module']}::{r['target']}" for r in rs if not r["intercepted"]][:8]}
    out["overall_interception_rate_pct"] = round(100 * sum(r["intercepted"] for r in rows) / len(rows), 1) if rows else None
    out["median_commit_ms"] = statistics.median([r["ms"] for r in rows]) if rows else None
    out["rows"] = rows
    return out


# -------------------------------------------------------- (d) AST blind spots


def idioms(fn: ast.FunctionDef) -> set[str]:
    found = set()
    lead = fn.body[_body_start(fn):]
    for stmt in lead[:6]:  # the leading run where guards live
        if isinstance(stmt, ast.Assert):
            found.add("assert_guard")
        elif isinstance(stmt, ast.If) and stmt.body and isinstance(stmt.body[-1], ast.Raise):
            t = stmt.test
            is_inst = any(isinstance(n, ast.Call) and getattr(n.func, "id", None) == "isinstance" for n in ast.walk(t))
            found.add("isinstance_raise_guard" if is_inst else "if_raise_guard")
        elif isinstance(stmt, ast.If) and stmt.body and isinstance(stmt.body[-1], ast.Return):
            found.add("early_return_guard")
    for node in ast.walk(fn):
        if isinstance(node, ast.Match):
            found.add("match_case")
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.IfExp):
            found.add("ternary_return")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" \
                and len(node.args) == 2:
            found.add("dict_get_default")
        elif isinstance(node, ast.Try) and any(isinstance(n, ast.Raise) for h in node.handlers for n in ast.walk(h)):
            found.add("try_except_raise")
    nested_raise = any(isinstance(n, ast.Raise) for s in fn.body[_body_start(fn) + 1:] if isinstance(s, (ast.If, ast.For, ast.While, ast.With))
                       for n in ast.walk(s))
    if nested_raise and "if_raise_guard" not in found and "isinstance_raise_guard" not in found:
        found.add("non_leading_raise")
    return found


def part_d(modules: list[tuple[str, Path, str, str]]) -> dict:
    k = StateKernel(ephemeral=True)
    table: dict[str, dict] = {}
    sweep: dict[str, dict] = {}
    functions = 0
    seen_roots: dict[Path, str] = {}
    for label, root, rel, src in modules:
        sid = seen_roots.get(root) or seen_roots.setdefault(root, k.init_session(root))
        node = node_ids(k, sid).get(rel)
        if node is None:
            continue
        mined = node["invariants_auto_mined"]
        tree = ast.parse(src)
        fns = [(fn.name, fn, False) for fn in tree.body if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))]
        fns += [(f"{c.name}.{m.name}", m, True) for c in tree.body if isinstance(c, ast.ClassDef)
                for m in c.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for name, fn, is_method in fns:
            functions += 1
            calls = not is_method and any(inv.startswith(f"call:{name}(") for inv in mined)
            # a guard mined under a nested scope (`fn.Inner.m`) still guards `fn`
            clauses = [inv.split(":", 2)[2] for inv in mined
                       if inv.startswith(f"guard:{name}:") or inv.startswith(f"guard:{name}.")]
            kinds = {
                "assert_guard": any(c.startswith("assert ") for c in clauses),
                "if_raise_guard": calls or any(c.startswith("if ") and " raises " in c for c in clauses),
                "isinstance_raise_guard": calls or any(c.startswith("if ") and "isinstance(" in c for c in clauses),
                "early_return_guard": any(" returns " in c for c in clauses),  # incl. "returns early"
                "dict_get_default": calls or any(".get(" in c and c.endswith(" has default") for c in clauses),
                "try_except_raise": any(c.startswith("except ") for c in clauses),
                "non_leading_raise": any(" raises " in c for c in clauses),
            }
            for kind, fault in guard_faults(src, fn.lineno):
                if fault is None:
                    continue
                v = k.commit(sid, node["node_id"], source=fault[1])
                hit = (not v.accepted) or bool(v.dirtied)
                s_ = sweep.setdefault(kind, {"faults": 0, "intercepted": 0, "outcomes": {}, "missed_examples": []})
                s_["faults"] += 1
                s_["intercepted"] += hit
                key = "accepted (missed)" if not hit else f"Gate {v.gate} {getattr(v.error, 'subtype', None) or ''}".strip()
                s_["outcomes"][key] = s_["outcomes"].get(key, 0) + 1
                if not hit and len(s_["missed_examples"]) < 6:
                    s_["missed_examples"].append(f"{label}:{rel}::{name}")
                if v.accepted:
                    k.commit(sid, node["node_id"], source=src, allow_deletion=True)
            for idiom in idioms(fn):
                covered = kinds.get(idiom, calls)  # match/case, ternary: only a call: invariant counts
                key = f"{idiom} ({'method' if is_method else 'function'})"
                row = table.setdefault(key, {"functions": 0, "with_mined_invariant": 0, "unmined_examples": []})
                row["functions"] += 1
                row["with_mined_invariant"] += covered
                if not covered and len(row["unmined_examples"]) < 5:
                    row["unmined_examples"].append(f"{label}:{rel}::{name}")
    for row in table.values():
        row["unmined"] = row["functions"] - row["with_mined_invariant"]
    for s_ in sweep.values():
        s_["interception_rate_pct"] = round(100 * s_["intercepted"] / s_["faults"], 1)
    total = sum(s_["faults"] for s_ in sweep.values())
    return {"functions_scanned": functions,
            "guard_sweep": {"faults": total,
                            "intercepted": sum(s_["intercepted"] for s_ in sweep.values()),
                            "interception_rate_pct": round(100 * sum(s_["intercepted"] for s_ in sweep.values()) / total, 1)
                            if total else None,
                            "by_kind": sweep},
            "idioms": dict(sorted(table.items(), key=lambda kv: -kv[1]["unmined"]))}


# --------------------------------------------------------------------- main


def main() -> int:
    t_start = time.perf_counter()
    raw = fetch(CANITEDIT)
    if raw is None:
        sys.exit("could not fetch CanItEdit rows")
    rows = [r["row"] for r in json.loads(raw)["rows"]]
    tasks = []
    for r in rows:
        if not (parses(r["before"]) and parses(r["after"])):
            continue
        name = re.sub(r"\W", "_", r["name"]) or "task"
        name = name if name[0].isalpha() else f"t_{name}"
        tasks.append({"label": f"CanItEdit/{r['full_name']}", "file": f"{name}.py", "before": r["before"],
                      "after": r["after"], "libraries": (r.get("taxonomy") or {}).get("libraries", [])})

    pkgs = {}
    for key, (repo, old, new, pkg, modules) in PACKAGES.items():
        old_files = {k_: v for k_, v in package_files(repo, old, pkg, modules).items() if parses(v)}
        new_files = {k_: v for k_, v in package_files(repo, new, pkg, modules).items() if parses(v)}
        pkgs[key] = {"repo": repo, "old": old, "new": new, "pkg": pkg, "old_files": old_files, "new_files": new_files}

    # projects
    a_modules, b_pairs, c_projects = [], [], []
    for t in tasks:
        root_before = make_project({t["file"]: t["before"]})
        a_modules.append((t["label"], root_before, t["file"], t["before"]))
        b_pairs.append((t["label"], root_before, t["file"], t["after"]))
        c_projects.append((t["label"], make_project({t["file"]: t["before"]}), {t["file"]: t["before"]}, None))
    for key, p in pkgs.items():
        root_old = make_project(p["old_files"], p["pkg"])
        root_new = make_project(p["new_files"], p["pkg"])
        for rel, src in p["new_files"].items():
            a_modules.append((f"{p['repo']}@{p['new']}", root_new, f"{p['pkg']}/{rel}", src))
        for rel, src in p["new_files"].items():
            if rel in p["old_files"] and p["old_files"][rel] != src:
                b_pairs.append((f"{p['repo']}@{p['old']}->{p['new']}:{rel}", root_old, f"{p['pkg']}/{rel}", src))
        c_projects.append((f"{p['repo']}@{p['new']}", make_project(p["new_files"], p["pkg"]),
                           {f"{p['pkg']}/{rel}": s for rel, s in p["new_files"].items()}, p["pkg"]))

    # Part d commits faults: fresh copies, untouched by part b's gold patches.
    d_modules, fresh = [], {}
    for label, root, rel, src in a_modules:
        if root not in fresh:
            fresh[root] = make_project({str(p.relative_to(root)).replace("\\", "/"): p.read_text(encoding="utf-8")
                                        for p in root.rglob("*.py")})
        d_modules.append((label, fresh[root], rel, src))

    a = part_a(a_modules)
    b = part_b(b_pairs)
    c = part_c(c_projects)
    d = part_d(d_modules)

    head = subprocess.run(["git", "rev-parse", "--short=7", "HEAD"], cwd=KERNEL_REPO, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "backend"], cwd=KERNEL_REPO, capture_output=True, text=True).stdout.strip())
    receipt = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "generator": ".stepcheck/discovery/verify_external_benchmarks.py",
        "kernel_commit": head, "backend_dirty": dirty,
        "python": platform.python_version(), "platform": platform.platform(),
        "datasets": {
            "canitedit": {"url": CANITEDIT, "rows_fetched": len(rows), "tasks_parsed": len(tasks)},
            **{key: {"repo": p["repo"], "tags": [p["old"], p["new"]], "modules_old": len(p["old_files"]),
                     "modules_new": len(p["new_files"]),
                     "changed_between_tags": sum(1 for r_ in p["new_files"] if r_ in p["old_files"]
                                                 and p["old_files"][r_] != p["new_files"][r_])}
               for key, p in pkgs.items()},
        },
        "sources": SOURCES,
        "a_causal_cone_and_compression": a,
        "b_gold_patches": b,
        "c_fault_interception": c,
        "d_ast_blind_spots": d,
        "runtime_s": round(time.perf_counter() - t_start, 1),
    }
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(receipt, indent=1), encoding="utf-8")

    def line(k_, v_):
        print(f"  {k_:<58} {v_}")

    print("EXTERNAL BENCHMARK CERTIFICATION —", head + (" (+uncommitted backend changes)" if dirty else ""))
    print(f"  datasets: CanItEdit {len(tasks)}/{len(rows)} tasks; " + "; ".join(
        f"{p['repo']} {p['old']}->{p['new']} ({len(p['new_files'])} modules, "
        f"{receipt['datasets'][k_]['changed_between_tags']} changed)" for k_, p in pkgs.items()))
    print("a) causal cone & compression")
    line("focused checkouts", a["checkouts"])
    line("aggregate compression (1 - payload/raw)", f"{a['aggregate_compression_pct']}%")
    line("median compression per checkout", f"{a['median_compression_pct']}%")
    line("checkouts larger than the raw module", a["checkouts_with_negative_compression"])
    line("cone members (independent walker)", a["cone_members_total"])
    line("cone verbatim recall", f"{a['cone_verbatim_recall_pct']}%")
    line("cone accounted recall (verbatim or named in the frame note)", f"{a['cone_accounted_recall_pct']}%")
    for kind, v in a["cone"].items():
        line(f"  {kind}", f"{v['verbatim']}/{v['members']} verbatim, {v['accounted']}/{v['members']} accounted")
    print("b) gold patches (real human `after` through StateKernel.commit)")
    line("patches", b["patches"])
    line("strict pass rate (allow_deletion=False)", f"{b['strict_pass_rate_pct']}%")
    line("declared pass rate (allow_deletion=True)", f"{b['declared_pass_rate_pct']}%")
    line("declared pass rate excluding environment rejections", f"{b['declared_pass_rate_excluding_environment_pct']}%")
    line("strict rejection reasons", json.dumps(b["strict_rejection_reasons"]))
    line("median commit latency", f"{b['median_commit_ms']} ms")
    print("c) fault interception")
    line("mined invariants in corpus", c["mined_invariants_in_corpus"])
    line("guard faults intercepted", f"{c['guard_interception_rate_pct']}% of {c['guard_faults']}")
    for kind, v in c["by_kind"].items():
        line(f"{kind}", f"{v['intercepted']}/{v['n']} ({v['interception_rate_pct']}%), median {v['median_ms']} ms")
        line("  outcomes", json.dumps(v["outcomes"]))
    line("overall interception", f"{c['overall_interception_rate_pct']}%")
    print("d) wild AST blind spots (guard-like idioms vs Gate C mined invariants)")
    line("functions scanned", d["functions_scanned"])
    gs = d["guard_sweep"]
    line("guard sweep (every guard kind in every function)", f"{gs['intercepted']}/{gs['faults']} ({gs['interception_rate_pct']}%)")
    for kind, v in gs["by_kind"].items():
        line(f"  {kind}", f"{v['intercepted']}/{v['faults']} ({v['interception_rate_pct']}%)")
    for idiom, v in list(d["idioms"].items())[:14]:
        line(idiom, f"{v['functions']} functions, {v['with_mined_invariant']} mined, {v['unmined']} unmined")
    print(f"receipt: {RECEIPT}  ({receipt['runtime_s']} s)")
    before_path = RECEIPT.with_name("external_benchmark_certification.before.json")
    if before_path.exists():
        compare(json.loads(before_path.read_text(encoding="utf-8")), receipt)
    return 0


def _metrics(r: dict) -> dict:
    a, b, c, d = (r["a_causal_cone_and_compression"], r["b_gold_patches"], r["c_fault_interception"],
                  r["d_ast_blind_spots"])
    kinds = c["by_kind"]

    def rate(kind):
        v = kinds.get(kind)
        return f"{v['intercepted']}/{v['n']}" if v else "—"

    guard_kinds = [k_ for k_ in kinds if k_ not in ("stub_unfocused_body", "break_imported_signature")]
    g_n = sum(kinds[k_]["n"] for k_ in guard_kinds)
    g_hit = sum(kinds[k_]["intercepted"] for k_ in guard_kinds)
    idioms = d["idioms"]
    gs = d.get("guard_sweep")
    return {
        "aggregate compression": f"{a['aggregate_compression_pct']}%",
        "median compression": f"{a['median_compression_pct']}%",
        "checkouts larger than raw": a["checkouts_with_negative_compression"],
        "median overshoot (tokens, partial focus kept sliced)": a.get("overshoot_median_tokens", "n/a"),
        "cone verbatim recall": f"{a['cone_verbatim_recall_pct']}%",
        "cone accounted recall": f"{a['cone_accounted_recall_pct']}%",
        "gold patches strict pass": f"{b['strict_pass_rate_pct']}%",
        "gold patches declared pass": f"{b['declared_pass_rate_pct']}%",
        "stub interception": rate("stub_unfocused_body"),
        "signature-break interception": rate("break_imported_signature"),
        "guard faults (one per kind per module)": f"{g_hit}/{g_n}" if g_n else "—",
        "guard sweep (every function)": f"{gs['intercepted']}/{gs['faults']}" if gs else "—",
        "mined invariants in corpus": c["mined_invariants_in_corpus"],
        "guard-idiom functions with a mined guard":
            f"{sum(v['with_mined_invariant'] for v in idioms.values())}/{sum(v['functions'] for v in idioms.values())}",
        "median commit latency (gold)": f"{b['median_commit_ms']} ms",
    }


def compare(before: dict, after: dict) -> None:
    mb, ma = _metrics(before), _metrics(after)
    print("\nBEFORE -> AFTER (receipts/external_benchmark_certification.before.json -> current)")
    print(f"  {'metric':<44} {'before':>14} {'after':>14}")
    for k_ in ma:
        print(f"  {k_:<44} {str(mb.get(k_, '—')):>14} {str(ma[k_]):>14}")


if __name__ == "__main__":
    sys.exit(main())
