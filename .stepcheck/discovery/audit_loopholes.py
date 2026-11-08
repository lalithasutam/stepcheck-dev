"""Red-team loophole & multi-benchmark audit of the StateKernel and the lifecycle hooks.

Measurement only: nothing in backend/ is modified. Six vectors, each printed as
PASS / LOOPHOLE CONFIRMED / PARTIAL, receipt at receipts/loophole_audit.json.

1. SWE-bench Verified rows 0-24 (Hugging Face datasets-server, HTTPS, no Docker): for every
   single-file Python gold patch the base file is fetched from GitHub at `base_commit`, the gold
   `patch` and `test_patch` are applied with a unified-diff applier here, and the module is run
   through the certification harness: causal-cone recall, strict / declared gold-patch pass
   rate through StateKernel.commit(), Gate C invariant counts.
2. Aider polyglot-benchmark reference solutions (javascript, go, rust, java): does Gate B reject
   a function body stubbed to `{}` / `// ...` / `todo!()`; does Gate C mine any guards.
3. Mutation taxonomy on psf/requests and pallets/flask (dry-run commits of the unmutated module
   first, then of each mutant): decorator stripping, relational boundary flips inside guards and
   asserts, guard-action neutering, `False and` short-circuit injection, exception widening.
4. Hook bypass: MultiEdit whose second edit stubs a body / drops a guard (policy `decide()` and the
   installed hook script offline); a Bash write to a tracked module.
5. Two-hop re-export facade: consumer -> pkg/__init__ (re-export) -> pkg/app; break the signature.
6. Stale-session rejected sync: an older session whose Gate A rejection of the current tree
   rewrites a valid module's OKF frame and breaks `stepcheck ci`.

usage: audit_loopholes.py [--offline]
"""
from __future__ import annotations

import ast
import datetime as dt
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
RECEIPT = HERE / "receipts" / "loophole_audit.json"
HOME = Path(tempfile.mkdtemp(prefix="sc-audit-home-"))
os.environ["STEPCHECK_HOME"] = str(HOME)  # the audit's sessions never touch ~/.stepcheck
os.environ["STEPCHECK_HOOK_AUTOSTART"] = "0"
PY = sys.executable

sys.path.insert(0, str(HERE))
import verify_external_benchmarks as X  # noqa: E402  (adds backend/ to sys.path, imports kernel)

from kernel import StateKernel, _okf  # noqa: E402

sys.path.insert(0, str(BACKEND))
import hooks  # noqa: E402

SWE_URL = ("https://datasets-server.huggingface.co/rows?dataset=princeton-nlp%2FSWE-bench_Verified"
           "&config=default&split=test&offset=0&length=25")
POLY_TREE = "https://api.github.com/repos/Aider-AI/polyglot-benchmark/git/trees/main?recursive=1"
POLY_RAW = "https://raw.githubusercontent.com/Aider-AI/polyglot-benchmark/main/"
PER_LANGUAGE = 6


def ok(v) -> bool:
    return bool(getattr(v, "accepted", False))


def why(v) -> str:
    return f"Gate {v.gate}: {str(v.error)[:160]}"


def git_head() -> tuple[str, bool]:
    head = subprocess.run(["git", "rev-parse", "--short=7", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "backend"], cwd=REPO, capture_output=True, text=True).stdout.strip())
    return head, dirty


# ----------------------------------------------------------------- unified diff


def split_patch(patch: str) -> dict[str, dict]:
    """path -> {"new_file": bool, "hunks": [(old_start, [(tag, text), ...])]}"""
    files: dict[str, dict] = {}
    cur = None
    for line in patch.splitlines():
        m = re.match(r"^diff --git a/(.+?) b/(.+)$", line)
        if m:
            cur = files.setdefault(m.group(2), {"new_file": False, "hunks": []})
            continue
        if cur is None:
            continue
        if line.startswith("--- /dev/null"):
            cur["new_file"] = True
            continue
        if line.startswith(("--- ", "+++ ", "index ", "new file", "deleted file", "similarity", "rename ", "old mode", "new mode")):
            continue
        h = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
        if h:
            cur["hunks"].append((int(h.group(1)), []))
            continue
        if cur["hunks"] and line[:1] in (" ", "-", "+", "\\"):
            if line.startswith("\\"):
                continue  # "\ No newline at end of file"
            cur["hunks"][-1][1].append((line[0], line[1:]))
        elif cur["hunks"] and line == "":
            cur["hunks"][-1][1].append((" ", ""))
    return files


def apply_hunks(src: str, hunks: list[tuple[int, list[tuple[str, str]]]]) -> str | None:
    lines = src.split("\n")
    offset = 0
    for old_start, body in hunks:
        old = [t for tag, t in body if tag in " -"]
        new = [t for tag, t in body if tag in " +"]
        expected = max(0, old_start - 1 + offset) if old_start else 0
        idx = expected
        if old:
            found = None
            for cand in [expected] + [expected + d for k in range(1, 400) for d in (k, -k)]:
                if 0 <= cand <= len(lines) - len(old) and lines[cand: cand + len(old)] == old:
                    found = cand
                    break
            if found is None:
                return None
            idx = found
        lines[idx: idx + len(old)] = new
        offset = (idx - max(0, old_start - 1)) + len(new) - len(old)
    return "\n".join(lines)


# ----------------------------------------------- 1. SWE-bench Verified sample


def vector_swebench() -> dict:
    raw = X.fetch(SWE_URL)
    if raw is None:
        return {"error": "could not fetch SWE-bench rows"}
    rows = [r["row"] for r in json.loads(raw)["rows"]]
    tasks, skipped = [], []
    for r in rows:
        files = split_patch(r["patch"])
        code = [p for p in files if p.endswith(".py")]
        if len(files) != 1 or len(code) != 1:
            skipped.append({"instance": r["instance_id"], "reason": f"{len(files)} files in gold patch"})
            continue
        rel = code[0]
        before_b = X.fetch(f"https://raw.githubusercontent.com/{r['repo']}/{r['base_commit']}/{rel}")
        if before_b is None:
            skipped.append({"instance": r["instance_id"], "reason": "base file not fetched"})
            continue
        before = before_b.decode("utf-8")
        after = apply_hunks(before, files[rel]["hunks"])
        if after is None or not X.parses(before) or not X.parses(after):
            skipped.append({"instance": r["instance_id"], "reason": "gold patch did not apply cleanly / does not parse"})
            continue
        tests = {}
        for trel, spec in split_patch(r["test_patch"]).items():
            if not trel.endswith(".py"):
                continue
            if spec["new_file"]:
                tbefore = ""
            else:
                tb = X.fetch(f"https://raw.githubusercontent.com/{r['repo']}/{r['base_commit']}/{trel}")
                if tb is None:
                    continue
                tbefore = tb.decode("utf-8")
            tafter = apply_hunks(tbefore, spec["hunks"])
            if tafter is not None and X.parses(tafter):
                tests[trel] = (tbefore, tafter)
        tasks.append({"instance": r["instance_id"], "repo": r["repo"], "base_commit": r["base_commit"], "path": rel,
                      "before": before, "after": after, "tests": tests, "difficulty": r.get("difficulty")})

    a_modules, b_pairs, inv_rows = [], [], []
    k = StateKernel(ephemeral=True)
    for t in tasks:
        files = {t["path"]: t["before"], **{trel: tb for trel, (tb, _ta) in t["tests"].items() if tb}}
        root = X.make_project(files)
        label = f"SWE-bench/{t['instance']}"
        a_modules.append((label, root, t["path"], t["before"]))
        root_b = X.make_project(files)
        for trel, (_tb, ta) in t["tests"].items():  # the test patch lands on disk beside the gold patch
            (root_b / trel).parent.mkdir(parents=True, exist_ok=True)
            (root_b / trel).write_text(ta, encoding="utf-8", newline="\n")
        b_pairs.append((label, root_b, t["path"], t["after"]))
        sid = k.init_session(root)
        node = X.node_ids(k, sid).get(t["path"])
        if node:
            mined = node["invariants_auto_mined"]
            inv_rows.append({"instance": t["instance"], "repo": t["repo"], "module": t["path"],
                             "lines": t["before"].count("\n") + 1, "invariants": len(node["invariants"]),
                             "guards_mined": sum(i.startswith("guard:") for i in mined),
                             "call_invariants": sum(i.startswith("call:") for i in node["invariants"])})
    a = X.part_a(a_modules) if a_modules else {}
    b = X.part_b(b_pairs) if b_pairs else {}
    per_repo: dict[str, dict] = {}
    for r in inv_rows:
        d = per_repo.setdefault(r["repo"], {"modules": 0, "invariants": 0, "guards_mined": 0})
        d["modules"] += 1
        d["invariants"] += r["invariants"]
        d["guards_mined"] += r["guards_mined"]
    repos_present = sorted({r["repo"] for r in rows})
    return {
        "rows_fetched": len(rows), "repos_in_rows": repos_present,
        "single_file_python_tasks": len(tasks), "skipped": skipped,
        "test_patches_applied": sum(len(t["tests"]) for t in tasks),
        "a_cone_and_compression": {k_: v for k_, v in a.items() if k_ != "rows"},
        "b_gold_patches": {k_: v for k_, v in b.items() if k_ != "rows"},
        "c_gate_c_invariants": {"per_module": inv_rows, "per_repo": per_repo,
                                "total_invariants": sum(r["invariants"] for r in inv_rows),
                                "total_guards_mined": sum(r["guards_mined"] for r in inv_rows)},
        "note": "rows 0-24 of the Verified split are astropy and django instances; sympy and scikit-learn do not "
                "occur in this window",
    }


# ------------------------------------------------- 2. Aider polyglot benchmark


def match_brace(src: str, open_idx: int, lang: str) -> int | None:
    """Index of the `}` matching src[open_idx] == '{', skipping strings and comments."""
    depth, i, n = 0, open_idx, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            i = src.find("\n", i)
            if i < 0:
                return None
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                return None
            i = j + 2
            continue
        if c in "\"`" or (c == "'" and (lang != "rust" or (i + 2 < n and (src[i + 1] == "\\" or src[i + 2] == "'")))):
            q, j = c, i + 1
            while j < n and src[j] != q:
                j += 2 if src[j] == "\\" else 1
            i = j + 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def functions(mod, src: str) -> list:
    decls, _ = mod.parse(src)
    out = []

    def visit(d):
        if getattr(d, "is_function", False) and getattr(d, "body_open", None) is not None:
            out.append(d)
        for m in getattr(d, "members", []) or []:
            visit(m)

    for d in decls:
        visit(d)
    return out


STUBS = {"javascript": "{}", "go": "{\n\t// ...\n}", "rust": "{\n    todo!()\n}", "java": "{}"}
IDIOMS = {
    "javascript": {"if (...) throw": re.compile(r"if\s*\([^)]*\)\s*\{?\s*throw\b", re.S)},
    "go": {"if err != nil { return": re.compile(r"if\s+err\s*!=\s*nil\s*\{[^}]*return", re.S),
           "if ... { panic": re.compile(r"if\s+[^{]+\{\s*panic\(", re.S)},
    "rust": {"assert!": re.compile(r"\bassert(_eq|_ne)?!\s*\("), "panic!": re.compile(r"\bpanic!\s*\("),
             "if ... { return Err": re.compile(r"if\s+[^{]+\{\s*return\s+Err", re.S)},
    "java": {"if (...) throw": re.compile(r"if\s*\([^)]*\)\s*\{?\s*throw\b", re.S)},
}
EXT = {"javascript": ".js", "go": ".go", "rust": ".rs", "java": ".java"}


def vector_polyglot() -> dict:
    tree_raw = X.fetch(POLY_TREE)
    if tree_raw is None:
        return {"error": "could not fetch the polyglot-benchmark tree"}
    paths = [t["path"] for t in json.loads(tree_raw)["tree"]]
    picks: dict[str, list[str]] = {}
    for lang in ("javascript", "go", "rust", "java"):
        if lang == "java":
            cands = [p for p in paths if re.match(rf"{lang}/exercises/practice/[^/]+/\.meta/src/reference/java/[^/]+\.java$", p)]
        elif lang == "javascript":
            cands = [p for p in paths if re.match(rf"{lang}/exercises/practice/[^/]+/\.meta/proof\.ci\.js$", p)]
        else:
            cands = [p for p in paths if re.match(rf"{lang}/exercises/practice/[^/]+/\.meta/example\.{EXT[lang][1:]}$", p)]
        picks[lang] = cands[:PER_LANGUAGE]

    out: dict[str, dict] = {}
    for lang, files in picks.items():
        project: dict[str, str] = {}
        for p in files:
            data = X.fetch(POLY_RAW + p)
            if data is None:
                continue
            slug = p.split("/")[3]
            name = Path(p).name if lang == "java" else slug.replace("-", "_") + EXT[lang]
            project[f"{slug}/{name}"] = data.decode("utf-8")
        root = X.make_project(project)
        k = StateKernel(ephemeral=True)
        sid = k.init_session(root)
        nodes = X.node_ids(k, sid)
        stub_rows, guard_rows = [], []
        for rel, src in project.items():
            node = nodes.get(rel)
            if node is None:
                stub_rows.append({"file": rel, "tracked": False})
                continue
            mod = _okf.lang_module(rel)
            fns = functions(mod, src)
            spans = []
            for d in fns:
                close = match_brace(src, d.body_open, lang)
                if close is not None and close - d.body_open > 40:
                    spans.append((close - d.body_open, d.dotted, d.body_open, close))
            if spans:
                _size, name, bo, bc = max(spans)
                stubbed = src[:bo] + STUBS[lang] + src[bc + 1:]
                v = k.commit(sid, node["node_id"], source=stubbed, dry_run=True)
                stub_rows.append({"file": rel, "function": name, "body_chars": bc - bo, "rejected": not ok(v),
                                  "verdict": "accepted" if ok(v) else why(v)})
            else:
                stub_rows.append({"file": rel, "function": None, "rejected": None, "verdict": "no brace body found"})
            mined = [i for i in node["invariants_auto_mined"] if i.startswith("guard:")]
            present = {kind: len(rx.findall(src)) for kind, rx in IDIOMS[lang].items()}
            guard_rows.append({"file": rel, "guards_mined": len(mined), "examples": mined[:3], "idioms_in_source": present})
        tested = [r for r in stub_rows if r.get("rejected") is not None]
        out[lang] = {
            "files": len(project), "sources": files,
            "stub": {"tested": len(tested), "rejected": sum(r["rejected"] for r in tested),
                     "accepted_examples": [f"{r['file']}::{r['function']}" for r in tested if not r["rejected"]][:6],
                     "rows": stub_rows},
            "guards": {"files_with_mined_guards": sum(1 for r in guard_rows if r["guards_mined"]),
                       "guards_mined_total": sum(r["guards_mined"] for r in guard_rows),
                       "idioms_in_sources": {kind: sum(r["idioms_in_source"].get(kind, 0) for r in guard_rows)
                                             for kind in IDIOMS[lang]},
                       "rows": guard_rows},
        }
    return out


# ---------------------------------------------------- 3. mutation taxonomy


def _offsets(src: str, node: ast.AST) -> tuple[int, int]:
    starts = [0]
    for line in src.split("\n")[:-1]:
        starts.append(starts[-1] + len(line) + 1)
    lines = src.split("\n")

    def off(lineno: int, col: int) -> int:
        return starts[lineno - 1] + len(lines[lineno - 1].encode("utf-8")[:col].decode("utf-8", "replace"))

    return off(node.lineno, node.col_offset), off(node.end_lineno, node.end_col_offset)


def _replace(src: str, node: ast.AST, new_text: str) -> str:
    a, b = _offsets(src, node)
    return src[:a] + new_text + src[b:]


def _stmt_to(src: str, stmt: ast.stmt, replacement: str) -> str | None:
    lines = src.splitlines(keepends=True)
    indent = re.match(r"\s*", lines[stmt.lineno - 1]).group(0)
    new = "".join(lines[: stmt.lineno - 1]) + f"{indent}{replacement}\n" + "".join(lines[stmt.end_lineno:])
    return new if X.parses(new) else None


_FLIP_TEXT = {ast.LtE: ("<=", "<"), ast.GtE: (">=", ">"), ast.Eq: ("==", "!="), ast.NotEq: ("!=", "=="),
              ast.Lt: ("<", "<="), ast.Gt: (">", ">="), ast.Is: (" is ", " is not "), ast.IsNot: (" is not ", " is ")}
_FLIP_RX = {"<=": r"<=", ">=": r">=", "==": r"==", "!=": r"!=", "<": r"(?<![<>=!])<(?!=)", ">": r"(?<![<>=!-])>(?!=)",
            " is ": r" is (?!not\b)", " is not ": r" is not "}


def _flip_compare(src: str, cmp: ast.Compare) -> str | None:
    if len(cmp.ops) != 1 or type(cmp.ops[0]) not in _FLIP_TEXT:
        return None
    old, new = _FLIP_TEXT[type(cmp.ops[0])]
    seg = ast.get_source_segment(src, cmp) or ""
    m = re.search(_FLIP_RX[old], seg)
    if not m:
        return None
    new_seg = seg[: m.start()] + new + seg[m.end():]
    out = _replace(src, cmp, new_seg)
    return out if X.parses(out) else None


def mutants(src: str, cap: int = 2) -> list[tuple[str, str, str, str]]:
    """(operator, function, description, mutated source) — up to `cap` per operator."""
    tree = ast.parse(src)
    found: dict[str, list] = {k_: [] for k_ in (
        "a_decorator_strip", "b_compare_flip_if_guard", "b_compare_flip_assert", "c_guard_action_neuter",
        "d_short_circuit_false_and", "e_except_widen_keep_raise", "e_except_widen_swallow")}

    def add(kind, fn, desc, new):
        if new is not None and new != src and len(found[kind]) < cap:
            found[kind].append((kind, fn, desc, new))

    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        for dec in fn.decorator_list:
            name = ast.unparse(dec)
            lines = src.splitlines(keepends=True)
            new = "".join(lines[: dec.lineno - 1]) + "".join(lines[dec.end_lineno:])
            add("a_decorator_strip", fn.name, f"remove @{name}", new if X.parses(new) else None)
        for node in ast.walk(fn):
            if isinstance(node, ast.If) and node.body and isinstance(node.body[-1], ast.Raise):
                cond = ast.unparse(node.test)
                for cmp in [c for c in ast.walk(node.test) if isinstance(c, ast.Compare)]:
                    add("b_compare_flip_if_guard", fn.name, f"flip operator in `if {cond}`", _flip_compare(src, cmp))
                    break
                n_c = len(found["c_guard_action_neuter"])
                add("c_guard_action_neuter", fn.name, f"`if {cond}:` raise -> {'pass' if n_c % 2 == 0 else 'return None'}",
                    _stmt_to(src, node.body[-1], "pass" if n_c % 2 == 0 else "return None"))
                add("d_short_circuit_false_and", fn.name, f"`if {cond}` -> `if False and ({cond})`",
                    _replace(src, node.test, f"False and ({cond})"))
            elif isinstance(node, ast.Assert):
                for cmp in [c for c in ast.walk(node.test) if isinstance(c, ast.Compare)]:
                    add("b_compare_flip_assert", fn.name, f"flip operator in `assert {ast.unparse(node.test)}`",
                        _flip_compare(src, cmp))
                    break
            elif isinstance(node, ast.ExceptHandler) and node.type is not None and node.body and isinstance(node.body[-1], ast.Raise):
                tname = ast.unparse(node.type)
                if tname != "Exception":
                    add("e_except_widen_keep_raise", fn.name, f"`except {tname}:` -> `except Exception:` (raise kept)",
                        _replace(src, node.type, "Exception"))
                    swallowed = _stmt_to(src, node.body[-1], "pass")
                    if swallowed is not None:
                        t2 = ast.parse(swallowed)
                        h2 = next((h for h in ast.walk(t2) if isinstance(h, ast.ExceptHandler) and h.lineno == node.lineno), None)
                        if h2 is not None and h2.type is not None:
                            add("e_except_widen_swallow", fn.name, f"`except {tname}: raise` -> `except Exception: pass`",
                                _replace(swallowed, h2.type, "Exception"))
    return [m for rows in found.values() for m in rows]


def vector_mutations() -> dict:
    k = StateKernel(ephemeral=True)
    per_op: dict[str, dict] = {}
    baseline_failed, examples_accepted = [], []
    for key, (repo, _old, new, pkg, modules) in X.PACKAGES.items():
        files = {rel: s for rel, s in X.package_files(repo, new, pkg, modules).items() if X.parses(s)}
        root = X.make_project(files, pkg)
        sid = k.init_session(root)
        nodes = X.node_ids(k, sid)
        for rel, src in files.items():
            node = nodes.get(f"{pkg}/{rel}")
            if node is None:
                continue
            base = k.commit(sid, node["node_id"], source=src, dry_run=True)
            if not ok(base):
                baseline_failed.append({"module": f"{repo}:{rel}", "verdict": why(base)})
                continue
            for op, fn, desc, new_src in mutants(src):
                t0 = time.perf_counter()
                v = k.commit(sid, node["node_id"], source=new_src, dry_run=True)
                ms = (time.perf_counter() - t0) * 1000
                env = (not ok(v)) and X.classify(v).startswith("environment")
                d = per_op.setdefault(op, {"tried": 0, "intercepted": 0, "environment": 0, "accepted": 0, "gates": {}, "median_ms": [],
                                           "accepted_examples": []})
                d["tried"] += 1
                d["median_ms"].append(ms)
                if ok(v):
                    d["accepted"] += 1
                    ex = {"module": f"{repo}:{rel}", "function": fn, "mutation": desc}
                    if len(d["accepted_examples"]) < 8:
                        d["accepted_examples"].append(ex)
                    examples_accepted.append({"operator": op, **ex})
                elif env:
                    d["environment"] += 1
                else:
                    d["intercepted"] += 1
                    g = X.classify(v)
                    d["gates"][g] = d["gates"].get(g, 0) + 1
    import statistics
    for d in per_op.values():
        d["median_ms"] = round(statistics.median(d["median_ms"]), 1) if d["median_ms"] else None
        judged = d["tried"] - d["environment"]
        d["interception_pct"] = round(100 * d["intercepted"] / judged, 1) if judged else None
    return {"operators": per_op, "baseline_failed": baseline_failed, "accepted_mutants": len(examples_accepted)}


# ------------------------------------------------------------ 4. hook bypass

SVC = '''LIMIT = 10


def check(x):
    if x < 0:
        raise ValueError("negative")
    return x


def compute(a, b):
    total = a + b
    if total > LIMIT:
        total = LIMIT
    return total
'''
CLIENT = "from svc import check, compute\n\n\ndef run(v):\n    return compute(check(v), 1)\n"


def _hook_script(event: dict, root: Path) -> tuple[int, str, str]:
    script = REPO / ".claude" / "hooks" / "stepcheck_hook.py"
    env = {**os.environ, "STEPCHECK_HOOK_URL": "http://127.0.0.1:8461", "STEPCHECK_HOOK_AUTOSTART": "0",
           "STEPCHECK_BACKEND": str(BACKEND), "STEPCHECK_HOME": str(HOME), "PYTHONUTF8": "1"}
    p = subprocess.run([PY, "-S", str(script)], input=json.dumps(event), capture_output=True, text=True, env=env,
                       cwd=root, timeout=120)
    return p.returncode, p.stdout, p.stderr


def vector_hooks() -> dict:
    root = X.make_project({"svc.py": SVC, "client.py": CLIENT})
    k = StateKernel()
    sid = k.init_session(root)
    svc = root / "svc.py"
    attested = k.commit(sid, k.locate(sid, svc)["node_id"], source=SVC)  # the module has been through the gates once
    k.flush(sid)
    base = dict(session_id="audit", cwd=str(root), stepcheck_session_id=sid)
    results = {}

    stub_edit = {"old_string": "    total = a + b\n    if total > LIMIT:\n        total = LIMIT\n    return total\n", "new_string": "    ...\n"}
    guard_edit = {"old_string": "    if x < 0:\n        raise ValueError(\"negative\")\n", "new_string": ""}
    benign = {"old_string": "LIMIT = 10", "new_string": "LIMIT = 10  # ceiling"}

    for name, edits in (("multiedit_stub_second_edit", [benign, stub_edit]), ("multiedit_guard_drop_second_edit", [benign, guard_edit])):
        ev = {**base, "hook_event_name": "PreToolUse", "tool_name": "MultiEdit", "tool_input": {"file_path": str(svc), "edits": edits}}
        out = hooks.decide(ev, k)
        decision = (out.get("hookSpecificOutput") or {}).get("permissionDecision")
        rc, _so, se = _hook_script(ev, root)
        results[name] = {"policy_decision": decision or "allow (no opinion)",
                         "policy_reason": (out.get("hookSpecificOutput") or {}).get("permissionDecisionReason", "")[:200],
                         "hook_script_exit": rc, "hook_script_stderr": se.strip()[:200],
                         "disk_unchanged": svc.read_text(encoding="utf-8") == SVC,
                         "blocked_before_write": decision == "deny" and rc == 2}
    ev = {**base, "hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": str(svc), "content": SVC.replace(
        "    total = a + b\n    if total > LIMIT:\n        total = LIMIT\n    return total\n", "    ...\n")}}
    out = hooks.decide(ev, k)
    results["write_whole_file_stub"] = {"policy_decision": (out.get("hookSpecificOutput") or {}).get("permissionDecision", "allow (no opinion)")}

    # Bash writes the stub straight to disk: nothing is staged for PreToolUse to judge.
    stubbed = SVC.replace("    total = a + b\n    if total > LIMIT:\n        total = LIMIT\n    return total\n", "    ...\n")
    pre = hooks.decide({**base, "hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {"command": f"python - <<'EOF'\nopen({str(svc)!r},'w').write(...)\nEOF"}}, k)
    svc.write_text(stubbed, encoding="utf-8", newline="\n")
    post = hooks.decide({**base, "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "..."}}, k)
    stop = hooks.decide({**base, "hook_event_name": "Stop", "stop_hook_active": False}, k)
    node = k.locate(sid, svc)
    k.flush(sid)
    ci = subprocess.run([PY, "-m", "cli", "ci", str(root)], cwd=BACKEND, capture_output=True, text=True,
                        env={**os.environ, "PYTHONUTF8": "1"}, timeout=300)
    post_ctx = ((post or {}).get("hookSpecificOutput") or {}).get("additionalContext", "")
    results["bash_write_stub_to_tracked_module"] = {
        "module_attested_before_write": ok(attested),
        "pre_tool_use": pre or "allow (no opinion)", "post_tool_use": post or "no opinion",
        "stop": stop or "no block", "node_status_after_stop_sync": node["status"] if node else None,
        "stepcheck_ci_exit": ci.returncode, "stepcheck_ci_last_line": (ci.stdout + ci.stderr).strip().splitlines()[-1][:200]
        if (ci.stdout + ci.stderr).strip() else "",
        "blocked_before_write": False,
        "flagged_by_post_tool_use": "Gate" in post_ctx and "svc.py" in post_ctx,
        "blocked_at_stop": (stop or {}).get("decision") == "block",
        "caught_after_write": (node or {}).get("status") == "REJECTED" or ci.returncode != 0,
    }
    return results


# --------------------------------------------------- 5. two-hop re-export facade


def vector_reexport() -> dict:
    files = {
        "pkg/__init__.py": "from .app import foo\n\n__all__ = [\"foo\"]\n",
        "pkg/app.py": "def foo(a, b):\n    return a + b\n\n\ndef bar():\n    return 1\n",
        "consumer.py": "from pkg import foo\n\n\ndef use():\n    return foo(1, 2)\n",
        "direct.py": "from pkg.app import foo\n\n\ndef use():\n    return foo(1, 2)\n",
    }
    root = X.make_project(files)
    k = StateKernel(ephemeral=True)
    sid = k.init_session(root)
    nodes = X.node_ids(k, sid)
    app = nodes["pkg/app.py"]["node_id"]
    edges_before = {n["path"].replace("\\", "/"): n["deps"] for n in k.graph(sid)["nodes"]}
    v = k.commit(sid, app, source=files["pkg/app.py"].replace("def foo(a, b):", "def foo(a, b, c):"))
    after = {n["path"].replace("\\", "/"): n["status"] for n in k.graph(sid)["nodes"]}
    return {
        "accepted": ok(v), "verdict": "accepted" if ok(v) else why(v), "dirtied": v.dirtied,
        "deps": edges_before, "status_after": after,
        "consumer_dirty": after.get("consumer.py") == "DIRTY_OMISSION_RISK",
        "direct_dirty": after.get("direct.py") == "DIRTY_OMISSION_RISK",
        "init_dirty": after.get("pkg/__init__.py") == "DIRTY_OMISSION_RISK",
    }


# ------------------------------------------- 6. stale-session rejected sync


def _frame_sha(root: Path, nid: str) -> str | None:
    f = root / ".stepcheck" / "okf" / f"{nid}.md"
    if not f.exists():
        return None
    text = f.read_text(encoding="utf-8")
    shas = re.findall(r"^\s+sha256: ([0-9a-f]{64})", text, re.M)
    status = re.search(r"^status: (\S+)", text, re.M)
    return f"{shas[-1][:12] if shas else None} ({status.group(1) if status else '?'})"


def vector_stale_session() -> dict:
    files = {
        "a.py": "def f(x):\n    if x < 0:\n        raise ValueError(x)\n    return x\n\n\ndef g():\n    return 2\n",
        "b.py": "from a import f, g\n\n\ndef run(v):\n    return f(v) + g()\n",
    }
    root = X.make_project(files)
    import hashlib
    k = StateKernel()
    old = k.init_session(root)   # the stale session: its graph will keep requiring `g`
    new = k.init_session(root)   # the session the refactor is landed in
    nodes = X.node_ids(k, new)
    a_id, b_id = nodes["a.py"]["node_id"], nodes["b.py"]["node_id"]
    v0 = k.commit(old, a_id, source=files["a.py"])  # the old session attested a.py as it was
    v1 = k.commit(new, b_id, source="from a import f\n\n\ndef run(v):\n    return f(v) + 2\n", allow_deletion=True)
    v2 = k.commit(new, a_id, source="def f(x):\n    if x < 0:\n        raise ValueError(x)\n    return x\n", allow_deletion=True)
    disk_sha = hashlib.sha256((root / "a.py").read_bytes()).hexdigest()[:12]
    frame_after_refactor = _frame_sha(root, a_id)
    ci_before = subprocess.run([PY, "-m", "cli", "ci", str(root)], cwd=BACKEND, capture_output=True, text=True,
                               env={**os.environ, "PYTHONUTF8": "1"}, timeout=300)
    sync = k.sync(old)  # what the Stop hook / a PreToolUse does for every registered session
    frame_after_stale_sync = _frame_sha(root, a_id)
    ci_after = subprocess.run([PY, "-m", "cli", "ci", str(root)], cwd=BACKEND, capture_output=True, text=True,
                              env={**os.environ, "PYTHONUTF8": "1"}, timeout=300)
    last = lambda p: ((p.stdout + p.stderr).strip().splitlines() or [""])[-1][:220]  # noqa: E731
    return {
        "old_session_attested_original": ok(v0),
        "refactor_commits_accepted": ok(v1) and ok(v2), "a_disk_sha": disk_sha,
        "a_frame_after_refactor": frame_after_refactor, "ci_exit_after_refactor": ci_before.returncode,
        "stale_sync_rejected": sync["rejected"], "a_frame_after_stale_sync": frame_after_stale_sync,
        "ci_exit_after_stale_sync": ci_after.returncode, "ci_last_line_after_stale_sync": last(ci_after),
        "disk_unchanged_by_stale_sync": hashlib.sha256((root / "a.py").read_bytes()).hexdigest()[:12] == disk_sha,
        "corrupted": ci_before.returncode == 0 and ci_after.returncode != 0,
    }


# ---------------------------------------------------------------------- main


def verdicts(r: dict) -> list[tuple[str, str, str, str]]:
    rows = []
    s = r["1_swebench"]
    if "error" in s:
        rows.append(("1", "SWE-bench Verified sample", "N/A", s["error"]))
    else:
        a, b, c = s["a_cone_and_compression"], s["b_gold_patches"], s["c_gate_c_invariants"]
        rows.append(("1a", "SWE-bench causal-cone recall",
                     "PASS" if a.get("cone_accounted_recall_pct") == 100.0 else "PARTIAL",
                     f"{s['single_file_python_tasks']} single-file tasks of {s['rows_fetched']}; verbatim {a.get('cone_verbatim_recall_pct')}%, "
                     f"accounted {a.get('cone_accounted_recall_pct')}%; compression {a.get('aggregate_compression_pct')}%"))
        rows.append(("1b", "SWE-bench gold patches through commit()",
                     "PASS" if b.get("declared_pass_rate_excluding_environment_pct") == 100.0 else "PARTIAL",
                     f"strict {b.get('strict_pass_rate_pct')}%, declared {b.get('declared_pass_rate_pct')}%; "
                     f"strict rejections {b.get('strict_rejection_reasons')}"))
        rows.append(("1c", "Gate C invariants on SWE-bench modules", "INFO",
                     f"{c['total_invariants']} invariants ({c['total_guards_mined']} mined guards) over {len(c['per_module'])} modules: "
                     + ", ".join(f"{k_} {v['invariants']}" for k_, v in c["per_repo"].items())))
    p = r["2_polyglot"]
    for lang, d in p.items():
        if not isinstance(d, dict) or "stub" not in d:
            continue
        st, g = d["stub"], d["guards"]
        rows.append((f"2a-{lang}", f"{lang}: stub a function body", "PASS" if st["tested"] and st["rejected"] == st["tested"]
                     else "LOOPHOLE CONFIRMED", f"{st['rejected']}/{st['tested']} stubs rejected"
                     + (f"; accepted: {st['accepted_examples'][:2]}" if st["accepted_examples"] else "")))
        idioms = g["idioms_in_sources"]
        rows.append((f"2b-{lang}", f"{lang}: Gate C guard mining", "PASS" if g["guards_mined_total"] else
                     ("LOOPHOLE CONFIRMED" if any(idioms.values()) else "N/A"),
                     f"{g['guards_mined_total']} guards mined in {g['files_with_mined_guards']}/{d['files']} files; idioms present {idioms}"))
    for op, d in r["3_mutations"]["operators"].items():
        rows.append((f"3{op[0]}", f"mutation {op[2:]}", "PASS" if d["accepted"] == 0 else "LOOPHOLE CONFIRMED",
                     f"{d['intercepted']}/{d['tried'] - d['environment']} intercepted ({d['interception_pct']}%), "
                     f"{d['accepted']} accepted, gates {d['gates']}"))
    h = r["4_hooks"]
    for name in ("multiedit_stub_second_edit", "multiedit_guard_drop_second_edit"):
        d = h[name]
        rows.append(("4", f"hook {name}", "PASS" if d["blocked_before_write"] else "LOOPHOLE CONFIRMED",
                     f"policy {d['policy_decision']}, hook script exit {d['hook_script_exit']}, disk unchanged {d['disk_unchanged']}"))
    d = h["bash_write_stub_to_tracked_module"]
    bash_verdict = ("PASS" if d.get("flagged_by_post_tool_use") and d.get("blocked_at_stop") and d["caught_after_write"]
                    else "PARTIAL" if d["caught_after_write"] else "LOOPHOLE CONFIRMED")
    rows.append(("4", "hook Bash writes a stub to a tracked module", bash_verdict,
                 f"PreToolUse {d['pre_tool_use']}; PostToolUse flagged {d.get('flagged_by_post_tool_use')}; Stop "
                 f"{'block' if d.get('blocked_at_stop') else 'no block'}; node {d['node_status_after_stop_sync']}; "
                 f"stepcheck ci exit {d['stepcheck_ci_exit']}"))
    e = r["5_reexport"]
    rows.append(("5", "2-hop re-export facade dirties consumer", "PASS" if e["consumer_dirty"] else "LOOPHOLE CONFIRMED",
                 f"dirtied {e['dirtied']}; consumer {e['status_after'].get('consumer.py')}, direct {e['status_after'].get('direct.py')}, "
                 f"deps consumer->{e['deps'].get('consumer.py')}"))
    f = r["6_stale_session"]
    rows.append(("6", "stale-session rejected sync corrupts the frame", "LOOPHOLE CONFIRMED" if f["corrupted"] else "PASS",
                 f"frame {f['a_frame_after_refactor']} -> {f['a_frame_after_stale_sync']}; ci exit {f['ci_exit_after_refactor']} -> "
                 f"{f['ci_exit_after_stale_sync']}; disk unchanged {f['disk_unchanged_by_stale_sync']}"))
    return rows


def main() -> int:
    t0 = time.perf_counter()
    head, dirty = git_head()
    results: dict = {}
    for key, fn in (("1_swebench", vector_swebench), ("2_polyglot", vector_polyglot), ("3_mutations", vector_mutations),
                    ("4_hooks", vector_hooks), ("5_reexport", vector_reexport), ("6_stale_session", vector_stale_session)):
        t = time.perf_counter()
        results[key] = fn()
        results[key]["_seconds"] = round(time.perf_counter() - t, 1)
        print(f"  [{key}] done in {results[key]['_seconds']}s", flush=True)
    rows = verdicts(results)
    receipt = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "generator": ".stepcheck/discovery/audit_loopholes.py",
        "kernel_commit": head, "backend_dirty": dirty, "python": platform.python_version(), "platform": platform.platform(),
        "sources": X.SOURCES, "verdicts": [{"vector": a, "test": b, "result": c, "detail": d} for a, b, c, d in rows],
        "results": results, "runtime_s": round(time.perf_counter() - t0, 1),
    }
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(receipt, indent=1, default=str), encoding="utf-8")
    print(f"\nRED-TEAM LOOPHOLE & MULTI-BENCHMARK AUDIT — {head}{' (+uncommitted backend changes)' if dirty else ''}")
    w = max(len(b) for _a, b, _c, _d in rows)
    for a, b, c, d in rows:
        print(f"  {a:<6} {b:<{w}}  {c:<19} {d}")
    print(f"receipt: {RECEIPT}  ({receipt['runtime_s']} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
