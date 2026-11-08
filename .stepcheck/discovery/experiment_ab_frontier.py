"""4-level precision / recall frontier for the Category A / B blind spots — measurement only,
nothing under backend/ changes. Each level is a prototype check layered on the Slice 35 gates:

  L0  Slice 35 baseline: strict dry-run StateKernel.commit (Gate B/C rejection = catch).
  L1  + structural `self` row polymorphism with white-box constant partitioning: for every class
      method present in both versions, the attributes it reads from `self` (its row type) are
      given to a duck-typed SimpleNamespace — a no-op callable where the attribute is called, a
      container where it is indexed / iterated, otherwise a primitive — and the parameters and
      attributes are driven over a primitive pool plus the boundary partitions {c-1, c, c+1}
      of every literal the method compares or computes with. before(m) and after(m) run in the
      Gate C sandbox on the same inputs; a differing result on an input where before ran
      cleanly is a flag.
  L2  + Hoare `modifies` clause: the set of `self.<attr>` a method writes must not lose a member.
  L3  + collaborator effect summary: the set of outgoing call targets (`recv.method(...)`,
      `fn(...)`) a function makes as statements must not lose a member.

Every level is measured over the full fault corpus (skylos_vs_stepcheck's 239 + A 13 + B 25 +
D 20 = 297) and the full legitimate-edit corpus (47 certification gold patches + 16 Category C
equivalent rewrites + 21 SWE-bench Verified rows 0-24 + 19 rows 25-44). L1-L3 apply to Python
only (D is unaffected by them). Receipt: receipts/ab_frontier.json.
usage: experiment_ab_frontier.py [--offline] [--vectors N]
"""
from __future__ import annotations

import ast
import datetime as dt
import itertools
import json
import subprocess
import sys
import time
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RECEIPT = HERE / "receipts" / "ab_frontier.json"
sys.path.insert(0, str(HERE))
import verify_external_benchmarks as X  # noqa: E402
import audit_loopholes as A  # noqa: E402
import benchmark_vs_skylos as B  # noqa: E402
import paper_honest_evaluation as P  # noqa: E402  (its generators only; no case list is read here)

from kernel import StateKernel, _okf, _sandbox  # noqa: E402

VECTORS = int(sys.argv[sys.argv.index("--vectors") + 1]) if "--vectors" in sys.argv else 48
POOL = [0, 1, -1, 2, "", "x", None, True, False, [], {}, 0.5]


def git_head() -> tuple[str, bool]:
    head = subprocess.run(["git", "rev-parse", "--short=7", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "backend"], cwd=REPO, capture_output=True, text=True).stdout.strip())
    return head, dirty


# ------------------------------------------------------------------ corpora


def swe_pairs(offset: int, length: int) -> list[dict]:
    url = ("https://datasets-server.huggingface.co/rows?dataset=princeton-nlp%2FSWE-bench_Verified"
           f"&config=default&split=test&offset={offset}&length={length}")
    raw = X.fetch(url)
    if raw is None:
        return []
    out = []
    for r in [r["row"] for r in json.loads(raw)["rows"]]:
        files = A.split_patch(r["patch"])
        code = [p for p in files if p.endswith(".py")]
        if len(files) != 1 or len(code) != 1:
            continue
        rel = code[0]
        before_b = X.fetch(f"https://raw.githubusercontent.com/{r['repo']}/{r['base_commit']}/{rel}")
        if before_b is None:
            continue
        before = before_b.decode("utf-8")
        after = A.apply_hunks(before, files[rel]["hunks"])
        if after is None or not X.parses(before) or not X.parses(after):
            continue
        tests = {}
        for trel, spec in A.split_patch(r["test_patch"]).items():
            if not trel.endswith(".py"):
                continue
            tb = b"" if spec["new_file"] else X.fetch(f"https://raw.githubusercontent.com/{r['repo']}/{r['base_commit']}/{trel}")
            if tb is None:
                continue
            ta = A.apply_hunks(tb.decode("utf-8"), spec["hunks"])
            if ta is not None and X.parses(ta):
                tests[trel] = (tb.decode("utf-8"), ta)
        root = X.make_project({rel: before, **{t: tb for t, (tb, _ta) in tests.items() if tb}})
        for t, (_tb, ta) in tests.items():
            (root / t).parent.mkdir(parents=True, exist_ok=True)
            (root / t).write_text(ta, encoding="utf-8", newline="\n")
        out.append({"label": f"SWE-bench/{r['instance_id']}", "root": root, "rel": rel, "before": before, "after": after})
    return out


def legit_corpus() -> list[dict]:
    cases: list[dict] = []
    raw = X.fetch(X.CANITEDIT)
    for r in [r["row"] for r in json.loads(raw)["rows"]]:
        if not (X.parses(r["before"]) and X.parses(r["after"])):
            continue
        name = __import__("re").sub(r"\W", "_", r["name"]) or "task"
        name = name if name[0].isalpha() else f"t_{name}"
        rel = f"{name}.py"
        cases.append({"group": "gold certification (47)", "label": f"CanItEdit/{r['full_name']}", "root": X.make_project({rel: r["before"]}),
                      "rel": rel, "before": r["before"], "after": r["after"]})
    for key, (repo, old, new, pkg, modules) in X.PACKAGES.items():
        old_files = {k_: v for k_, v in X.package_files(repo, old, pkg, modules).items() if X.parses(v)}
        new_files = {k_: v for k_, v in X.package_files(repo, new, pkg, modules).items() if X.parses(v)}
        root = X.make_project(old_files, pkg)
        for rel, src in new_files.items():
            if rel in old_files and old_files[rel] != src:
                cases.append({"group": "gold certification (47)", "label": f"{repo}@{old}->{new}:{rel}", "root": root,
                              "rel": f"{pkg}/{rel}", "before": old_files[rel], "after": src})
    for c in swe_pairs(0, 25):
        cases.append({"group": "SWE-bench 0-24 (21)", **c})
    for c in swe_pairs(25, 20):
        cases.append({"group": "SWE-bench 25-44 (19)", **c})
    return cases


def honest_corpus(k: StateKernel) -> list[dict]:
    """A, B, C, D exactly as paper_honest_evaluation builds them (its generators, same caps)."""
    cases: list[dict] = []
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
            for cat, found in (("A", P.category_a(src, 6)), ("B", P.category_b(src, 3)),
                               ("C", P.category_c(src, node["invariants_auto_mined"], 6))):
                for fn, desc, after in found:
                    pools[cat].setdefault(key, []).append({"category": cat, "label": f"{repo}@{new}", "root": root,
                                                           "rel": f"{pkg}/{rel}", "function": fn, "description": desc,
                                                           "before": src, "after": after})
    for cat in "ABC":
        queues = [list(v) for v in pools[cat].values()]
        picked: list[dict] = []
        while len(picked) < P.CAP[cat] and any(queues):
            for q in queues:
                if q and len(picked) < P.CAP[cat]:
                    picked.append(q.pop(0))
        cases += picked
    tree_raw = X.fetch(A.POLY_TREE)
    if tree_raw is not None:
        import re
        paths = [t["path"] for t in json.loads(tree_raw)["tree"]]
        per_lang = P.CAP["D"] // 4
        for lang in ("javascript", "go", "rust", "java"):
            if lang == "java":
                cands = [p for p in paths if re.match(rf"{lang}/exercises/practice/[^/]+/\.meta/src/reference/java/[^/]+\.java$", p)]
            elif lang == "javascript":
                cands = [p for p in paths if re.match(rf"{lang}/exercises/practice/[^/]+/\.meta/proof\.ci\.js$", p)]
            else:
                cands = [p for p in paths if re.match(rf"{lang}/exercises/practice/[^/]+/\.meta/example\.{A.EXT[lang][1:]}$", p)]
            project: dict[str, str] = {}
            for p in cands[: A.PER_LANGUAGE * 8]:
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
                if rel not in nodes or got >= per_lang:
                    continue
                for fn, desc, after in P.category_d(lang, rel, src, _okf.lang_module(rel), per_lang - got):
                    cases.append({"category": "D", "label": f"Aider polyglot/{lang}", "root": root, "rel": rel, "function": fn,
                                  "description": desc, "before": src, "after": after})
                    got += 1
    return cases


# ------------------------------------------------------------------ L0


def level0(k: StateKernel, cases: list[dict]) -> None:
    sessions: dict[Path, str] = {}
    for c in cases:
        sid = sessions.get(c["root"]) or sessions.setdefault(c["root"], k.init_session(c["root"]))
        node = X.node_ids(k, sid).get(c["rel"])
        if node is None:
            c["L0"] = {"flag": False, "note": "untracked"}
            continue
        base = k.commit(sid, node["node_id"], source=c["before"], dry_run=True)
        if not base.accepted:
            c["L0"] = {"flag": False, "note": f"baseline rejected: {X.classify(base)}"}
            continue
        v = k.commit(sid, node["node_id"], source=c["after"], dry_run=True)
        env = (not v.accepted) and X.classify(v).startswith("environment")
        c["L0"] = {"flag": (not v.accepted) and v.gate in ("B", "C") and not env, "gate": v.gate,
                   "error": str(v.error)[:160] if v.error else None, "environment": env}
        c["node_id"], c["sid"] = node["node_id"], sid


# ------------------------------------------------------------------ L2 / L3 structure


def _methods(tree: ast.Module) -> dict[str, tuple[ast.ClassDef, ast.FunctionDef]]:
    out = {}
    for cls in tree.body:
        if isinstance(cls, ast.ClassDef):
            for m in cls.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out[f"{cls.name}.{m.name}"] = (cls, m)
    return out


def _functions(tree: ast.Module) -> dict[str, ast.AST]:
    out: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[node.name] = node
    for name, (_cls, m) in _methods(tree).items():
        out[name] = m
    return out


def _self_name(fn) -> str | None:
    args = fn.args.posonlyargs + fn.args.args
    return args[0].arg if args else None


def write_set(fn) -> set[str]:
    me = _self_name(fn)
    out = set()
    for n in ast.walk(fn):
        targets = []
        if isinstance(n, ast.Assign):
            targets = n.targets
        elif isinstance(n, (ast.AugAssign, ast.AnnAssign)):
            targets = [n.target]
        for t in targets:
            for sub in ast.walk(t):
                if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == me:
                    out.add(sub.attr)
    return out


def call_set(fn) -> set[str]:
    out = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call):
            out.add(ast.unparse(n.value.func))
        elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Await) and isinstance(n.value.value, ast.Call):
            out.add(ast.unparse(n.value.value.func))
    return out


def level2(before: str, after: str) -> list[str]:
    tb, ta = ast.parse(before), ast.parse(after)
    mb, ma = _methods(tb), _methods(ta)
    flags = []
    for name in mb.keys() & ma.keys():
        lost = write_set(mb[name][1]) - write_set(ma[name][1])
        if lost:
            flags.append(f"{name} no longer writes self.{sorted(lost)[0]}")
    return flags


def level3(before: str, after: str) -> list[str]:
    tb, ta = ast.parse(before), ast.parse(after)
    fb, fa = _functions(tb), _functions(ta)
    flags = []
    for name in fb.keys() & fa.keys():
        lost = call_set(fb[name]) - call_set(fa[name])
        if lost:
            flags.append(f"{name} no longer calls {sorted(lost)[0]}(...)")
    return flags


# ------------------------------------------------------------------ L1 differential probing


class _Duck:
    """An attribute that is called, indexed or iterated: answers everything, stays itself."""

    def __call__(self, *a, **k):
        return self

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return self

    def __getitem__(self, k):
        return self

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0

    def __bool__(self):
        return False

    def __eq__(self, other):
        return isinstance(other, _Duck)

    def __hash__(self):
        return 0

    def __repr__(self):
        return "Duck"


def row_type(fn) -> dict[str, str]:
    """self.attr -> how it is used: 'call', 'container' or 'value' (reads only)."""
    me = _self_name(fn)
    uses: dict[str, str] = {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == me:
            uses[n.func.attr] = "call"
        elif isinstance(n, (ast.Subscript,)) and isinstance(n.value, ast.Attribute) and isinstance(n.value.value, ast.Name) and n.value.value.id == me:
            uses.setdefault(n.value.attr, "container")
        elif isinstance(n, (ast.For, ast.comprehension)) and isinstance(n.iter, ast.Attribute) and isinstance(n.iter.value, ast.Name) and n.iter.value.id == me:
            uses.setdefault(n.iter.attr, "container")
        elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == me and isinstance(n.ctx, ast.Load):
            uses.setdefault(n.attr, "value")
    return uses


def constants(fn) -> list:
    out = []
    for n in ast.walk(fn):
        if isinstance(n, (ast.Compare, ast.BinOp)):
            for sub in ast.walk(n):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, (int, float, str)) and not isinstance(sub.value, bool):
                    out.append(sub.value)
    return out


def partitions(fn) -> list:
    pool = list(POOL)
    for c in constants(fn):
        if isinstance(c, (int, float)):
            pool += [c - 1, c, c + 1]
        elif isinstance(c, str):
            pool += [c, ""]
    seen, out = set(), []
    for v in pool:
        key = (type(v).__name__, repr(v))
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


def _vectors(fn, attrs: dict[str, str], pool: list) -> list[tuple[dict, list]]:
    params = [a.arg for a in (fn.args.posonlyargs + fn.args.args)[1:]]
    slots = [a for a, kind in attrs.items() if kind == "value"] + params
    if len(slots) > 6:
        slots = slots[:6]
    combos = itertools.product(pool, repeat=len(slots)) if slots else iter([()])
    out = []
    for i, combo in enumerate(combos):
        if i >= VECTORS * 7:
            break
        if i % 7:  # deterministic stride through the product space
            continue
        state = {}
        for a, kind in attrs.items():
            if kind == "call":
                state[a] = _Duck()
            elif kind == "container":
                state[a] = _Duck()
        for s, v in zip(slots, combo):
            if s in attrs:
                state[s] = v
        args = [combo[slots.index(p)] if p in slots else _Duck() for p in params]
        out.append((state, args))
        if len(out) >= VECTORS:
            break
    return out


def _run(cls, method: str, state: dict, args: list):
    try:
        me = types.SimpleNamespace(**state)
        fn = getattr(cls, method)
        value = _sandbox.guarded(lambda: fn(me, *args))
        return ("ok", repr(value)[:120], sorted((k_, repr(v)[:60]) for k_, v in vars(me).items() if not isinstance(v, _Duck)))
    except BaseException as exc:  # noqa: BLE001 — any exception is an observation
        return ("exc", type(exc).__name__, None)


def level1(node_id: str, before: str, after: str, project_sources: dict, project_paths: dict, cache: dict) -> tuple[list[str], str | None]:
    """Flags, or (no flags, note) when the module cannot be loaded here."""
    try:
        tb, ta = ast.parse(before), ast.parse(after)
    except SyntaxError:
        return [], "syntax"
    mb, ma = _methods(tb), _methods(ta)
    shared = [n for n in mb if n in ma and ast.dump(mb[n][1]) != ast.dump(ma[n][1])]  # only methods the edit touched
    if not shared:
        return [], None

    def load(src: str):
        key = (node_id, hash(src))
        if key not in cache:
            try:
                cache[key] = _sandbox.guarded(lambda: _sandbox.load_namespace(node_id, src, project_sources, project_paths),
                                              steps=None, seconds=_sandbox.IMPORT_WALL_BUDGET_SECONDS)
            except Exception as exc:  # noqa: BLE001
                cache[key] = exc
        return cache[key]

    nb, na = load(before), load(after)
    if isinstance(nb, Exception) or isinstance(na, Exception):
        return [], f"environment: {type(nb if isinstance(nb, Exception) else na).__name__}"
    flags = []
    for name in shared:
        cls_name, meth = name.split(".", 1)
        cb, ca = nb.get(cls_name), na.get(cls_name)
        if cb is None or ca is None or not hasattr(cb, meth) or not hasattr(ca, meth):
            continue
        fn_b = mb[name][1]
        attrs = row_type(fn_b)
        pool = partitions(fn_b)
        for state, args in _vectors(fn_b, attrs, pool):
            rb = _run(cb, meth, dict(state), list(args))
            if rb[0] != "ok":
                continue
            ra = _run(ca, meth, dict(state), list(args))
            if ra != rb:
                flags.append(f"{name}: before {rb[0]} {rb[1]} / after {ra[0]} {ra[1]} on {[(k_, repr(v)[:20]) for k_, v in state.items() if not isinstance(v, _Duck)][:3]} {[repr(a)[:20] for a in args][:3]}")
                break
    return flags, None


# ------------------------------------------------------------------ main


def main() -> int:
    t0 = time.perf_counter()
    head, dirty = git_head()
    k = StateKernel(ephemeral=True)
    core, _meta = B.build_cases()
    faults = [{"group": "core 239", "kind": c["kind"], "category": c["category"], **{k_: c[k_] for k_ in ("label", "root", "rel", "before", "after")}}
              for c in core]
    honest = honest_corpus(k)
    for c in honest:
        c["group"] = f"Category {c['category']}"
    faults += [c for c in honest if c["category"] in "ABD"]
    legit = [c for c in honest if c["category"] == "C"]
    for c in legit:
        c["group"] = "Category C (16)"
    legit += legit_corpus()
    legit_groups = ", ".join(f"{g}: {sum(c['group'] == g for c in legit)}" for g in dict.fromkeys(c["group"] for c in legit))
    print(f"faults {len(faults)} (core {sum(c['group'] == 'core 239' for c in faults)}, A {sum(c.get('category') == 'A' for c in faults)}, "
          f"B {sum(c.get('category') == 'B' for c in faults)}, D {sum(c.get('category') == 'D' for c in faults)}); "
          f"legit {len(legit)} ({legit_groups})", flush=True)

    allc = faults + legit
    level0(k, allc)
    print("  L0 done", flush=True)
    sessions: dict[Path, str] = {}
    cache: dict = {}
    for i, c in enumerate(allc):
        python = c["rel"].endswith(".py")
        c["L2"] = level2(c["before"], c["after"]) if python else []
        c["L3"] = level3(c["before"], c["after"]) if python else []
        if python and "sid" in c:
            s = k._session(c["sid"])
            srcs = {nid: n.info.source for nid, n in s.nodes.items() if nid != c["node_id"]}
            paths = {nid: n.info.path for nid, n in s.nodes.items()}
            c["L1"], c["L1_note"] = level1(c["node_id"], c["before"], c["after"], srcs, paths, cache)
        else:
            c["L1"], c["L1_note"] = [], None
        if (i + 1) % 50 == 0:
            print(f"  L1-L3 {i + 1}/{len(allc)} ({time.perf_counter() - t0:.0f}s)", flush=True)

    def flagged(c: dict, level: int) -> bool:
        return bool(c["L0"]["flag"] or (level >= 1 and c["L1"]) or (level >= 2 and c["L2"]) or (level >= 3 and c["L3"]))

    groups_f = {"Cat A (13)": lambda c: c.get("category") == "A", "Cat B (25)": lambda c: c.get("category") == "B",
                "Cat D (20)": lambda c: c.get("category") == "D", "core 239": lambda c: c["group"] == "core 239"}
    groups_l = {"Cat C FPR (16)": "Category C (16)", "Gold Cert Pass (47)": "gold certification (47)",
                "SWE 0-24 Pass (21)": "SWE-bench 0-24 (21)", "SWE 25-44 Pass (19)": "SWE-bench 25-44 (19)"}
    table = []
    for level in range(4):
        row = {"level": f"L{level}"}
        for name, pred in groups_f.items():
            rows = [c for c in faults if pred(c)]
            row[name] = (sum(flagged(c, level) for c in rows), len(rows))
        tp = sum(flagged(c, level) for c in faults)
        row["Total Recall (297)"] = (tp, len(faults))
        fp = 0
        for name, grp in groups_l.items():
            rows = [c for c in legit if c["group"] == grp]
            bad = sum(flagged(c, level) for c in rows)
            fp += bad
            row[name] = (len(rows) - bad, len(rows)) if "Pass" in name else (bad, len(rows))
        row["fp_total"] = (fp, len(legit))
        row["Overall Precision"] = round(100 * tp / (tp + fp), 1) if tp + fp else None
        table.append(row)

    env_notes = sum(1 for c in allc if c.get("L1_note", "") and str(c["L1_note"]).startswith("environment"))
    receipt = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "generator": ".stepcheck/discovery/experiment_ab_frontier.py",
               "kernel_commit": head, "backend_dirty": dirty, "vectors_per_method": VECTORS, "table": table,
               "l1_environment_skips": env_notes,
               "cases": [{k_: v for k_, v in c.items() if k_ not in ("before", "after", "root", "sid")} | {"root": str(c["root"])} for c in allc],
               "sources": X.SOURCES, "runtime_s": round(time.perf_counter() - t0, 1)}
    RECEIPT.write_text(json.dumps(receipt, indent=1, default=str), encoding="utf-8")

    def cell(v):
        return f"{v[0]}/{v[1]}" if isinstance(v, tuple) else str(v)

    cols = ["Cat A (13)", "Cat B (25)", "Cat C FPR (16)", "Cat D (20)", "Total Recall (297)", "Gold Cert Pass (47)",
            "SWE 0-24 Pass (21)", "SWE 25-44 Pass (19)", "Overall Precision"]
    print(f"\nA/B PRECISION-RECALL FRONTIER — kernel {head}{' (+dirty)' if dirty else ''}; L1 environment skips {env_notes}")
    print("| Level | " + " | ".join(cols) + " |")
    print("| --- | " + " | ".join("---:" for _ in cols) + " |")
    for row in table:
        print(f"| {row['level']} | " + " | ".join(cell(row[c]) + ("%" if c == "Overall Precision" and row[c] is not None else "") for c in cols) + " |")
    for level in (1, 2, 3):
        key = f"L{level}"
        fps = [c for c in legit if c[key] and not c["L0"]["flag"]]
        print(f"\n{key} false positives on legitimate edits ({len(fps)}):")
        for c in fps[:10]:
            print(f"  {c['label']}: {c[key][0][:140]}")
    print(f"receipt: {RECEIPT}  ({receipt['runtime_s']} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
