"""Kill criterion #1 — Skylos vs StepCheck on untested edits.

The same external fault corpus the certification harness uses (CanItEdit guard drops, the
psf/requests + pallets/flask "wild" guard drops and body-stub wipes) plus the red-team audit's
subtle AST mutation operators (decorator / `@overload` strip, relational flips in guards and
asserts, guard-action neutering, `False and` short-circuits, exception widening / swallowing),
each judged twice with NO covering unit test:

  Skylos     `skylos <project> -a --ai-defects --json --no-upload --no-grep-verify` on the project
             before and after the fault; CAUGHT when the after-scan carries a finding in the
             mutated file that the before-scan did not (any section: dead code, quality, AI
             defects, security, secrets; abstentions and "uncertain" dead-code rows count too,
             so the comparison is generous to Skylos). `--no-grep-verify` because Skylos's grep
             verification does not complete on this machine and would turn every dead-code row
             into an abstention; the rows are still counted as catches.
  StepCheck  `StateKernel.commit(source=<after>, dry_run=True)` in a session opened on the
             project; CAUGHT when Gate B or Gate C rejects the staged source (no declaration).
             A Gate A rejection, or an accepted commit, is NOT a catch.

Receipt: receipts/skylos_vs_stepcheck.json (header: kernel commit, skylos version, flags).
usage: benchmark_vs_skylos.py [--offline] [--workers N] [--limit N]
"""
from __future__ import annotations

import ast
import datetime as dt
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
RECEIPT = HERE / "receipts" / "skylos_vs_stepcheck.json"
HOME = Path(tempfile.mkdtemp(prefix="sc-skylos-home-"))
os.environ["STEPCHECK_HOME"] = str(HOME)
os.environ["STEPCHECK_HOOK_AUTOSTART"] = "0"

sys.path.insert(0, str(HERE))
import verify_external_benchmarks as X  # noqa: E402  (adds backend/ to sys.path, imports kernel)
import audit_loopholes as A  # noqa: E402  (the mutation operators)

from kernel import StateKernel  # noqa: E402

SKYLOS = Path(sys.executable).with_name("skylos.exe" if os.name == "nt" else "skylos")
SKYLOS_FLAGS = ["-a", "--ai-defects", "--json", "--no-upload", "--no-grep-verify"]
SKIP_SECTIONS = {"definitions", "dead_code_evidence", "analysis_summary", "workspaces", "architecture_metrics",
                 "assessment", "provenance", "whitelisted", "suppressed", "analysis_errors"}


def _opt(flag: str, default: int) -> int:
    if flag in sys.argv:
        return int(sys.argv[sys.argv.index(flag) + 1])
    return default


WORKERS = _opt("--workers", 3)
LIMIT = _opt("--limit", 0)


def git_head() -> tuple[str, bool]:
    head = subprocess.run(["git", "rev-parse", "--short=7", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "backend"], cwd=REPO, capture_output=True, text=True).stdout.strip())
    return head, dirty


def skylos_version() -> str:
    p = subprocess.run([str(SKYLOS), "--version"], capture_output=True, text=True, env={**os.environ, "PYTHONUTF8": "1"})
    text = (p.stdout + p.stderr).strip()
    return text.splitlines()[0].replace("skylos ", "").strip() if text else "unknown"


# ------------------------------------------------------------------ Skylos


def skylos_scan(root: Path) -> tuple[list[dict], float, str | None]:
    """Every finding Skylos reports for the project: [{section, rule_id, name, file, line}]."""
    t0 = time.perf_counter()
    p = subprocess.run([str(SKYLOS), str(root), *SKYLOS_FLAGS], capture_output=True, text=True,
                       env={**os.environ, "PYTHONUTF8": "1"}, timeout=900)
    seconds = time.perf_counter() - t0
    out = p.stdout
    if "{" not in out:
        return [], seconds, f"no JSON (rc {p.returncode}): {(p.stderr or out)[-200:]}"
    try:
        data = json.loads(out[out.index("{"):])
    except ValueError as exc:
        return [], seconds, f"bad JSON: {exc}"
    finds = []
    base = str(root.resolve()).replace("\\", "/").rstrip("/") + "/"
    for section, items in data.items():
        if section in SKIP_SECTIONS or not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            file = str(it.get("file") or "").replace("\\", "/")
            if file.lower().startswith(base.lower()):
                file = file[len(base):]  # root-relative: the after-scan runs in a copy of the project
            finds.append({"section": section, "rule_id": it.get("rule_id"),
                          "name": it.get("name") or it.get("simple_name") or it.get("full_name") or (it.get("message") or "")[:80],
                          "file": file, "line": it.get("line")})
    return finds, seconds, None


def _key(f: dict) -> tuple:
    # root-relative file; line-insensitive (a dropped guard shifts every line below it)
    return (f["section"], f["rule_id"], f["name"], f["file"])


def new_findings(before: list[dict], after: list[dict], rel: str) -> list[dict]:
    seen = {_key(f) for f in before}
    return [f for f in after if _key(f) not in seen and f["file"].endswith(rel)]


# ------------------------------------------------------------------ corpus


def build_cases() -> tuple[list[dict], dict]:
    """Every (project, module, fault) the certification harness and the audit judge."""
    raw = X.fetch(X.CANITEDIT)
    if raw is None:
        sys.exit("could not fetch CanItEdit rows (run once without --offline)")
    rows = [r["row"] for r in json.loads(raw)["rows"]]
    cases: list[dict] = []
    meta = {"canitedit_rows": len(rows), "packages": {}}
    for r in rows:
        if not (X.parses(r["before"]) and X.parses(r["after"])):
            continue
        name = __import__("re").sub(r"\W", "_", r["name"]) or "task"
        name = name if name[0].isalpha() else f"t_{name}"
        rel, src = f"{name}.py", r["before"]
        root = X.make_project({rel: src})
        label = f"CanItEdit/{r['full_name']}"
        for kind, fault in [("stub_unfocused_body", X.stub_fault(src))] + X.guard_faults(src):
            if fault is None:
                continue
            target, staged = fault
            category = "stub wipe (CanItEdit)" if kind == "stub_unfocused_body" else "guard drop (CanItEdit)"
            cases.append({"category": category, "kind": kind, "label": label, "root": root, "rel": rel, "target": target,
                          "before": src, "after": staged})
    for key, (repo, _old, new, pkg, modules) in X.PACKAGES.items():
        files = {rel: s for rel, s in X.package_files(repo, new, pkg, modules).items() if X.parses(s)}
        meta["packages"][key] = {"repo": repo, "tag": new, "modules": len(files)}
        root = X.make_project(files, pkg)
        for rel, src in files.items():
            prel = f"{pkg}/{rel}"
            label = f"{repo}@{new}"
            for kind, fault in [("stub_unfocused_body", X.stub_fault(src))] + X.guard_faults(src):
                if fault is None:
                    continue
                target, staged = fault
                category = "stub wipe (requests/flask)" if kind == "stub_unfocused_body" else "wild guard drop (requests/flask)"
                cases.append({"category": category, "kind": kind, "label": label, "root": root, "rel": prel, "target": target,
                              "before": src, "after": staged})
            for op, fn, desc, new_src in A.mutants(src):
                cases.append({"category": f"subtle mutation: {op[2:]}", "kind": op, "label": label, "root": root, "rel": prel,
                              "target": fn, "description": desc, "before": src, "after": new_src})
    if LIMIT:
        cases = cases[:LIMIT]
    return cases, meta


# ------------------------------------------------------------------ StepCheck


def stepcheck_verdicts(cases: list[dict]) -> None:
    k = StateKernel(ephemeral=True)
    sessions: dict[Path, str] = {}
    for c in cases:
        sid = sessions.get(c["root"]) or sessions.setdefault(c["root"], k.init_session(c["root"]))
        node = X.node_ids(k, sid).get(c["rel"])
        if node is None:
            c["stepcheck"] = {"caught": False, "gate": None, "note": "untracked"}
            continue
        base = k.commit(sid, node["node_id"], source=c["before"], dry_run=True)
        if not base.accepted:
            c["stepcheck"] = {"caught": False, "gate": None, "note": f"baseline rejected: {X.classify(base)}"}
            continue
        t0 = time.perf_counter()
        v = k.commit(sid, node["node_id"], source=c["after"], dry_run=True)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        env = (not v.accepted) and X.classify(v).startswith("environment")
        c["stepcheck"] = {"caught": (not v.accepted) and v.gate in ("B", "C") and not env, "gate": v.gate,
                          "subtype": getattr(v.error, "subtype", None), "environment": env,
                          "error": str(v.error)[:160] if v.error else None, "ms": ms}


# ------------------------------------------------------------------ main


def main() -> int:
    t_start = time.perf_counter()
    head, dirty = git_head()
    version = skylos_version()
    cases, meta = build_cases()
    print(f"corpus: {len(cases)} cases; skylos {version}; kernel {head}{' (dirty)' if dirty else ''}", flush=True)

    t = time.perf_counter()
    stepcheck_verdicts(cases)
    print(f"  stepcheck verdicts in {time.perf_counter() - t:.0f}s", flush=True)

    roots = sorted({c["root"] for c in cases}, key=str)
    before: dict[Path, list[dict]] = {}
    t = time.perf_counter()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for root, (finds, _s, err) in zip(roots, pool.map(skylos_scan, roots)):
            before[root] = finds
            if err:
                print(f"  skylos before-scan error on {root}: {err}", flush=True)
    print(f"  {len(roots)} before-scans in {time.perf_counter() - t:.0f}s", flush=True)

    def after_scan(c: dict) -> dict:
        copy = Path(tempfile.mkdtemp(prefix="sc-skylos-after-"))
        shutil.copytree(c["root"], copy, dirs_exist_ok=True)
        (copy / c["rel"]).write_text(c["after"], encoding="utf-8", newline="\n")
        finds, seconds, err = skylos_scan(copy)
        shutil.rmtree(copy, ignore_errors=True)
        new = new_findings(before[c["root"]], finds, c["rel"])
        return {"caught": bool(new), "new_findings": [{k_: f[k_] for k_ in ("section", "rule_id", "name", "line")} for f in new][:6],
                "seconds": round(seconds, 1), "error": err}

    t = time.perf_counter()
    done = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for c, res in zip(cases, pool.map(after_scan, cases)):
            c["skylos"] = res
            done += 1
            if done % 25 == 0:
                print(f"  skylos after-scans {done}/{len(cases)} ({time.perf_counter() - t:.0f}s)", flush=True)
    print(f"  {len(cases)} after-scans in {time.perf_counter() - t:.0f}s", flush=True)

    order = ["guard drop (CanItEdit)", "wild guard drop (requests/flask)", "stub wipe (CanItEdit)", "stub wipe (requests/flask)"]
    order += sorted({c["category"] for c in cases if c["category"].startswith("subtle")})
    table = []
    for cat in order:
        rows = [c for c in cases if c["category"] == cat]
        if not rows:
            continue
        sky = sum(c["skylos"]["caught"] for c in rows)
        sc = sum(c["stepcheck"]["caught"] for c in rows)
        rules: dict[str, int] = {}
        for c in rows:
            for f in c["skylos"]["new_findings"]:
                rid = f["rule_id"] or f["section"]
                rules[rid] = rules.get(rid, 0) + 1
        gates: dict[str, int] = {}
        for c in rows:
            if c["stepcheck"]["caught"]:
                g = f"Gate {c['stepcheck']['gate']} {c['stepcheck'].get('subtype') or ''}".strip()
                gates[g] = gates.get(g, 0) + 1
        table.append({"category": cat, "cases": len(rows), "skylos_caught": sky, "stepcheck_caught": sc,
                      "skylos_rules": dict(sorted(rules.items(), key=lambda kv: -kv[1])), "stepcheck_gates": gates,
                      "stepcheck_environment": sum(bool(c["stepcheck"].get("environment")) for c in rows),
                      "stepcheck_baseline_skipped": sum("note" in c["stepcheck"] for c in rows)})
    subtle = [r for r in table if r["category"].startswith("subtle")]
    if subtle:
        table.append({"category": "subtle AST mutations (subtotal)", "cases": sum(r["cases"] for r in subtle),
                      "skylos_caught": sum(r["skylos_caught"] for r in subtle), "stepcheck_caught": sum(r["stepcheck_caught"] for r in subtle)})
    table.append({"category": "ALL", "cases": len(cases), "skylos_caught": sum(c["skylos"]["caught"] for c in cases),
                  "stepcheck_caught": sum(c["stepcheck"]["caught"] for c in cases)})

    receipt = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "generator": ".stepcheck/discovery/benchmark_vs_skylos.py",
        "kernel_commit": head, "backend_dirty": dirty, "python": platform.python_version(), "platform": platform.platform(),
        "skylos": {"version": version, "flags": SKYLOS_FLAGS, "catch_rule": "any new finding in the mutated file vs the before-scan "
                   "(line-insensitive key: section, rule, name); abstentions count"},
        "stepcheck": {"catch_rule": "StateKernel.commit(source=after, dry_run=True) rejected at Gate B or C, no allow_deletion"},
        "corpus": meta, "sources": X.SOURCES, "table": table,
        "cases": [{k_: v for k_, v in c.items() if k_ not in ("before", "after", "root")} | {"root": str(c["root"])} for c in cases],
        "runtime_s": round(time.perf_counter() - t_start, 1),
    }
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(receipt, indent=1, default=str), encoding="utf-8")

    print(f"\nSKYLOS {version} vs STEPCHECK ({head}{' +dirty backend' if dirty else ''}) ON UNTESTED EDITS")
    print("| Fault Category (No Covering Test) | Total Cases | Caught by Skylos 4.50.1 (`-a --ai-defects`) | Caught by StepCheck (Gate B/C) |")
    print("| --- | ---: | ---: | ---: |")
    for r in table:
        n = r["cases"]
        print(f"| {r['category']} | {n} | {r['skylos_caught']} ({100 * r['skylos_caught'] / n:.1f}%) | "
              f"{r['stepcheck_caught']} ({100 * r['stepcheck_caught'] / n:.1f}%) |")
    print(f"receipt: {RECEIPT}  ({receipt['runtime_s']} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
