"""Enterprise-scale stress benchmark for the StateKernel — measurement only.

1. Monolithic files: the largest Python modules in the cached SWE-ABS / BugsInPy / SWE-bench
   corpus (external_cache/), each as a single-file project: init_session, a focused checkout,
   and the commit latency of editing one function (dry-run through Gates A/B/C, and one landed
   commit), p50 / p95 / max and the share under 25 / 50 ms.
2. Whole repository: a shallow django/django clone (_cache/django): cold init_session wall
   clock and peak working set, the in-process PreToolUse Edit hook on one file inside it, and
   `stepcheck ci` cold vs warm.
3. Noise and generated code: what the indexer tracks in a tree with Django migrations, protobuf
   `_pb2.py`, `index.d.ts`, `bundle.min.js`, vendored / build output and .gitignored artifacts.
4. Resilience: UTF-8 BOM, deep nesting, circular imports, `from . import *`.

usage: benchmark_enterprise_scale.py [--label slice35] [--out receipts/enterprise_scale.<label>.json]
                                     [--files 15] [--edits 5] [--skip-repo]
"""
from __future__ import annotations

import ast
import ctypes
import datetime as dt
import io
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
CACHE = HERE / "_cache"
EXT = HERE / "external_cache"
HOME = Path(tempfile.mkdtemp(prefix="sc-scale-home-"))
os.environ["STEPCHECK_HOME"] = str(HOME)
os.environ["STEPCHECK_HOOK_AUTOSTART"] = "0"
sys.path.insert(0, str(BACKEND))

from kernel import StateKernel, _okf  # noqa: E402
import hooks  # noqa: E402
import cli  # noqa: E402


def _opt(flag, default):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default


LABEL = _opt("--label", "slice35")
OUT = Path(_opt("--out", str(HERE / "receipts" / f"enterprise_scale.{LABEL}.json")))
N_FILES = int(_opt("--files", 15))
N_EDITS = int(_opt("--edits", 5))
SKIP_REPO = "--skip-repo" in sys.argv
SKIP_MONOLITHS = "--skip-monoliths" in sys.argv
REPO_DIR = Path(_opt("--repo", str(CACHE / "django")))


def git_head() -> tuple[str, bool]:
    head = subprocess.run(["git", "rev-parse", "--short=7", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "backend"], cwd=REPO, capture_output=True, text=True).stdout.strip())
    return head, dirty


def peak_rss_mb() -> float | None:
    """Peak working set of this process (Windows), else None."""
    if os.name != "nt":
        return None

    class PMC(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong), ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

    pmc = PMC()
    pmc.cb = ctypes.sizeof(PMC)
    h = ctypes.windll.kernel32.GetCurrentProcess()
    if ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
        return round(pmc.PeakWorkingSetSize / 1e6, 1)
    return None


def rss_mb() -> float | None:
    if os.name != "nt":
        return None

    class PMC(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong), ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t), ("a", ctypes.c_size_t), ("b", ctypes.c_size_t), ("c", ctypes.c_size_t),
                    ("d", ctypes.c_size_t), ("e", ctypes.c_size_t), ("f", ctypes.c_size_t)]

    pmc = PMC()
    pmc.cb = ctypes.sizeof(PMC)
    if ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
        return round(pmc.WorkingSetSize / 1e6, 1)
    return None


def pct(values, q):
    s = sorted(values)
    return round(s[round(q * (len(s) - 1))], 1) if s else None


def stats(ms: list[float]) -> dict:
    return {"n": len(ms), "p50": pct(ms, 0.5), "p95": pct(ms, 0.95), "max": round(max(ms), 1) if ms else None,
            "under_25ms_pct": round(100 * sum(m < 25 for m in ms) / len(ms), 1) if ms else None,
            "under_50ms_pct": round(100 * sum(m < 50 for m in ms) / len(ms), 1) if ms else None}


def make_project(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="sc-scale-"))
    for rel, src in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(src, encoding="utf-8", newline="\n")
    return root


# ------------------------------------------------------------------ 1. monoliths


def largest_cached_modules(n: int) -> list[tuple[str, str, int, int]]:
    """(label, source, loc, functions) for the n largest distinct Python sources in external_cache/."""
    seen: set[str] = set()
    out = []
    for p in EXT.iterdir():
        try:
            text = p.read_bytes().decode("utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if text.lstrip().startswith(("{", "[", "<")) or len(text) < 50_000:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            continue
        key = text[:400] + text[-400:]
        if key in seen:
            continue
        seen.add(key)
        fns = sum(isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) for x in ast.walk(tree))
        hint = re.search(r'^"""(.{0,60})', text, re.S)
        label = (hint.group(1).strip().splitlines()[0][:50] if hint else p.name[:12]).replace("|", "/")
        out.append((f"{p.name[:10]} {label}", text, text.count("\n") + 1, fns))
    out.sort(key=lambda r: -r[2])
    return out[:n]


def edit_one_function(src: str, idx: int) -> tuple[str, str] | None:
    """A benign edit inside the idx-th top-level function or method: a no-op statement after
    the docstring. (name, new source) or None."""
    tree = ast.parse(src)
    fns = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fns.append((node.name, node))
        elif isinstance(node, ast.ClassDef):
            fns += [(f"{node.name}.{m.name}", m) for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if not fns:
        return None
    name, fn = fns[(idx * max(1, len(fns) // max(1, N_EDITS))) % len(fns)]
    body = fn.body
    first = body[1] if (len(body) > 1 and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant)) else body[0]
    lines = src.splitlines(keepends=True)
    indent = re.match(r"\s*", lines[first.lineno - 1]).group(0)
    new = "".join(lines[: first.lineno - 1]) + f"{indent}_stepcheck_probe = 0\n" + "".join(lines[first.lineno - 1:])
    try:
        ast.parse(new)
    except SyntaxError:
        return None
    return name, new


def stress_monoliths() -> dict:
    rows = []
    all_dry, all_real = [], []
    for label, src, loc, fns in largest_cached_modules(N_FILES):
        rel = "mod.py"
        root = make_project({rel: src})
        k = StateKernel()
        t0 = time.perf_counter()
        sid = k.init_session(root)
        init_ms = (time.perf_counter() - t0) * 1000
        nid = next(n["node_id"] for n in k.graph(sid)["nodes"] if n["path"].replace("\\", "/") == rel)
        edits = [e for e in (edit_one_function(src, i) for i in range(N_EDITS)) if e]
        t0 = time.perf_counter()
        payload = k.checkout(sid, nid, focus=[edits[0][0]] if edits else [])
        checkout_ms = (time.perf_counter() - t0) * 1000
        dry, outcomes = [], {}
        for name, new in edits:
            t0 = time.perf_counter()
            v = k.commit(sid, nid, source=new, dry_run=True)
            dry.append((time.perf_counter() - t0) * 1000)
            key = "accepted" if v.accepted else f"Gate {v.gate}" + (" (environment)" if "failed to load" in str(v.error) else "")
            outcomes[key] = outcomes.get(key, 0) + 1
        real_ms = None
        if edits:
            t0 = time.perf_counter()
            k.commit(sid, nid, source=edits[0][1], dry_run=False)
            real_ms = (time.perf_counter() - t0) * 1000
            all_real.append(real_ms)
        all_dry += dry
        rows.append({"module": label, "loc": loc, "functions": fns, "init_ms": round(init_ms, 1), "checkout_ms": round(checkout_ms, 1),
                     "checkout_tokens": payload.token_count, "dry_commit_ms": [round(m, 1) for m in dry], "landed_commit_ms": round(real_ms, 1) if real_ms else None,
                     "outcomes": outcomes})
        print(f"  monolith {loc:>6} LOC {fns:>4} fns init {init_ms:7.0f} ms  checkout {checkout_ms:6.0f} ms  dry p50 {pct(dry, .5)} ms  {outcomes}", flush=True)
    return {"files": len(rows), "loc_total": sum(r["loc"] for r in rows), "init": stats([r["init_ms"] for r in rows]),
            "checkout": stats([r["checkout_ms"] for r in rows]), "dry_run_commit": stats(all_dry), "landed_commit": stats(all_real), "rows": rows}


# ------------------------------------------------------------------ 2. whole repository


def stress_repo(repo: Path) -> dict:
    if not repo.exists():
        return {"error": f"{repo} not found (clone django/django --depth 1 into _cache/django)"}
    files = _okf.tracked_files(repo)
    loc = 0
    for p in files:
        try:
            loc += p.read_bytes().count(b"\n")
        except OSError:
            pass
    rss0 = rss_mb()
    k = StateKernel()
    t0 = time.perf_counter()
    try:
        sid = k.init_session(repo)
    except Exception as exc:  # noqa: BLE001 — the baseline may not survive the tree
        return {"repo": str(repo), "tracked_files": len(files), "loc": loc,
                "init_session_crash": f"{type(exc).__name__}: {str(exc)[:160]}", "seconds_before_crash": round(time.perf_counter() - t0, 1)}
    init_s = time.perf_counter() - t0
    # Peak memory of an index, on a second (ephemeral) kernel: tracemalloc slows allocation-heavy
    # code several-fold, so it never shares the wall clock above. (Slice 35/36 receipts measured
    # both at once; their init seconds carry that overhead.)
    tracemalloc.start()
    try:
        StateKernel(ephemeral=True).init_session(repo)
    except Exception:  # noqa: BLE001
        pass
    _cur, tm_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    nodes = k.graph(sid)["nodes"]
    target = (next((n for n in nodes if n["path"].replace("\\", "/") in ("django/db/models/query.py", "db/models/query.py")), None)
              or max(nodes, key=lambda n: (repo / n["path"]).stat().st_size))  # a lazy node carries no source in the graph
    path = repo / target["path"]
    text = path.read_text(encoding="utf-8")
    anchor = next((ln for ln in text.splitlines() if ln.strip().startswith("def ")), None)
    event = {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(repo), "stepcheck_session_id": sid,
             "tool_input": {"file_path": str(path), "old_string": anchor, "new_string": anchor + "\n    _stepcheck_probe = 0"}}
    hook_ms = []
    for _ in range(5):
        t0 = time.perf_counter()
        out = hooks.decide(event, k)
        hook_ms.append((time.perf_counter() - t0) * 1000)
    read_event = {"hook_event_name": "PreToolUse", "tool_name": "Read", "cwd": str(repo), "stepcheck_session_id": sid,
                  "tool_input": {"file_path": str(path)}}
    read_ms = []
    for _ in range(3):
        t0 = time.perf_counter()
        hooks.decide(read_event, k)
        read_ms.append((time.perf_counter() - t0) * 1000)
    # a fresh process rehydrating the session from disk: what every hook subprocess pays
    t0 = time.perf_counter()
    k2 = StateKernel()
    k2.locate(sid, path)
    rehydrate_ms = (time.perf_counter() - t0) * 1000
    ci = {}
    for run in ("cold", "warm"):
        # a fresh interpreter per run, as a CI runner would start it: the first run pays the
        # cold OS file cache, the second does not; neither inherits this process's memo state
        env = {**os.environ, "STEPCHECK_HOME": str(HOME), "STEPCHECK_HOOK_AUTOSTART": "0", "PYTHONUTF8": "1"}
        t0 = time.perf_counter()
        done = subprocess.run([sys.executable, "-m", "cli", "ci", str(repo)], cwd=BACKEND, env=env,
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3600)
        text = done.stdout.strip()
        ci[run] = {"seconds": round(time.perf_counter() - t0, 1), "exit": done.returncode,
                   "last_line": text.splitlines()[-1][:160] if text else done.stderr.strip()[-160:], "fresh_process": True}
    return {"repo": str(repo), "tracked_files": len(files), "loc": loc, "nodes": len(nodes),
            "init_session_s": round(init_s, 1), "init_files_per_s": round(len(files) / init_s, 1) if init_s else None,
            "tracemalloc_peak_mb": round(tm_peak / 1e6, 1), "rss_before_mb": rss0, "rss_after_mb": rss_mb(), "peak_rss_mb": peak_rss_mb(),
            "session_file_mb": round((repo / ".stepcheck" / "sessions" / f"{sid}.json").stat().st_size / 1e6, 1) if (repo / ".stepcheck" / "sessions" / f"{sid}.json").exists() else None,
            "hook_edit_target": target["path"], "hook_edit_ms": stats(hook_ms), "hook_edit_decision": (out.get("hookSpecificOutput") or {}).get("permissionDecision", "allow (no opinion)"),
            "hook_read_ms": stats(read_ms), "fresh_process_rehydrate_ms": round(rehydrate_ms, 1), "ci": ci}


# ------------------------------------------------------------------ 3. noise


def stress_noise() -> dict:
    files = {
        "app/models.py": "class User:\n    def __init__(self, name):\n        if not name:\n            raise ValueError(name)\n        self.name = name\n",
        "app/migrations/0001_initial.py": "from django.db import migrations, models\n\n\nclass Migration(migrations.Migration):\n    initial = True\n    operations = [\n" + "".join(f"        migrations.CreateModel(name='M{i}', fields=[]),\n" for i in range(300)) + "    ]\n",
        "app/migrations/__init__.py": "",
        "proto/foo_pb2.py": "# Generated by the protocol buffer compiler.  DO NOT EDIT!\n" + "".join(f"_DESCRIPTOR_{i} = {i}\n" for i in range(2000)),
        "proto/foo_pb2_grpc.py": "# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!\nimport grpc\n" + "".join(f"def stub_{i}(x):\n    return x\n\n" for i in range(300)),
        "web/index.d.ts": "export declare function f(x: number): number;\n" * 500,
        "web/bundle.min.js": "!function(e){" + "var a=1;" * 20000 + "}();\n",
        "web/app.generated.ts": "export const g = 1;\n" * 1000,
        "web/src/app.ts": "export function run(x: number): number {\n  if (x < 0) throw new RangeError('x');\n  return x;\n}\n",
        "vendor/lib/x.py": "def v():\n    return 1\n" * 50,
        "dist/out.py": "x = 1\n" * 1000,
        "build/lib/pkg/m.py": "y = 2\n" * 1000,
        ".next/server/page.js": "module.exports = {};\n",
        "target/debug/gen.rs": "fn g() {}\n",
        "artifacts/generated_big.py": "".join(f"def gen_{i}(a):\n    return a + {i}\n\n" for i in range(3000)),
        ".gitignore": "artifacts/\n*.min.js\n",
    }
    root = make_project(files)
    subprocess.run(["git", "init", "-q"], cwd=root, capture_output=True)
    t0 = time.perf_counter()
    tracked = [str(p.relative_to(root)).replace("\\", "/") for p in _okf.tracked_files(root)]
    discover_ms = (time.perf_counter() - t0) * 1000
    k = StateKernel()
    t0 = time.perf_counter()
    sid = k.init_session(root)
    init_ms = (time.perf_counter() - t0) * 1000
    nodes = {n["path"].replace("\\", "/"): n for n in k.graph(sid)["nodes"]}
    noise = [p for p in tracked if re.search(r"migrations/|_pb2|\.min\.js|\.d\.ts|\.generated\.|^vendor/|^dist/|^build/|^\.next/|^target/|^artifacts/", p)]
    return {"files_in_tree": len(files), "tracked": tracked, "tracked_count": len(tracked), "noise_tracked": noise,
            "noise_tracked_count": len(noise), "discover_ms": round(discover_ms, 1), "init_ms": round(init_ms, 1),
            "invariants_mined_in_noise": sum(len(nodes[p]["invariants"]) + len(nodes[p]["invariants_auto_mined"]) for p in noise if p in nodes),
            "gitignored_tracked": [p for p in tracked if p.startswith("artifacts/") or p.endswith(".min.js")]}


# ------------------------------------------------------------------ 4. resilience


def stress_resilience() -> dict:
    out: dict = {}
    # BOM + non-ASCII
    root = make_project({"b.py": "def f(x):\n    if x is None:\n        raise ValueError('naïve 🙂')\n    return x\n"})
    raw = (root / "b.py").read_bytes()
    (root / "b.py").write_bytes(b"\xef\xbb\xbf" + raw.replace(b"\n", b"\r\n"))
    (root / "latin.py").write_bytes("x = 'caf\xe9'\n".encode("latin-1"))
    k = StateKernel()
    try:
        sid = k.init_session(root)
        nodes = {n["path"] for n in k.graph(sid)["nodes"]}
        v = k.commit(sid, "b", source="def f(x):\n    if x is None:\n        raise ValueError('naïve 🙂')\n    return x + 0\n")
        out["bom_crlf"] = {"indexed": "b.py" in nodes, "latin1_skipped": "latin.py" not in nodes, "commit_accepted": v.accepted,
                           "bom_preserved": (root / "b.py").read_bytes().startswith(b"\xef\xbb\xbf"), "crlf_preserved": b"\r\n" in (root / "b.py").read_bytes()}
    except Exception as exc:  # noqa: BLE001
        out["bom_crlf"] = {"crash": repr(exc)[:200]}
    # deep nesting
    for depth in (50, 120, 400):
        src = "def deep(x):\n" + "".join("    " * (i + 1) + f"if x > {i}:\n" for i in range(depth)) + "    " * (depth + 1) + "return x\n" + "    return 0\n"
        root = make_project({"deep.py": src})
        k = StateKernel()
        t0 = time.perf_counter()
        try:
            sid = k.init_session(root)
            if "deep" not in {n["node_id"] for n in k.graph(sid)["nodes"]}:
                out[f"nesting_{depth}"] = {"indexed": False, "commit": "untracked: past the parser's limits, index unaffected",
                                           "ms": round((time.perf_counter() - t0) * 1000, 1)}
                continue
            v = k.commit(sid, "deep", source=src.replace("return 0", "return 1"))
            out[f"nesting_{depth}"] = {"indexed": True, "commit": "accepted" if v.accepted else f"Gate {v.gate}: {str(v.error)[:80]}", "ms": round((time.perf_counter() - t0) * 1000, 1)}
        except RecursionError as exc:
            out[f"nesting_{depth}"] = {"crash": f"RecursionError: {str(exc)[:80]}"}
        except Exception as exc:  # noqa: BLE001
            out[f"nesting_{depth}"] = {"crash": repr(exc)[:160]}
    # circular imports + wildcard
    root = make_project({
        "pkg/__init__.py": "from .a import *\nfrom .b import *\n",
        "pkg/a.py": "from . import b\n\n\ndef fa(x):\n    if x < 0:\n        raise ValueError(x)\n    return b.fb(x) + 1\n",
        "pkg/b.py": "from . import a\n\n\ndef fb(x):\n    if x > 100:\n        raise ValueError(x)\n    return x\n\n\ndef uses_a(y):\n    return a.fa(y)\n",
        "consumer.py": "from pkg import fa, fb\n\n\ndef run(v):\n    return fa(v) + fb(v)\n",
    })
    k = StateKernel()
    t0 = time.perf_counter()
    try:
        sid = k.init_session(root)
        ids = {n["path"].replace("\\", "/"): n["node_id"] for n in k.graph(sid)["nodes"]}
        v = k.commit(sid, ids["pkg/a.py"], source="from . import b\n\n\ndef fa(x, strict=False):\n    if x < 0:\n        raise ValueError(x)\n    return b.fb(x) + 1\n")
        status = {n["path"].replace("\\", "/"): n["status"] for n in k.graph(sid)["nodes"]}
        out["circular_wildcard"] = {"indexed": sorted(ids), "commit_accepted": v.accepted, "dirtied": v.dirtied, "status": status,
                                    "ms": round((time.perf_counter() - t0) * 1000, 1), "terminated": True}
    except Exception as exc:  # noqa: BLE001
        out["circular_wildcard"] = {"crash": repr(exc)[:200]}
    return out


def main() -> int:
    t_start = time.perf_counter()
    head, dirty = git_head()
    print(f"ENTERPRISE SCALE — {LABEL} on kernel {head}{' (+dirty backend)' if dirty else ''}", flush=True)
    results = {"1_monoliths": {} if SKIP_MONOLITHS else stress_monoliths()}
    print("  [1_monoliths] done", flush=True)
    results["2_repository"] = {} if SKIP_REPO else stress_repo(REPO_DIR)
    print("  [2_repository] done", flush=True)
    results["3_noise"] = stress_noise()
    print("  [3_noise] done", flush=True)
    results["4_resilience"] = stress_resilience()
    print("  [4_resilience] done", flush=True)
    receipt = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "generator": ".stepcheck/discovery/benchmark_enterprise_scale.py",
               "label": LABEL, "kernel_commit": head, "backend_dirty": dirty, "python": sys.version.split()[0], "results": results,
               "runtime_s": round(time.perf_counter() - t_start, 1)}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(receipt, indent=1, default=str), encoding="utf-8")
    m, r, n, z = results["1_monoliths"], results["2_repository"], results["3_noise"], results["4_resilience"]
    if m:
        print(f"\n1. monoliths: {m['files']} files, {m['loc_total']:,} LOC; init {m['init']}; checkout {m['checkout']}")
        print(f"   dry-run commit {m['dry_run_commit']}; landed commit {m['landed_commit']}")
    if r and "init_session_crash" in r:
        print(f"2. repository: {r['tracked_files']} files, {r['loc']:,} LOC; init_session CRASHED after {r['seconds_before_crash']} s: {r['init_session_crash']}")
    elif r and "error" not in r:
        print(f"2. repository: {r['tracked_files']} files, {r['loc']:,} LOC; cold init {r['init_session_s']} s ({r['init_files_per_s']} files/s); "
              f"tracemalloc peak {r['tracemalloc_peak_mb']} MB, peak RSS {r['peak_rss_mb']} MB, session file {r['session_file_mb']} MB")
        print(f"   hook Edit on {r['hook_edit_target']}: {r['hook_edit_ms']} -> {r['hook_edit_decision']}; hook Read {r['hook_read_ms']}; "
              f"fresh-process rehydrate {r['fresh_process_rehydrate_ms']} ms; ci cold {r['ci']['cold']['seconds']} s / warm {r['ci']['warm']['seconds']} s ({r['ci']['warm']['last_line']})")
    else:
        print("2. repository:", r.get("error", "skipped"))
    print(f"3. noise: tracked {n['tracked_count']}/{n['files_in_tree']} files, noise tracked {n['noise_tracked_count']} {n['noise_tracked']}, "
          f"gitignored tracked {n['gitignored_tracked']}, invariants mined in noise {n['invariants_mined_in_noise']}, init {n['init_ms']} ms")
    print(f"4. resilience: {json.dumps(z, default=str)[:900]}")
    print(f"receipt: {OUT}  ({receipt['runtime_s']} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
