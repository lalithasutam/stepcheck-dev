"""Unseen holdout: SWE-bench Verified rows [offset, offset+length) that no rule was tuned on.
Every single-file Python gold patch goes through StateKernel.commit strict and declared, with
the test patch landed beside it, exactly as audit_loopholes.vector_swebench does for rows 0-24.
usage: swe_holdout.py [--offset 25] [--length 20]   (needs the network the first time)
Receipt: receipts/swe_holdout.json
"""
from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import verify_external_benchmarks as X  # noqa: E402
import audit_loopholes as A  # noqa: E402

OFFSET = int(sys.argv[sys.argv.index("--offset") + 1]) if "--offset" in sys.argv else 25
LENGTH = int(sys.argv[sys.argv.index("--length") + 1]) if "--length" in sys.argv else 20
URL = ("https://datasets-server.huggingface.co/rows?dataset=princeton-nlp%2FSWE-bench_Verified"
       f"&config=default&split=test&offset={OFFSET}&length={LENGTH}")
RECEIPT = HERE / "receipts" / "swe_holdout.json"


def main() -> int:
    t0 = time.perf_counter()
    head, dirty = A.git_head()
    raw = X.fetch(URL)
    if raw is None:
        sys.exit("could not fetch the holdout rows")
    rows = [r["row"] for r in json.loads(raw)["rows"]]
    tasks, skipped = [], []
    for r in rows:
        files = A.split_patch(r["patch"])
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
        after = A.apply_hunks(before, files[rel]["hunks"])
        if after is None or not X.parses(before) or not X.parses(after):
            skipped.append({"instance": r["instance_id"], "reason": "gold patch did not apply cleanly / does not parse"})
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
        tasks.append({"instance": r["instance_id"], "repo": r["repo"], "path": rel, "before": before, "after": after, "tests": tests})
    pairs = []
    for t in tasks:
        files = {t["path"]: t["before"], **{trel: tb for trel, (tb, _ta) in t["tests"].items() if tb}}
        root = X.make_project(files)
        for trel, (_tb, ta) in t["tests"].items():
            (root / trel).parent.mkdir(parents=True, exist_ok=True)
            (root / trel).write_text(ta, encoding="utf-8", newline="\n")
        pairs.append((f"SWE-bench/{t['instance']}", root, t["path"], t["after"]))
    b = X.part_b(pairs) if pairs else {}
    receipt = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "generator": ".stepcheck/discovery/swe_holdout.py",
               "kernel_commit": head, "backend_dirty": dirty, "rows": {"offset": OFFSET, "length": LENGTH, "fetched": len(rows)},
               "repos": sorted({r["repo"] for r in rows}), "single_file_python_tasks": len(tasks), "skipped": skipped,
               "b_gold_patches": b, "sources": X.SOURCES, "runtime_s": round(time.perf_counter() - t0, 1)}
    RECEIPT.write_text(json.dumps(receipt, indent=1, default=str), encoding="utf-8")
    print(f"SWE-bench Verified holdout rows {OFFSET}-{OFFSET + LENGTH - 1} — kernel {head}{' (+dirty)' if dirty else ''}")
    print(f"  repos {receipt['repos']}; single-file tasks {len(tasks)}/{len(rows)}; skipped {len(skipped)}")
    if b:
        print(f"  strict {b['strict_pass_rate_pct']}% ({sum(r['strict'] for r in b['rows'])}/{b['patches']}), declared {b['declared_pass_rate_pct']}%, "
              f"excluding environment {b['declared_pass_rate_excluding_environment_pct']}%; strict rejections {b['strict_rejection_reasons']}")
        for r in b["rejected_examples"]:
            print("   ", r["task"], r.get("strict_rejection"), (r.get("strict_error") or "")[:160])
    print(f"receipt: {RECEIPT}  ({receipt['runtime_s']} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
