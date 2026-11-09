"""Zero-hallucination integrity gate for the discovery campaign.

1. Runs `pytest -q` and `stepcheck ci .` and stores their verbatim output as receipts.
2. Generates every report (NOVEL_SOLUTIONS_AND_BENCHMARKS.md, the paper in Markdown
   and LaTeX, the generated block of HN-WAR-ROOM.md) strictly from the JSON/CSV
   receipts on disk through a Ledger: every number printed is looked up or
   recomputed from a receipt at generation time and recorded with its source.
3. Verifies: reloads every receipt, recomputes every ledger entry, asserts the
   text is identical and present in the document; then extracts every numeric
   token from the generated documents and asserts each one is a ledger entry or
   a registered non-metric token (dates, version ids, commit hashes).
4. Prints `ZERO-HALLUCINATION INTEGRITY AUDIT: PASS` only if everything holds.

usage: verify_integrity.py [--skip-runs]   (--skip-runs reuses the stored pytest/ci receipts)
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import re
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
R = HERE / "receipts"
PAPER = REPO / ".stepcheck" / "paper"
WAR_ROOM = REPO / ".stepcheck" / "HN-WAR-ROOM.md"
PY = sys.executable
TODAY = "2026-11-03"

# ----------------------------------------------------------------- receipts


def load_json(name: str) -> dict:
    return json.loads((R / name).read_text(encoding="utf-8"))


def run_and_record(skip: bool) -> None:
    if skip and (R / "pytest_full.json").exists() and (R / "ci_output.json").exists():
        return
    p = subprocess.run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=REPO / "backend",
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = p.stdout + p.stderr
    m = re.search(r"(\d+) passed", out)
    (R / "pytest_full.txt").write_text(out, encoding="utf-8")
    (R / "pytest_full.json").write_text(json.dumps({
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "command": "python -m pytest -q", "cwd": "backend",
        "returncode": p.returncode, "passed": int(m.group(1)) if m else None,
        "failed": int(re.search(r"(\d+) failed", out).group(1)) if re.search(r"(\d+) failed", out) else 0,
    }, indent=1), encoding="utf-8")
    c = subprocess.run([PY, "-m", "cli", "ci", str(REPO)], cwd=REPO / "backend",
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    cout = c.stdout + c.stderr
    mm = re.search(r"stepcheck ci: (PASS|FAIL) \u2014 (\d+) modules verified", cout)
    inv = re.search(r"(\d+) invariants executed", cout)
    (R / "ci_output.txt").write_text(cout, encoding="utf-8")
    (R / "ci_output.json").write_text(json.dumps({
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "command": "stepcheck ci <repo>",
        "returncode": c.returncode, "verdict": mm.group(1) if mm else None,
        "modules_verified": int(mm.group(2)) if mm else None, "invariants_executed": int(inv.group(1)) if inv else None,
    }, indent=1), encoding="utf-8")


def git_head() -> str:
    return subprocess.run(["git", "rev-parse", "--short=7", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()


# ------------------------------------------------------------------- ledger


def walk(obj, path: list):
    for key in path:
        obj = obj[key]
    return obj


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile on a sorted copy (the method stated in the reports)."""
    s = sorted(values)
    return s[max(0, min(len(s) - 1, round(q * (len(s) - 1))))]


class Ledger:
    """Every number that reaches a document goes through here."""

    def __init__(self, data: dict[str, dict]):
        self.data = data
        self.entries: list[dict] = []
        self.computed: dict[str, tuple] = {}  # label -> (fn, kind)

    @staticmethod
    def fmt(value, kind: str) -> str:
        if value is None:
            return "n/a"
        if kind == "int":
            return f"{int(round(value)):,}"
        if kind == "pct1":
            return f"{value:.1f}%"
        if kind == "pct2":
            return f"{value:.2f}%"
        if kind == "ms1":
            return f"{value:.1f} ms"
        if kind == "usd2":
            return f"${value:,.2f}"
        if kind == "f2":
            return f"{value:.2f}"
        if kind == "f3":
            return f"{value:.3f}"
        if kind == "ratio_pct1":
            return f"{100 * value:.1f}%"
        if kind == "str":
            return str(value)
        raise ValueError(kind)

    def get(self, source: str, path: list, kind: str = "int") -> str:
        value = walk(self.data[source], path)
        text = self.fmt(value, kind)
        self.entries.append({"source": source, "path": path, "kind": kind, "text": text})
        return text

    def computed_value(self, label: str, fn, kind: str) -> str:
        self.computed[label] = (fn, kind)
        text = self.fmt(fn(self.data), kind)
        self.entries.append({"source": "computed", "path": [label], "kind": kind, "text": text})
        return text


# ----------------------------------------------------------- aggregates


def latency_rows(d):
    """Recompute Table: per-phase p50/p95/p99 from Track 1's raw per-module list."""
    rows = {}
    for m in d["track1_engine"]["4_phase_latency"]["per_module"]:
        for key, val in m.items():
            if key.endswith("_ns") and isinstance(val, (int, float)):
                rows.setdefault(key, []).append(val / 1e6)
    return rows


def tex_escape(s: str) -> str:
    return s.replace("%", r"\%").replace("_", r"\_").replace("&", r"\&").replace("#", r"\#")


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def tex_table(headers: list[str], rows: list[list[str]], caption: str, label: str) -> str:
    cols = "l" * len(headers)
    body = " \\\\\n".join(" & ".join(tex_escape(c) for c in r) for r in rows)
    return (f"\\begin{{table}}[h]\n\\centering\n\\begin{{tabular}}{{{cols}}}\n\\toprule\n"
            + " & ".join(tex_escape(h) for h in headers) + " \\\\\n\\midrule\n" + body
            + " \\\\\n\\bottomrule\n\\end{tabular}\n\\caption{" + tex_escape(caption) + f"}}\n\\label{{{label}}}\n\\end{{table}}")


# ------------------------------------------------------------- generation


def build(L: Ledger, head: str) -> dict[str, str]:
    d = L.data
    t1, t2, t3, t4 = d["track1_engine"], d["track2_product"], d["track3_market"], d["track4_gtm"]
    g = L.get
    sections: list[tuple[str, str, list[tuple[str, list, str]] | None]] = []
    tables_md: dict[str, str] = {}
    tables_tex: dict[str, str] = {}

    # ---- pre-fix receipts and Red/Green
    red_f, red_p = g("pytest_red", ["counts", "failed"]), g("pytest_red", ["counts", "passed"])
    red_t = g("pytest_red", ["counts", "timeout"])
    green_p, green_f = g("pytest_green", ["counts", "passed"]), g("pytest_green", ["counts", "failed"])
    prefix_total = g("pre_fix_failures", ["counts", "total"])
    prefix_probes = g("pre_fix_failures", ["counts", "track1_seam_probes"])
    prefix_red = g("pre_fix_failures", ["counts", "red_tests"])
    full_passed = g("pytest_full", ["passed"])
    full_rc = g("pytest_full", ["returncode"])
    ci_rc = g("ci_output", ["returncode"])
    ci_modules = g("ci_output", ["modules_verified"])
    ci_inv = g("ci_output", ["invariants_executed"])
    dog_commits = L.computed_value("dogfood.accepted_commits", lambda x: sum(1 for c in x["dogfood_slice16"]["commits"] if c["accepted"]), "int")
    dog_raw = g("dogfood_slice16", ["telemetry", "raw_bloated_tokens"])
    dog_comp = g("dogfood_slice16", ["telemetry", "compacted_okf_tokens"])
    dog_saved = g("dogfood_slice16", ["telemetry", "tokens_saved"])
    dog_turns = g("dogfood_slice16", ["telemetry", "turns"])
    dog_rows = [[c["node_id"], ", ".join(c["ops"]), "accepted" if c["accepted"] else f"rejected at Gate {c['gate']}",
                 (c["attestation_sha256"] or "")[:16] + "…"] for c in d["dogfood_slice16"]["commits"]]

    # ---- Track 1
    pat = t1["1_multi_def_symbol_spans"]["library_patterns"]["totals"]
    pat_rows = [[k.replace("_", " "), g("track1_engine", ["1_multi_def_symbol_spans", "library_patterns", "totals", k])] for k in pat]
    tables_md["patterns"] = md_table(["AST pattern (16 packages + backend)", "occurrences"], pat_rows)
    tables_tex["patterns"] = tex_table(["AST pattern", "occurrences"], pat_rows, "Symbol-addressing hazards found in the installed corpus.", "tab:patterns")
    swe = t1["1_multi_def_symbol_spans"]["swebench"]
    swe_err = g("track1_engine", ["1_multi_def_symbol_spans", "swebench", "error"], "str") if not swe.get("fetched") else ""
    swe_line = ("fetched" if swe.get("fetched") else f"not fetched ({swe_err}); no synthetic stand-in was used")
    slice_pre = t1["2_method_slicing"]["pre_fix"]
    pre_whole = g("track1_engine", ["2_method_slicing", "pre_fix", "focus_whole_class_tokens"])
    pre_dotted = g("track1_engine", ["2_method_slicing", "pre_fix", "focus_dotted_tokens"])
    agg = t1["2_method_slicing"]["aggregate"]
    classes_measured = g("track1_engine", ["2_method_slicing", "aggregate", "classes_measured"])
    agg_saving = g("track1_engine", ["2_method_slicing", "aggregate", "aggregate_saving_vs_class_focus_pct"], "pct2")
    med_saving = g("track1_engine", ["2_method_slicing", "aggregate", "median_saving_vs_class_focus_pct"], "pct2")
    fz = t1["3_fuzzing_and_trace_hook"]
    fz_rows = [
        ["_okf.apply_patch", g("track1_engine", ["3_fuzzing_and_trace_hook", "apply_patch", "examples"]),
         L.computed_value("fuzz.apply_patch.counterexamples", lambda x: len(x["track1_engine"]["3_fuzzing_and_trace_hook"]["apply_patch"]["counterexamples"]), "int")],
        ["mine_guard_invariants → gate_c", g("track1_engine", ["3_fuzzing_and_trace_hook", "mine_guard_invariants", "examples"]),
         L.computed_value("fuzz.miner.false_positives", lambda x: len(x["track1_engine"]["3_fuzzing_and_trace_hook"]["mine_guard_invariants"]["false_positives"]), "int")],
        ["_sandbox.guarded", g("track1_engine", ["3_fuzzing_and_trace_hook", "guarded", "examples"]), "see recursion row"],
    ]
    tables_md["fuzz"] = md_table(["property", "examples", "counterexamples / false positives"], fz_rows)
    tables_tex["fuzz"] = tex_table(["property", "examples", "counterexamples"], fz_rows, "Hypothesis property runs (seed 20261103).", "tab:fuzz")
    rec_err = g("track1_engine", ["3_fuzzing_and_trace_hook", "guarded", "recursion", "recursion_error"])
    rec_ok = g("track1_engine", ["3_fuzzing_and_trace_hook", "guarded", "recursion", "completed"])
    hook_changed = str(fz["mutual_recursion"]["trace_hook_left_installed_or_changed"])
    second_enforced = str(fz["mutual_recursion"]["second_commit_runaway_loop"]["step_budget_still_enforced"])
    lat = latency_rows(d)
    lat_phase_names = ["parse_ns", "analyze_ns", "skeleton_ns", "checkout_focus_empty_ns", "gate_a_ns", "gate_b_ns", "gate_c_ns", "commit_append_ns"]
    lat_rows = []
    for ph in lat_phase_names:
        if ph not in lat:
            continue
        label = ph.removesuffix("_ns")
        lat_rows.append([label, L.computed_value(f"lat.{ph}.n", lambda x, p=ph: len(latency_rows(x)[p]), "int"),
                         L.computed_value(f"lat.{ph}.p50", lambda x, p=ph: percentile(latency_rows(x)[p], 0.50), "ms1"),
                         L.computed_value(f"lat.{ph}.p95", lambda x, p=ph: percentile(latency_rows(x)[p], 0.95), "ms1"),
                         L.computed_value(f"lat.{ph}.p99", lambda x, p=ph: percentile(latency_rows(x)[p], 0.99), "ms1")])
    tables_md["latency"] = md_table(["phase", "modules", "p50", "p95", "p99"], lat_rows)
    tables_tex["latency"] = tex_table(["phase", "n", "p50", "p95", "p99"], lat_rows, "Per-phase kernel latency across the installed corpus, nearest-rank percentiles recomputed from the per-module receipt (ephemeral kernel, Windows, single machine).", "tab:latency")
    appends_ok = g("track1_engine", ["4_phase_latency", "commit_append", "accepted"])
    appends_rej = g("track1_engine", ["4_phase_latency", "commit_append", "rejected"])
    intoto_ok = str(t1["5_in_toto_provenance"]["all_checks_pass"])
    intoto_n = L.computed_value("intoto.envelopes", lambda x: len(x["track1_engine"]["5_in_toto_provenance"]["envelopes"]), "int")

    # ---- Track 2
    rg = t2["read_guard"]
    t2_rows = [
        ["Read guard, deny path", g("track2_product", ["read_guard", "latency_deny_path", "p50_ms"], "ms1"), g("track2_product", ["read_guard", "latency_deny_path", "p95_ms"], "ms1")],
        ["Read guard, allow path", g("track2_product", ["read_guard", "latency_allow_path", "p50_ms"], "ms1"), g("track2_product", ["read_guard", "latency_allow_path", "p95_ms"], "ms1")],
        ["Stop guard, dirty session", g("track2_product", ["stop_guard", "dirty_state", "latency", "p50_ms"], "ms1"), g("track2_product", ["stop_guard", "dirty_state", "latency", "p95_ms"], "ms1")],
        ["Stop guard, clean session", g("track2_product", ["stop_guard", "clean_state", "latency", "p50_ms"], "ms1"), g("track2_product", ["stop_guard", "clean_state", "latency", "p95_ms"], "ms1")],
    ]
    tables_md["hooks"] = md_table(["hook", "p50", "p95"], t2_rows)
    tables_tex["hooks"] = tex_table(["hook", "p50", "p95"], t2_rows, "Lifecycle-hook latency (fresh interpreter per invocation).", "tab:hooks")
    tok = t2["token_overhead"]["totals"]
    tok_rows = [
        ["(b) raw Read of all tracked modules", g("track2_product", ["token_overhead", "totals", "b_raw_read_tool_tokens"]), "—"],
        ["(a) CLAUDE.md compliance, focus on the largest symbol", g("track2_product", ["token_overhead", "totals", "a_focused_checkout_tokens"]), g("track2_product", ["token_overhead", "totals", "a_vs_b_saved_pct"], "pct1")],
        ["(c) hook-enforced skeleton for modules over the threshold", g("track2_product", ["token_overhead", "totals", "c_hook_enforced_tokens"]), g("track2_product", ["token_overhead", "totals", "c_vs_b_saved_pct"], "pct1")],
        ["(d) pure focus=[] skeleton", g("track2_product", ["token_overhead", "totals", "d_skeleton_checkout_tokens"]), g("track2_product", ["token_overhead", "totals", "d_vs_b_saved_pct"], "pct1")],
    ]
    tables_md["tokens"] = md_table(["per-turn context source", "tokens", "saved vs (b)"], tok_rows)
    tables_tex["tokens"] = tex_table(["context source", "tokens", "saved vs raw"], tok_rows, "Per-turn context cost on the repository's own modules.", "tab:tokens")
    denied_saved = g("track2_product", ["read_guard", "totals_denied", "saved_pct_vs_read_tool"], "pct1")
    denied_ctx = g("track2_product", ["read_guard", "totals_denied", "hook_context_tokens"])
    denied_raw = g("track2_product", ["read_guard", "totals_denied", "raw_read_tool_tokens"])
    reason_tok = g("track2_product", ["read_guard", "zero_token_claim", "reason_tokens_denied"])
    ci_rep_bytes = g("track2_product", ["ci_report", "backend_copy", "bytes"])
    ci_rep_det = str(t2["ci_report"]["backend_copy"]["deterministic_two_runs_identical"])
    ci_rep_ms = L.computed_value("ci_report.generation_ms.first", lambda x: x["track2_product"]["ci_report"]["backend_copy"]["generation_ms"][0], "ms1")

    # ---- Track 3
    au_pub, au_now = t3["audit"]["published_docs_audit_html"], t3["audit"]["rederived_now"]
    au_rows = [[k.replace("_", " "), g("track3_market", ["audit", "published_docs_audit_html", k], "usd2" if "usd" in k else "int"),
                g("track3_market", ["audit", "rederived_now", k], "usd2" if "usd" in k else "int")]
               for k in ("sessions", "assistant_turns", "cache_gap_turns", "gap_rebilled_tokens", "gap_waste_usd")]
    tables_md["audit"] = md_table(["audit figure", "published receipt", "re-derived at run time"], au_rows)
    tables_tex["audit"] = tex_table(["figure", "published", "re-derived"], au_rows, "Real-transcript audit: the published receipt versus the same parser over every transcript present at run time.", "tab:audit")
    span_days = g("track3_market", ["audit", "window", "span_days"], "f2")
    sc = t3["arbitrage"]["scenarios"]
    arb_rows = []
    for key in sc:
        by = {round(r["pass_rate"], 2): r for r in sc[key]["by_pass_rate"]} if sc[key]["by_pass_rate"] and "pass_rate" in sc[key]["by_pass_rate"][0] else {}
        def saving_at(x, key=key, pr=None):
            rows = x["track3_market"]["arbitrage"]["scenarios"][key]["by_pass_rate"]
            row = next(r for r in rows if abs(r["pass_rate"] - pr) < 1e-9)
            return row["solo_monthly_saving_usd"] if "solo_monthly_saving_usd" in row else row[next(k for k in row if "saving" in k and "solo" in k)]
        be_pro = sc[key]["break_even_pass_rate_pro_29"]
        be_team = sc[key]["break_even_pass_rate_team_199"]
        arb_rows.append([key.replace("|", " · ").replace("_", " "),
                         g("track3_market", ["arbitrage", "scenarios", key, "solo_monthly_baseline_usd"], "usd2"),
                         L.computed_value(f"arb.{key}.save50", lambda x, k=key: saving_at(x, k, 0.5), "usd2"),
                         L.computed_value(f"arb.{key}.save80", lambda x, k=key: saving_at(x, k, 0.8), "usd2"),
                         L.computed_value(f"arb.{key}.save95", lambda x, k=key: saving_at(x, k, 0.95), "usd2"),
                         g("track3_market", ["arbitrage", "scenarios", key, "break_even_pass_rate_pro_29"], "ratio_pct1") if isinstance(be_pro, (int, float)) else "none",
                         g("track3_market", ["arbitrage", "scenarios", key, "break_even_pass_rate_team_199"], "ratio_pct1") if isinstance(be_team, (int, float)) else "none"])
    tables_md["arbitrage"] = md_table(["routing scenario", "solo baseline / month", "saving @50%", "@80%", "@95%", "break-even pass rate (Pro)", "(Team)"], arb_rows)
    tables_tex["arbitrage"] = tex_table(["scenario", "baseline", "save 50", "save 80", "save 95", "BE Pro", "BE Team"], arb_rows, "Gate-backed model arbitrage on the audited developer's observed volume (assumed prices in the receipt).", "tab:arbitrage")
    shield_rows = []
    for tier in ("sonnet", "opus"):
        shield_rows.append([tier, g("track3_market", ["cache_cliff_shield", "tiers", tier, "delta_above_cache_read_observed_usd"], "usd2"),
                            g("track3_market", ["cache_cliff_shield", "tiers", tier, "solo_annual_delta_usd"], "usd2"),
                            g("track3_market", ["cache_cliff_shield", "tiers", tier, "team25_annual_delta_usd"], "usd2")])
    tables_md["shield"] = md_table(["price tier", "observed delta above cache-read", "annualized, solo", "annualized, 25 seats"], shield_rows)
    tables_tex["shield"] = tex_table(["tier", "observed", "solo / yr", "25 seats / yr"], shield_rows, "Cache-cliff re-write cost that bounded OKF rehydration replaces (Fable tier skipped: no public price fetched).", "tab:shield")
    gap_turns = g("track3_market", ["cache_cliff_shield", "gap_turns"])
    gap_tokens = g("track3_market", ["cache_cliff_shield", "gap_rebilled_tokens"])
    pro_price = g("track3_market", ["assumptions", "tiers_usd_per_month", next(k for k in t3["assumptions"]["tiers_usd_per_month"] if "pro" in k.lower())], "usd2")
    team_price = g("track3_market", ["assumptions", "tiers_usd_per_month", next(k for k in t3["assumptions"]["tiers_usd_per_month"] if "team" in k.lower())], "usd2")
    c43 = g("track3_market", ["compliance", "control_map", "OWASP_AISVS_1.0", "AC.4.3", "matched_heading"], "str")
    c93 = g("track3_market", ["compliance", "control_map", "OWASP_AISVS_1.0", "AC.9.3", "matched_heading"], "str")

    # ---- Track 4
    assets_rows = [[Path(a["path"]).name, g("track4_gtm", ["assets", i, "bytes"]), a["sha256"][:16] + "…"] for i, a in enumerate(t4["assets"])]
    tables_md["assets"] = md_table(["asset", "bytes", "sha256"], assets_rows)
    tables_tex["assets"] = tex_table(["asset", "bytes", "sha256"], assets_rows, "Generated GTM assets.", "tab:assets")
    privacy_terms = g("track4_gtm", ["checks", "audit_card_privacy", "forbidden_terms"])
    privacy_pass = str(t4["checks"]["audit_card_privacy"]["pass"])
    card = t4["derived"]["audit_total"]
    card_usd = g("track4_gtm", ["derived", "audit_total", "gap_waste_usd"], "usd2")
    card_pct = g("track4_gtm", ["derived", "audit_total", "read_saving_pct"], "pct1")
    card_reg = g("track4_gtm", ["derived", "audit_total", "regressions"])
    card_sessions = g("track4_gtm", ["derived", "audit_total", "sessions"])

    # ---- paper eval (V2 kernel, before Slice 16) and benchmark
    pe = d["paper_eval_table3"]
    pe_keys = pe.get("system", pe)
    def pe_get(name, kind):
        return g("paper_eval_table3", (["system", name] if "system" in pe else [name]), kind)
    pe_rows = [["precision", pe_get("precision", "ratio_pct1" if pe_keys.get("precision", 0) <= 1 else "pct1")],
               ["recall", pe_get("recall", "ratio_pct1" if pe_keys.get("recall", 0) <= 1 else "pct1")],
               ["false positive rate", pe_get("fpr", "ratio_pct1" if pe_keys.get("fpr", 0) <= 1 else "pct1")]]
    tables_md["paper_eval"] = md_table(["fault matrix (50 faults, 50 valid edits)", "value"], pe_rows)
    tables_tex["paper_eval"] = tex_table(["metric", "value"], pe_rows, "PASS\\_TO\\_PASS fault matrix on the 387-file corpus.", "tab:prf")
    bench_raw = g("benchmark", ["final", "raw_bloated_tokens"])
    bench_comp = g("benchmark", ["final", "compacted_okf_tokens"])
    bench_pct = g("benchmark", ["final", "savings_pct"], "pct1")
    corpus_files = g("track4_gtm", ["derived", "corpus", "files"])
    corpus_loc = g("track4_gtm", ["derived", "corpus", "loc"])
    corpus_pkgs = g("track4_gtm", ["derived", "corpus", "packages"])

    before = d["dogfood_slice16"]["kernel_commit_before"]
    # ================================================================ documents
    novel = f"""# Novel solutions and benchmarks — discovery campaign

Generated {TODAY} by `.stepcheck/discovery/verify_integrity.py` from the JSON receipts under `.stepcheck/discovery/receipts/`. Every number below is read or recomputed from a receipt at generation time; the integrity gate re-derives each one and fails if any differs. Kernel before the slice: `{before}`; after: `{head}`.

## 1. Pre-fix failure receipts (Red → Green)

- Pre-fix loopholes recorded against the unpatched kernel: {prefix_total} ({prefix_probes} seam probes on real corpus files, {prefix_red} failing seam tests).
- Red run of `backend/tests/test_slice16_novel_capabilities.py` per test in its own interpreter: {red_f} failed, {red_p} passed, {red_t} timed out.
- Green run after landing Slice 16 through the gates: {green_p} passed, {green_f} failed.
- Full suite after the slice: {full_passed} passed (exit code {full_rc}); `stepcheck ci`: exit code {ci_rc}, {ci_modules} modules verified, {ci_inv} invariants executed.

## 2. Engine track

### 2.1 Symbol-addressing hazards in the installed corpus

{tables_md['patterns']}

SWE-bench Verified rows: {swe_line}.

### 2.2 Sub-class method slicing

Before the slice, `focus=["StateKernel.commit"]` rendered the class with the method as a signature only ({pre_dotted} tokens) while `focus=["StateKernel"]` rendered the whole class ({pre_whole} tokens). Across {classes_measured} classes in the class-heavy packages, the prototype's method-level payload saves {agg_saving} of the class-focus payload in aggregate (median {med_saving} per class). The slice lands dotted `focus=["Class.method"]` and dotted `replace_symbol` / `delete_symbol` in the kernel.

### 2.3 Property-based fuzzing and trace-hook resilience

{tables_md['fuzz']}

Recursion probes under `guarded`: {rec_err} runs ended in RecursionError, {rec_ok} completed. Mutual recursion through a real `commit`: trace hook left installed or changed = {hook_changed}; the step budget on the next commit was still enforced = {second_enforced}. The slice adds a depth cap inside the tracer and makes the budget a `BaseException` so staged code cannot launder it into the expected exception.

### 2.4 Phase latency (nearest-rank percentiles recomputed from the per-module receipt)

{tables_md['latency']}

Trivial-append commits across the corpus on the unpatched kernel: {appends_ok} accepted, {appends_rej} rejected.

### 2.5 in-toto Statement v1 provenance

Prototype envelopes verified on real commits: {intoto_n}; all round-trip checks pass = {intoto_ok}. The slice ships `StateKernel.provenance()`.

## 3. Product track (zero-token hooks, PR report)

{tables_md['hooks']}

Hook execution itself puts no tokens into the model; what enters context on a denied Read is the skeleton: {denied_ctx} tokens where the raw Read of the same modules is {denied_raw} ({denied_saved} less), plus {reason_tok} tokens of decision reasons.

{tables_md['tokens']}

`stepcheck ci --report` prototype: {ci_rep_bytes} bytes of Markdown, byte-identical across two runs = {ci_rep_det}, generated in {ci_rep_ms}.

## 4. Market track (FinOps)

{tables_md['audit']}

Observed transcript span: {span_days} days. Prices and tier fees are assumptions recorded in the receipt (Pro {pro_price}/month, Team {team_price}/month).

{tables_md['arbitrage']}

{tables_md['shield']}

Cache-cliff turns in the re-derived audit: {gap_turns}, re-billed tokens: {gap_tokens}. Compliance mapping: the AISVS heading matched for `AC.4.3` is "{c43}" (the receipt records a weak fit for the attestation story) and for `AC.9.3` is "{c93}".

## 5. GTM track

{tables_md['assets']}

Audit card (privacy check over {privacy_terms} forbidden terms, pass = {privacy_pass}): cache-cliff tax {card_usd}, Read→skeleton compaction {card_pct}, regressions caught {card_reg}, across {card_sessions} sessions.

## 6. Slice 16 landed through the gates

{md_table(["node", "ops", "verdict", "attestation sha256"], dog_rows)}

Gated commits accepted: {dog_commits}; session telemetry: {dog_raw} raw tokens vs {dog_comp} compacted over {dog_turns} turns ({dog_saved} saved).

## 7. Standing benchmark and corpus evaluation

50-turn benchmark: {bench_raw} raw → {bench_comp} compacted tokens ({bench_pct} saved). Corpus evaluation: {corpus_files} files, {corpus_loc} LOC, {corpus_pkgs} packages.

{tables_md['paper_eval']}
"""

    paper_md = f"""# StepCheck: a deterministic context firewall and gated state engine for AI coding agents

Generated {TODAY} from execution receipts by `.stepcheck/discovery/verify_integrity.py`. Kernel evaluated: `{before}` (pre-slice) and `{head}` (post-slice).

## Abstract

Long agent sessions degrade in two coupled ways: the context re-read every turn grows until attention over it decays, and silent omissions (a dropped decorator, a removed guard clause) pass the tests the agent still runs. StepCheck interposes a deterministic kernel between agent and model: modules are compiled into OKF frames, checked out as AST skeletons with a chosen focus, and modified only through patches that must pass three gates — mechanical (A), omission (B) and executed invariants (C) — before a DSSE attestation lands. We evaluate on an installed corpus of {corpus_pkgs} packages ({corpus_files} files, {corpus_loc} LOC) and on the kernel's own repository.

## 1. Design

The kernel (Seam 1) exposes `init_session`, `checkout(focus=)`, `commit(patch=)`, `lock_node`, `finalize_session` and `provenance`. A gateway (Seam 2) serves the same operations over REST and MCP and a BYOK proxy. Gate A checks syntax, locks and the names dependents import (including names bound inside conditional blocks and lazy `__all__` exports); Gate B fingerprints preserved symbols — definitions, decorators per module and per symbol, calls into dependencies — and refuses mass deletion; Gate C evaluates string, tree and callable invariants, the callable ones auto-mined from leading guard clauses, under a step, wall-clock and recursion-depth budget. Every landed commit yields a deterministic DSSE envelope; `provenance()` re-expresses the latest one as an in-toto Statement v1.

## 2. Evaluation

### 2.1 Fault matrix

{tables_md['paper_eval']}

### 2.2 Compaction and context cost

50-turn benchmark: {bench_raw} raw tokens versus {bench_comp} sent ({bench_pct} saved). On the repository's own modules:

{tables_md['tokens']}

### 2.3 Latency

{tables_md['latency']}

### 2.4 Symbol addressing on real code

{tables_md['patterns']}

Method-level slicing saves {agg_saving} of the class-focus payload in aggregate over {classes_measured} classes (median {med_saving}).

### 2.5 Robustness

{tables_md['fuzz']}

Mutual recursion through a real commit left the trace hook unchanged = {hook_changed}; the budget stayed enforced on the next commit = {second_enforced}.

### 2.6 Operational economics

{tables_md['audit']}

{tables_md['shield']}

## 3. Limitations

Faults are synthetic AST mutations. All timings come from one Windows machine. The token counter is the kernel's own estimator. SWE-bench Verified rows were {swe_line}. Prices in the economics tables are assumptions recorded in the receipt, not measurements.

## 4. Reproducibility

`python -m pytest -q` ({full_passed} passed), `stepcheck ci .` ({ci_modules} modules), `.stepcheck/paper_eval/run_eval.py`, `.stepcheck/discovery/engine_explorer.py`, `product_explorer.py`, `market_explorer.py`, `gtm_explorer.py`, then `verify_integrity.py`.
"""

    tex = "\n".join([
        "% Generated " + TODAY + " by .stepcheck/discovery/verify_integrity.py from execution receipts.",
        "\\documentclass{article}", "\\usepackage{booktabs}", "\\usepackage[margin=1in]{geometry}",
        "\\title{StepCheck: a deterministic context firewall and gated state engine for AI coding agents}",
        "\\begin{document}", "\\maketitle",
        "\\begin{abstract}", tex_escape(
            f"Long agent sessions degrade in two coupled ways: the context re-read every turn grows until attention over it decays, and silent omissions pass the tests the agent still runs. StepCheck interposes a deterministic kernel between agent and model: modules are compiled into OKF frames, checked out as AST skeletons with a chosen focus, and modified only through patches that must pass three gates before a DSSE attestation lands. We evaluate on {corpus_pkgs} installed packages ({corpus_files} files, {corpus_loc} LOC) and on the kernel's own repository; the 50-turn benchmark sends {bench_comp} tokens where a raw agent sends {bench_raw} ({bench_pct} saved)."),
        "\\end{abstract}",
        "\\section{Evaluation}", tables_tex["paper_eval"], tables_tex["tokens"], tables_tex["latency"], tables_tex["patterns"], tables_tex["fuzz"],
        tables_tex["hooks"], tables_tex["audit"], tables_tex["arbitrage"], tables_tex["shield"], tables_tex["assets"],
        "\\section{Reproducibility}", tex_escape(f"python -m pytest -q ({full_passed} passed); stepcheck ci . ({ci_modules} modules verified); the discovery scripts under .stepcheck/discovery/."),
        "\\end{document}", "",
    ])

    war = f"""<!-- generated:start (verify_integrity.py, {TODAY}; do not edit by hand) -->
## Campaign facts (generated from receipts)

| Fact | Value | Receipt |
| --- | --- | --- |
| Corpus fault matrix | precision {pe_rows[0][1]}, recall {pe_rows[1][1]}, FPR {pe_rows[2][1]} | `.stepcheck/paper_eval/results/table3_faults.json` |
| Tests | {full_passed} passed; `stepcheck ci` {ci_modules} modules | `receipts/pytest_full.json`, `receipts/ci_output.json` |
| Re-derived audit | {au_rows[0][2]} sessions, {au_rows[1][2]} turns, {au_rows[2][2]} cache-cliff turns, {au_rows[4][2]} above cache-read | `receipts/track3_market.json` |
| Hook-enforced skeletons | {denied_saved} fewer tokens than raw Reads of the same modules | `receipts/track2_product.json` |
| Method slicing | {agg_saving} aggregate saving vs class focus over {classes_measured} classes | `receipts/track1_engine.json` |
| Trace hook under mutual recursion | hook changed = {hook_changed}; budget still enforced = {second_enforced} | `receipts/track1_engine.json` |
| Slice 16 | {dog_commits} gated commits, {green_p} Green tests | `receipts/dogfood_slice16.json`, `receipts/pytest_green.json` |
<!-- generated:end -->"""
    return {"novel": novel, "paper_md": paper_md, "paper_tex": tex, "war": war}


# ------------------------------------------- v0.2 campaign (Slices 17–20)

OPTIONAL = {
    "pytest_red_17_20": "pytest_red_slice17_20.json", "pytest_green_17_20": "pytest_green_slice17_20.json",
    "dogfood_17_20": "dogfood_slice17_20.json", "docs_sync": "docs_sync.json", "repo_sync": "repo_sync.json",
    "track3_v2": "track3_market_v2.json", "track3_v3": "track3_market_v3.json",
    "pytest_red_21_25": "pytest_red_slice21_25.json", "pytest_green_21_25": "pytest_green_slice21_25.json",
    "dogfood_21_25": "dogfood_slice21_25.json", "journeys": "overnight_user_journeys.json",
    "fuzzer": "overnight_fuzzer.json", "tiers": "commercial_tiers.json",
    "pytest_red_v031": "pytest_red_v031.json", "pytest_green_v031": "pytest_green_v031.json", "dogfood_v031": "dogfood_v031.json",
    "pytest_red_v031_hook": "pytest_red_v031_hook.json", "pytest_green_v031_hook": "pytest_green_v031_hook.json",
    "enterprise_scale": "enterprise_scale.json", "nbs_audit": "not_benchmark_shaped_audit.json",
}
for _n in range(17, 26):
    for _lab in ("before", "after"):
        OPTIONAL[f"slice{_n}_{_lab}"] = f"slice{_n}_metrics_{_lab}.json"
CAMPAIGNS = [("17_20", "v0.2 production-readiness campaign (Slices 17–20)", (17, 18, 19, 20), 8),
             ("21_25", "v0.3 overnight campaign (Slices 21–25)", (21, 22, 23, 24, 25), 9),
             ("v031", "Privacy fixes release (whole-token leak check, abbreviated audit paths)", (), 10),
             ("v031_hook", "Hook cost fix (a locked-node rejection no longer re-renders the project)", (), 11)]


def build_enterprise(L: Ledger) -> dict[str, str]:
    """Section 7: the Slice 35 -> 36 -> 37 enterprise-scale table (every cell is the receipt's
    own string) and the zero-trust audit of those slices (fault sensitivity on monoliths,
    bisimulation of the incremental path against a cold one, out-of-distribution trees)."""
    d = L.data
    if "enterprise_scale" not in d:
        return {"md": "", "tex": ""}
    g = L.get
    es = d["enterprise_scale"]
    n_labels = len(es["labels"])
    heads = ["Measurement"] + [g("enterprise_scale", ["labels", i], "str") for i in range(n_labels)]
    rows = [[g("enterprise_scale", ["table", i, j], "str") for j in range(len(row))] for i, row in enumerate(es["table"])]
    md = ["## 7. Enterprise monorepo scaling (Slices 35 → 36 → 37)", "",
          "Measured by `.stepcheck/discovery/benchmark_enterprise_scale.py` on the fifteen largest cached modules, "
          "the `django/` package, the full django tree, a noise tree and the resilience cases; one column per slice "
          "(receipt `receipts/enterprise_scale.json`). The last column's run times `init_session` without tracemalloc "
          "attached; the earlier columns carry its overhead. `stepcheck ci` is timed twice in the benchmark process, "
          "after the hook probes; a fresh process measures the package at the warm figure.", "",
          md_table(heads, rows), ""]
    tex = [tex_table(heads, rows, "Enterprise-scale measurements per slice (receipt strings).", "tab:enterprise")]
    if "nbs_audit" in d:
        a = d["nbs_audit"]
        md += ["### 7.1 Zero-trust audit of Slices 35–37", "",
               f"`audit_not_benchmark_shaped.py` (receipt `receipts/not_benchmark_shaped_audit.json`) diffed `backend/` against "
               f"{g('nbs_audit', ['base'], 'str')}: {g('nbs_audit', ['1_static_purity', 'added_lines'])} added lines, "
               f"{g('nbs_audit', ['1_static_purity', 'literal_hits_outside_tests'])} corpus-name literals outside tests, every one in a "
               f"docstring or comment (the receipt lists each with its line). Every exclusion pattern and gate exemption is printed verbatim in the receipt.", ""]
        f_rows = []
        for kind in ("guard_drop", "relational_flip", "action_neuter", "stub_wipe"):
            f_rows.append([kind.replace("_", " "),
                           g("nbs_audit", ["2_fault_injection", "by_fault", kind, "blocked"]) + " / " + g("nbs_audit", ["2_fault_injection", "by_fault", kind, "n"]),
                           g("nbs_audit", ["2_fault_injection", "by_fault", kind, "rate_pct"], "pct1"),
                           g("nbs_audit", ["2_fault_injection", "by_fault", kind, "latency_when_blocking", "p50"], "ms1"),
                           g("nbs_audit", ["2_fault_injection", "by_fault", kind, "latency_when_blocking", "p95"], "ms1")])
        md += ["Fault injection in guarded functions at the top, middle and bottom of the monoliths, committed through the fast path "
               f"(stitched on {g('nbs_audit', ['2_fault_injection', 'stitched_path_used_pct'], 'pct1')} of commits): "
               f"{g('nbs_audit', ['2_fault_injection', 'blocked'])} of {g('nbs_audit', ['2_fault_injection', 'faults_tested'])} blocked "
               f"({g('nbs_audit', ['2_fault_injection', 'catch_rate_pct'], 'pct1')}). The accepted faults are `return X` guards neutered to "
               "`return None`: the early return survives, the value does not, and a structural guard invariant does not see values.", "",
               md_table(["fault", "blocked", "rate", "p50 when blocking", "p95"], f_rows), "",
               f"Bisimulation over {g('nbs_audit', ['3_bisimulation', 'edits'])} edits (benign function, method, multi-function and "
               f"module-constant edits, every injected fault, SWE-bench gold patches): the fast path — stitched tree, segment reuse, "
               f"memory and disk cache — against a cold path with every memo cleared and no stitched tree, against a from-scratch analysis "
               f"of the edited text, and against Gate C with every probe in scope: "
               f"{g('nbs_audit', ['3_bisimulation', 'divergences'])} divergence(s) in verdict, gate or invariant set.", ""]
        o_rows = []
        for name in a["4_ood_repositories"]:
            r = a["4_ood_repositories"][name]
            p = ["4_ood_repositories", name]
            o_rows.append([name, g("nbs_audit", p + ["tracked_files"]), g("nbs_audit", p + ["loc"]),
                           g("nbs_audit", p + ["init_s"], "f2") + " s", "exit " + g("nbs_audit", p + ["ci", "exit"]) + " in " + g("nbs_audit", p + ["ci", "seconds"], "f2") + " s",
                           g("nbs_audit", p + ["hook_edit_ms", "p50"], "ms1") if r.get("hook_edit_ms") else "n/a",
                           g("nbs_audit", p + ["fault_catch_rate_pct"], "pct1") if r.get("fault_catch_rate_pct") is not None else "n/a"])
        md += ["Zero-shot trees never referenced by the benchmark (fastapi, tornado and scrapy as fresh shallow clones; the Martian "
               "online tree, Python and Rust). The two `stepcheck ci` failures are real broken imports in those trees "
               "(`maint/test/redbot/red_test.py` imports a symbol tornado removed; `etl/main.py` imports a name its target lacks).", "",
               md_table(["tree", "files", "LOC", "cold init", "stepcheck ci", "hook Edit p50", "faults caught"], o_rows), ""]
        tex.append(tex_table(["fault", "blocked", "rate", "p50", "p95"], f_rows, "Monolith fault injection through the incremental path.", "tab:faults"))
        tex.append(tex_table(["tree", "files", "LOC", "init", "ci", "hook p50", "faults"], o_rows, "Zero-shot out-of-distribution trees.", "tab:ood"))
    return {"md": "\n".join(md), "tex": "\n".join(tex)}


def flatten(obj, prefix: list | None = None, depth: int = 0, out: list | None = None) -> list[tuple[list, float]]:
    """(path, value) for every numeric leaf up to 3 levels deep; lists and strings skipped."""
    out = [] if out is None else out
    prefix = prefix or []
    if isinstance(obj, dict) and depth <= 3:
        for k, v in obj.items():
            if isinstance(v, bool) or k in ("generated_at", "kernel_commit", "python_version"):
                continue
            if isinstance(v, (int, float)):
                out.append((prefix + [k], v))
            elif isinstance(v, dict):
                flatten(v, prefix + [k], depth + 1, out)
    return out


def kind_for(path: list, value) -> str:
    key = path[-1].lower()
    if "pct" in key or key.endswith("_percent") or "recall" in key or "saving" in key and isinstance(value, float) and value <= 100:
        return "pct1" if isinstance(value, float) else "int"
    if key.endswith("_ms") or "latency" in key or "p50" in key or "p95" in key or "p99" in key:
        return "ms1"
    if "usd" in key or key.startswith("$"):
        return "usd2"
    if isinstance(value, float):
        return "f2"
    return "int"


def build_campaign(L: Ledger, tag: str, title: str, slices: tuple, section: int) -> tuple[list[str], list[str]]:
    d = L.data
    g = L.get
    md: list[str] = [f"## {section}. {title}", ""]
    tex: list[str] = []
    red, green, dog = f"pytest_red_{tag}", f"pytest_green_{tag}", f"dogfood_{tag}"
    if red in d:
        md.append(f"Red receipt over the new test modules on the unpatched tree: {g(red, ['counts', 'failed'])} failed, "
                  f"{g(red, ['counts', 'passed'])} passed, {g(red, ['counts', 'timeout'])} timed out.")
    if green in d:
        md.append(f"Green receipt after landing: {g(green, ['counts', 'passed'])} passed, "
                  f"{g(green, ['counts', 'failed'])} failed, {g(green, ['counts', 'timeout'])} timed out.")
    if dog in d:
        rows = []
        for i, s in enumerate(d[dog]["slices"]):
            rows.append([s["slice"], L.computed_value(f"{dog}.{s['slice']}.commits", lambda x, i=i, k=dog: sum(1 for c in x[k]["slices"][i]["commits"] if c["accepted"]), "int"),
                         L.computed_value(f"{dog}.{s['slice']}.new", lambda x, i=i, k=dog: sum(1 for c in x[k]["slices"][i]["attested_new_modules"] if c.get("accepted")), "int"),
                         L.computed_value(f"{dog}.{s['slice']}.reverified", lambda x, i=i, k=dog: len(x[k]["slices"][i]["reverified"]), "int"),
                         "yes" if s["ok"] and s["omission_risks"]["can_finalize"] else "no",
                         g(dog, ["slices", i, "telemetry", "tokens_saved"])])
        t = md_table(["slice", "gated commits", "new modules attested", "dependents re-verified", "finalized", "session tokens saved"], rows)
        md += ["", f"### {section}.1 Dogfooding through the gates", "", t, ""]
        tex.append(tex_table(["slice", "commits", "new", "re-verified", "finalized", "tokens saved"], rows, f"{title}: landed through StepCheck's own gates.", f"tab:dogfood{tag}"))
    for j, n in enumerate(slices, start=2):
        after, before = d.get(f"slice{n}_after"), d.get(f"slice{n}_before")
        if not after:
            continue
        rows = []
        for path, value in flatten(after):
            kind = kind_for(path, value)
            cell_after = g(f"slice{n}_after", path, kind)
            cell_before = "—"
            if before:
                try:
                    walk(before, path)
                    cell_before = g(f"slice{n}_before", path, kind)
                except (KeyError, TypeError):
                    pass
            rows.append([".".join(str(p) for p in path), cell_before, cell_after])
        md += [f"### {section}.{j} Slice {n} metrics (before → after)", "", md_table(["metric", "before", "after"], rows), ""]
        tex.append(tex_table(["metric", "before", "after"], rows, f"Slice {n}: receipts before and after landing.", f"tab:slice{n}"))
    return md, tex


def build_v02(L: Ledger) -> dict[str, str]:
    d = L.data
    g = L.get
    md: list[str] = []
    tex: list[str] = []
    for tag, title, slices, section in CAMPAIGNS:
        if not any(k in d for k in (f"pytest_red_{tag}", f"dogfood_{tag}")):
            continue
        m, t = build_campaign(L, tag, title, slices, section)
        md += m
        tex += t
    for key, heading in (("journeys", "Overnight user journeys"), ("fuzzer", "Overnight adversarial fuzzing")):
        if key in d:
            head = d[key].get("summary") or d[key].get("counts") or {}
            rows = [[".".join(str(p) for p in path), g(key, ["summary" if "summary" in d[key] else "counts"] + path, kind_for(path, value))]
                    for path, value in flatten(head)]
            if rows:
                md += [f"### {heading}", "", md_table(["figure", "value"], rows), ""]
    if "repo_sync" in d:
        rs = d["repo_sync"]
        md += ["### 8.6 Repository sync", "",
               f"Backend LOC {g('repo_sync', ['loc', 'total'])}; audit over {g('repo_sync', ['docs_audit', 'total', 'sessions'])} sessions, "
               f"{g('repo_sync', ['docs_audit', 'total', 'assistant_turns'])} assistant turns, {g('repo_sync', ['docs_audit', 'total', 'cache_gap_turns'])} cache-cliff turns, "
               f"{g('repo_sync', ['docs_audit', 'total', 'gap_rebilled_tokens'])} re-billed tokens, {g('repo_sync', ['docs_audit', 'total', 'gap_waste_usd'], 'usd2')} above cache-read.", ""]
    if "docs_sync" in d:
        md += [f"README / LAUNCH / CLAUDE.md / .cursorrules figures rewritten by `sync_docs.py` from receipts: "
               f"{L.computed_value('docs_sync.substitutions', lambda x: sum(s['matches'] for s in x['docs_sync']['substitutions']), 'int')} substitutions.", ""]
    for key, heading, label in (("track3_v2", "FinOps re-simulation v2 (compaction + rehydration + arbitrage)", "tab:finops2"),
                                ("track3_v3", "FinOps re-simulation v3 (real tool_result compaction + tiers)", "tab:finops3")):
        if key in d:
            v = d[key]
            root = "headline" if "headline" in v else ("summary_numbers" if "summary_numbers" in v else None)
            if root is None:
                continue
            rows = [[".".join(str(p) for p in path), g(key, [root] + path, kind_for(path, value))] for path, value in flatten(v[root])]
            if rows:
                md += [f"### {heading}", "", md_table(["figure", "value"], rows), ""]
                tex.append(tex_table(["figure", "value"], rows, heading + " on the real transcripts.", label))
    return {"md": "\n".join(md) + "\n", "tex": "\n".join(tex)}


def verify_docs_sync(fresh: dict) -> list[str]:
    """Every figure sync_docs.py wrote must still be in the file, and must equal the receipt it came from."""
    problems: list[str] = []
    ds = fresh.get("docs_sync")
    if not ds:
        return problems
    vals = ds["values"]
    expect = {"pytest_full.json:passed": str(vals["tests"]), "repo_sync.json:loc.total": f"{vals['loc_rounded']:,}",
              "repo_sync.json:audit.sessions": str(vals["audit"]["sessions"]), "repo_sync.json:audit.assistant_turns": f"{vals['audit']['assistant_turns']:,}",
              "repo_sync.json:audit.cache_gap_turns": str(vals["audit"]["cache_gap_turns"]), "repo_sync.json:audit.gap_rebilled_tokens": f"{vals['audit']['gap_rebilled_tokens']:,}",
              "repo_sync.json:audit.gap_waste_usd": f"{vals['audit']['gap_waste_usd']:.2f}"}
    if fresh["pytest_full"]["passed"] != vals["tests"]:
        problems.append(f"docs_sync test count {vals['tests']} != pytest_full {fresh['pytest_full']['passed']}")
    if "repo_sync" in fresh and fresh["repo_sync"]["loc"]["total"] != vals["loc"]:
        problems.append("docs_sync LOC differs from repo_sync.json")
    # LAUNCH.md's audit row must carry exactly the regenerated receipt's totals.
    if "repo_sync" in fresh:
        au = fresh["repo_sync"]["docs_audit"]["total"]
        launch = (REPO / "LAUNCH.md").read_text(encoding="utf-8")
        row = re.search(r"\| Real-log audit \| (.+?) \|", launch)
        want = [f"{au['sessions']} Claude Code sessions", f"{au['assistant_turns']:,} assistant turns",
                f"{au['cache_gap_turns']} cache-cliff resumes", f"{au['gap_rebilled_tokens']:,} tokens", f"${au['gap_waste_usd']:.2f} paid"]
        for w in want:
            if not row or w not in row.group(1):
                problems.append(f"LAUNCH.md audit row lacks {w!r} from repo_sync.json")
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        if f"{au['sessions']}-session audit receipt" not in readme:
            problems.append(f"README.md live link does not say {au['sessions']}-session audit receipt")
    for s in ds["substitutions"]:
        if not s["matches"]:
            continue
        text = (REPO / s["file"]).read_text(encoding="utf-8")
        repl = s["replacement"]
        if "\\" in repl:  # a back-reference: check the figure the source names
            needle = expect.get(s["source"], re.sub(r"\\(g<\d+>|\d)", "", repl))
        else:  # a literal replacement (e.g. "5.70M tokens"): it must still be there verbatim
            needle = repl
        if needle and needle not in text:
            problems.append(f"{s['file']}: synced text {needle!r} ({s['source']}) no longer present")
    return problems


WAR_ROOM_Q1_LANGUAGES = ("StepCheck's kernel indexes Python, TypeScript/JS, Go, Rust and Java (gated patches, "
                         "skeletons and guard conservation in all five; executable Gate C `call:` probes remain Python-only).")


def sync_war_room_replies(war: str, data: dict) -> tuple[str, list[str]]:
    """The hand-written HN replies carry campaign facts too. Q1's language concession is
    rewritten from the kernel's tracked suffixes (a fixed sentence, no figure) and Q2's
    cache-cliff figures from receipts/repo_sync.json, so nothing in them is typed by hand.
    Returns the rewritten text and the problems found (a figure that could not be placed)."""
    problems: list[str] = []
    if "repo_sync" not in data:
        return war, problems
    au = data["repo_sync"]["docs_audit"]["total"]
    tokens_m = f"{au['gap_rebilled_tokens'] / 1e6:.2f}M"
    subs = [
        ("Q1 language concession", r"StepCheck is Python-only\.|StepCheck's kernel indexes Python[^\n]*?Python-only\)\.", WAR_ROOM_Q1_LANGUAGES),
        ("Q2 cache-cliff turns and tokens", r"found [\d,]+ turns that resumed after the cache had expired and re-wrote [\d.]+M tokens",
         f"found {au['cache_gap_turns']} turns that resumed after the cache had expired and re-wrote {tokens_m} tokens"),
        ("Q2 dollars above cache-read", r"which is \$[\d.]+ above what cache-read pricing", f"which is ${au['gap_waste_usd']:.2f} above what cache-read pricing"),
        ("Q2 arithmetic", r"\([\d.]+M × \(\$3\.00 − \$0\.30\)/MTok", f"({tokens_m} × ($3.00 − $0.30)/MTok"),
        ("Q2 full-rate figure", r"the full-rate number would be \$[\d.]+", f"the full-rate number would be ${au['gap_rebilled_tokens'] * 3.0 / 1e6:.2f}"),
    ]
    for label, pattern, repl in subs:
        war, n = re.subn(pattern, lambda _m, r=repl: r, war)
        if n != 1:
            problems.append(f"HN-WAR-ROOM.md: {label} matched {n} times, expected 1")
    return war, problems


# ----------------------------------------------------------- verification

NON_METRIC_TOKENS = {
    TODAY: "generation date", "2026": "year in the date", "11": "month in the date", "03": "day in the date",
    "20261103": "hypothesis seed stated in the receipt", "50": "percentile / fault-matrix size labels", "80": "pass-rate column label",
    "95": "percentile / pass-rate label", "99": "percentile label", "1": "section numbers", "2": "section numbers",
    "3": "section numbers", "4": "section numbers", "5": "section numbers", "6": "section numbers", "7": "section numbers",
    "25": "team seat count assumption named in the receipt", "4.3": "AISVS control id", "9.3": "AISVS control id",
    "1in": "LaTeX margin", "16": "slice number",
}


def numeric_tokens(text: str, string_entries: list[str] = ()) -> list[str]:
    cleaned = "\n".join(ln for ln in text.splitlines() if not ln.startswith("#") and not ln.startswith("\\section"))  # headings: section numbers
    cleaned = re.sub(r"`[^`]*`", " ", cleaned)  # code spans carry paths and hashes, not metrics
    for s in string_entries:  # receipt strings quoted verbatim (error messages, headings)
        cleaned = cleaned.replace(s, " ").replace(tex_escape(s), " ")
    cleaned = re.sub(r"[0-9a-f]{12,}…?", " ", cleaned)  # sha256 prefixes
    cleaned = re.sub(r"\b[0-9a-f]{7}\b", " ", cleaned)  # git commit ids
    cleaned = re.sub(r"SHA-256|Statement v1|in-toto|PASS_TO_PASS|p50|p95|p99|seed \d+", " ", cleaned)
    cleaned = cleaned.replace("\\%", "%").replace("\\_", "_")
    # a digit glued to a letter is an identifier (sha256, v1, py3), not a metric
    return [t.rstrip(",.") for t in re.findall(r"(?<![A-Za-z0-9_])\$?\d[\d,]*(?:\.\d+)?%?", cleaned)]


def verify(L: Ledger, docs: dict[str, str], fresh: dict[str, dict]) -> list[str]:
    problems: list[str] = []
    fresh_ledger = Ledger(fresh)
    for e in L.entries:
        if e["source"] == "computed":
            fn, kind = L.computed[e["path"][0]]
            text = Ledger.fmt(fn(fresh), kind)
        else:
            text = Ledger.fmt(walk(fresh[e["source"]], e["path"]), e["kind"])
        if text != e["text"]:
            problems.append(f"ledger mismatch {e['source']}:{e['path']} generated {e['text']!r} recomputed {text!r}")
        if not any(e["text"] in doc or tex_escape(e["text"]) in doc for doc in docs.values()):
            problems.append(f"ledger text {e['text']!r} from {e['source']}:{e['path']} not found in any document")
    allowed = {e["text"] for e in L.entries} | set(NON_METRIC_TOKENS)
    allowed |= {t.replace(" ms", "") for t in allowed} | {t.lstrip("$") for t in allowed}
    allowed |= {t.lstrip("-") for t in allowed}  # a negative figure tokenizes without its sign
    strings = [e["text"] for e in L.entries if e["kind"] == "str"]
    for name, doc in docs.items():
        for tok in numeric_tokens(doc, strings):
            base = tok.rstrip("%").lstrip("$")
            if tok in allowed or base in allowed or tok + " ms" in allowed or "$" + tok in allowed:
                continue
            problems.append(f"{name}: numeric token {tok!r} is not backed by a ledger entry")
    return problems


def main() -> int:
    skip = "--skip-runs" in sys.argv
    run_and_record(skip)
    head = git_head()
    names = {
        "track1_engine": "track1_engine.json", "track2_product": "track2_product.json", "track3_market": "track3_market.json",
        "track4_gtm": "track4_gtm.json", "pre_fix_failures": "pre_fix_failures.json", "pytest_red": "pytest_red.json",
        "pytest_green": "pytest_green.json", "dogfood_slice16": "dogfood_slice16.json", "pytest_full": "pytest_full.json",
        "ci_output": "ci_output.json",
    }
    def load_all() -> dict[str, dict]:
        data = {k: load_json(v) for k, v in names.items()}
        data["paper_eval_table3"] = json.loads((REPO / ".stepcheck" / "paper_eval" / "results" / "table3_faults.json").read_text(encoding="utf-8"))
        data["benchmark"] = json.loads((REPO / "benchmarks" / "results.json").read_text(encoding="utf-8"))
        for k, v in OPTIONAL.items():
            if (R / v).exists():
                data[k] = load_json(v)
        return data
    data = load_all()
    L = Ledger(data)
    docs = build(L, head)
    extra = build_v02(L)
    docs["novel"] += "\n" + extra["md"]
    docs["paper_md"] += "\n## 5. v0.2 campaign results\n\n" + extra["md"].split("\n", 2)[2]
    docs["paper_tex"] = docs["paper_tex"].replace("\\section{Reproducibility}", extra["tex"] + "\n\\section{Reproducibility}")
    ent = build_enterprise(L)
    if ent["md"]:
        docs["novel"] += "\n" + ent["md"]
        docs["paper_md"] += "\n" + ent["md"]
        docs["paper_tex"] = docs["paper_tex"].replace("\\section{Reproducibility}", ent["tex"] + "\n\\section{Reproducibility}")
    (HERE / "NOVEL_SOLUTIONS_AND_BENCHMARKS.md").write_text(docs["novel"], encoding="utf-8")
    PAPER.mkdir(parents=True, exist_ok=True)
    (PAPER / "STEPCHECK_PAPER.md").write_text(docs["paper_md"], encoding="utf-8")
    (PAPER / "stepcheck_paper.tex").write_text(docs["paper_tex"], encoding="utf-8")
    war = WAR_ROOM.read_text(encoding="utf-8") if WAR_ROOM.exists() else "# HN war room\n"
    if "<!-- generated:start" in war:
        war = re.sub(r"<!-- generated:start.*?<!-- generated:end -->", lambda _m: docs["war"], war, flags=re.S)
    else:
        war = war.rstrip("\n") + "\n\n" + docs["war"] + "\n"
    war, war_problems = sync_war_room_replies(war, data)
    WAR_ROOM.write_text(war, encoding="utf-8")
    (HERE / "ledger.json").write_text(json.dumps(L.entries, indent=1), encoding="utf-8")

    fresh = load_all()
    problems = verify(L, docs, fresh) + verify_docs_sync(fresh) + war_problems
    full, ci = data["pytest_full"], data["ci_output"]
    for tag, title, _slices, _sec in CAMPAIGNS:
        green, dog = f"pytest_green_{tag}", f"dogfood_{tag}"
        if green in data and (data[green]["counts"]["failed"] or data[green]["counts"]["timeout"]):
            problems.append(f"{title}: Green receipt has failures or timeouts")
        if dog in data and not data[dog].get("all_ok"):
            problems.append(f"{title}: a gated commit was rejected or a session could not finalize")
    if full["returncode"] != 0 or not full["passed"]:
        problems.append(f"pytest exit {full['returncode']} passed={full['passed']}")
    if ci["returncode"] != 0 or ci["verdict"] != "PASS":
        problems.append(f"stepcheck ci exit {ci['returncode']} verdict={ci['verdict']}")
    if not data["dogfood_slice16"]["all_accepted"] or data["dogfood_slice16"]["omission_risks"]["dirty"]:
        problems.append("dogfood receipt: not every gated commit was accepted or dirty nodes remain")
    if data["pytest_green"]["counts"]["failed"] or data["pytest_green"]["counts"]["timeout"]:
        problems.append("Green receipt has failures or timeouts")
    summary = {"ledger_entries": len(L.entries), "documents": list(docs), "pytest_passed": full["passed"], "ci_modules": ci["modules_verified"], "problems": problems}
    (HERE / "integrity_summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "problems"}))
    for p in problems:
        print("PROBLEM:", p)
    print("ZERO-HALLUCINATION INTEGRITY AUDIT:", "PASS" if not problems else "FAIL")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
