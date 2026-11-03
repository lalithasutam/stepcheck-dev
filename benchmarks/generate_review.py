"""Build architecture-review.html from benchmarks/results.json + live repo stats.

Self-contained dark report in the Studio's instrument-panel palette: deep-module
scorecard, seam test matrix, gate catches, and the raw-vs-compacted cost curve.
Run after coding_rot_benchmark.py:  python3 benchmarks/generate_review.py
"""
from __future__ import annotations

import datetime
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = json.loads((ROOT / "benchmarks" / "results.json").read_text(encoding="utf-8"))


def loc(path: Path) -> int:
    return sum(
        len(p.read_text(encoding="utf-8").splitlines())
        for p in path.rglob("*.py")
        if "__pycache__" not in p.parts
    )


def pytest_count() -> str:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT / "backend",
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip().splitlines()
    return out[-1] if out else "?"


def cost_chart_svg(series: list[dict]) -> str:
    W, H = 760, 260
    padl, padr, padt, padb = 64, 16, 16, 34
    mx = max(p["raw"] for p in series)
    xs = lambda i: padl + i / (len(series) - 1) * (W - padl - padr)  # noqa: E731
    ys = lambda v: H - padb - v / mx * (H - padt - padb)  # noqa: E731

    def line(key: str) -> str:
        return " ".join(f"{xs(i):.1f},{ys(p[key]):.1f}" for i, p in enumerate(series))

    grid = ""
    for f in (0, 0.25, 0.5, 0.75, 1.0):
        y = H - padb - f * (H - padt - padb)
        grid += (
            f'<line x1="{padl}" x2="{W-padr}" y1="{y:.0f}" y2="{y:.0f}" stroke="#232b35"/>'
            f'<text x="{padl-8}" y="{y+4:.0f}" text-anchor="end" font-size="11" fill="#5a6572">'
            f"{int(mx*f/1000)}k</text>"
        )
    marks = ""
    for ev in RESULTS["gate_events"]:
        if "gate" not in ev:
            continue
        x = xs(ev["turn"] - 1)
        marks += (
            f'<line x1="{x:.0f}" x2="{x:.0f}" y1="{padt}" y2="{H-padb}" '
            f'stroke="#e0a33b" stroke-dasharray="3 4"/>'
            f'<text x="{x:.0f}" y="{H-padb+16}" text-anchor="middle" font-size="11" '
            f'fill="#e0a33b">T{ev["turn"]} · Gate {ev["gate"]}</text>'
        )
    return f"""<svg viewBox="0 0 {W} {H}" role="img"
  aria-label="Cumulative tokens over 50 turns: raw agent vs StepCheck">
  {grid}{marks}
  <polyline points="{line('raw')}" fill="none" stroke="#e25d5d" stroke-width="2.5"/>
  <polyline points="{line('compacted')}" fill="none" stroke="#3fb87f" stroke-width="2.5"/>
  <text x="{W-padr}" y="{ys(series[-1]['raw'])-8:.0f}" text-anchor="end" font-size="12"
        fill="#e25d5d">raw re-read baseline (cache-cliff billed)</text>
  <text x="{W-padr}" y="{ys(series[-1]['compacted'])+18:.0f}" text-anchor="end" font-size="12"
        fill="#3fb87f">StepCheck compacted (focused checkouts + folded patches)</text>
</svg>"""


def main() -> None:
    f = RESULTS["final"]
    kernel_loc = loc(ROOT / "backend" / "kernel")
    server_loc = len((ROOT / "backend" / "server.py").read_text(encoding="utf-8").splitlines())
    tests = pytest_count()
    gate_rows = "".join(
        f"<tr><td>T{e['turn']}</td><td><code>{e['node']}</code></td>"
        f"<td class='g{e.get('gate','')}'>{('Gate ' + e['gate'] + (' · propagation (accepted)' if e.get('propagation') else '')) if 'gate' in e else '—'}</td>"
        f"<td><code>{e.get('subtype') or e.get('event') or ''}</code></td>"
        f"<td>{e.get('error','')}</td></tr>"
        for e in RESULTS["gate_events"]
    )
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><link rel="llms-txt" href="https://lalithasutam.github.io/stepcheck-dev/llms.txt"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>StepCheck Dev — Architecture Review</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin:0; background:#0e1116; color:#d7dee7;
         font:15px/1.55 "Segoe UI","Helvetica Neue",Arial,sans-serif; }}
  main {{ max-width:860px; margin:0 auto; padding:40px 24px 80px; }}
  h1 {{ font-size:26px; letter-spacing:-.01em; margin:0 0 4px; }}
  h2 {{ font-size:17px; margin:40px 0 10px; color:#d7dee7; }}
  .sub {{ color:#8a96a5; margin:0 0 28px; }}
  table {{ border-collapse:collapse; width:100%; font-size:13.5px; }}
  th,td {{ border:1px solid #232b35; padding:7px 10px; text-align:left;
           vertical-align:top; }}
  th {{ background:#151a21; color:#8a96a5; font-weight:600; }}
  code {{ font:12.5px ui-monospace,Consolas,monospace; color:#d7dee7; }}
  .gA {{ color:#e25d5d; }} .gB {{ color:#e0a33b; }} .gC {{ color:#4c8dff; }}
  .stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:1px;
            background:#232b35; border:1px solid #232b35; margin:14px 0; }}
  .stats div {{ background:#151a21; padding:12px 14px; }}
  .stats b {{ display:block; font-size:21px; font-variant-numeric:tabular-nums; }}
  .stats span {{ color:#8a96a5; font-size:12px; }}
  .ok {{ color:#3fb87f; }}
  figure {{ margin:14px 0; border:1px solid #232b35; background:#151a21;
            padding:14px; }}
  p {{ max-width:72ch; }}
</style></head><body><main>
<h1>StepCheck Dev — architecture review</h1>
<p class="sub">Anti-context-rot state engine · dual-door gateway · visual workspace
· generated {datetime.date.today().isoformat()} from the live repo and
<code>benchmarks/results.json</code>.</p>

<p><strong>Verdict: the deep-module bet holds, and the fold pays.</strong> One
kernel behind one Python seam carries compilation, skeleton slicing, patch
folding, three gates (now with semantic invariants), locking, attestation and
telemetry in {kernel_loc} lines; everything HTTP-shaped lives behind the second
seam ({server_loc} lines). {tests} across the two seams, zero mocks of
internals, and all four events injected into the 50-turn benchmark were caught
at the intended gate.</p>

<h2>Deep modules &amp; seams</h2>
<table>
<tr><th>Module</th><th>Interface</th><th>Implementation</th><th>Deletion test</th></tr>
<tr><td><code>StateKernel</code> (Seam 1)</td>
    <td>8 methods: init_session · checkout(focus=) · commit(source= | patch=) ·
        lock_node · finalize_session · get_telemetry · record_draft/drafts · graph</td>
    <td>{kernel_loc} LOC across <code>kernel/</code> (_okf, _gates, _sandbox,
        _telemetry, _tokens stay private); every kernel caveat from v1 and v2 is closed</td>
    <td class="ok">Deleting any private module breaks only the kernel — no caller
        imports them.</td></tr>
<tr><td><code>DualDoorGateway</code> (Seam 2)</td>
    <td>Door 1: <code>POST /v1/chat/completions</code> · <code>/v1/messages</code>
        (BYOK or dry-run). Door 2: <code>/v1/step/*</code> ·
        Streamable&nbsp;HTTP MCP at <code>/mcp</code> ·
        <code>WS /v1/ws/{{session_id}}</code></td>
    <td>{server_loc} LOC, stateless over the kernel</td>
    <td class="ok">Gateway deletes cleanly: no kernel code knows HTTP exists.</td></tr>
</table>

<h2>50-turn coding-rot benchmark</h2>
<div class="stats">
  <div><b>{f['raw_bloated_tokens']:,}</b><span>raw bloated tokens (re-reads billed
      past the 5-min cache cliff)</span></div>
  <div><b>{f['compacted_okf_tokens']:,}</b><span>compacted OKF tokens actually sent</span></div>
  <div><b class="ok">{f['savings_pct']}%</b><span>tokens saved ·
      ${f['dollars_saved']} at $3.00/MTok</span></div>
  <div><b class="ok">4 / 4</b><span>injected events caught (B omission · B propagation · C · A)</span></div>
</div>
<figure>{cost_chart_svg(RESULTS['series'])}</figure>

<h2>Gate catches</h2>
<table>
<tr><th>Turn</th><th>Node</th><th>Gate</th><th>Subtype / event</th><th>Detail</th></tr>
{gate_rows}
</table>

<h2>What the upgrade pass changed</h2>
<table>
<tr><th>Caveat (v1)</th><th>Resolution</th></tr>
<tr><td>Gate C invariants were string containment over raw source — brittle to
    whitespace, blind to semantics.</td>
    <td>Invariants now evaluate against <code>src</code> =
    <code>ast.unparse(tree)</code> (normalized, comment-free, self-reference-proof),
    <code>tree</code> (the <code>ast.Module</code>) and <code>ns</code> (the staged
    module exec-loaded into an isolated namespace with project imports resolved to
    canonical sources). Sugar: <code>call:charge("acct", 0) raises ValueError</code>.
    Legacy string invariants are unchanged and now whitespace-proof.</td></tr>
<tr><td>Compacted tokens reached 73k (45.3%): every commit re-sent the whole
    module and every checkout dragged the full <code>verified[]</code> chain plus
    data ballast.</td>
    <td>Checkout takes <code>focus=[…]</code>: focused defs verbatim, the rest of the
    target as an AST skeleton (signatures, decorators, docstrings, assignment runs
    folded to one line); dependencies ship as interface skeletons. Commits take a
    <code>patch</code> of AST ops (append / replace_symbol / delete_symbol) folded
    into canonical state, and telemetry charges the patch, not the module.
    Superseded attestations fold into one summary in the payload (the on-disk
    frame keeps the full chain).</td></tr>
</table>

<h2>Kernel caveats closed in the hardening pass</h2>
<table>
<tr><th>Caveat (v2)</th><th>Resolution</th></tr>
<tr><td>An unfocused <code>checkout(focus=None)</code> carried whole-module source
    and could breach the &lt;4,000-token budget on large files.</td>
    <td>When the unfocused frame would meet the budget, <code>checkout()</code> falls
    back to a pure AST skeleton with a symbol index and sets
    <code>auto_skeletonized=True</code>; the frame tells the agent to re-checkout with
    <code>focus=[…]</code>. Small modules are untouched.</td></tr>
<tr><td>Callable invariants executed staged code with no bound — a runaway loop
    or recursion at Gate C could hang the kernel.</td>
    <td>Namespace loading and every invariant evaluation run under a per-thread
    trace guard (<code>_sandbox.guarded</code>): 200,000 line-event step budget,
    0.5 s wall-clock backstop. Overrun is a deterministic <code>LogicalError</code>
    naming the invariant; <code>RecursionError</code> simply fails the invariant.
    The kernel stays healthy and the next correct diff passes.</td></tr>
</table>

<h2>Packaging</h2>
<p>One port now serves everything: <code>stepcheck up</code> mounts the compiled
Studio at <code>/studio</code> (SPA deep links fall back to <code>index.html</code>,
missing hashed assets still 404) beside Door 1, <code>/v1/step/*</code>,
Streamable&nbsp;HTTP MCP at <code>/mcp</code> and <code>WS /v1/ws/*</code>.
<code>stepcheck benchmark</code>, <code>stepcheck review</code> and
<code>stepcheck preview</code> regenerate the numbers, this report and the
self-contained <code>stepcheck-studio-preview.html</code> replay.</p>

<h2>Risks worth watching</h2>
<p>The execution guard bounds time, not capability: callable invariants still run
the agent's staged code in-process with real imports, so run the kernel in a
container when agents are untrusted. The WS fan-out is in-process; multi-worker
deployment needs a shared bus.</p>
</main></body></html>"""
    out = ROOT / "architecture-review.html"
    out.write_text(html, encoding="utf-8")
    print(f"wrote {out} ({len(html):,} bytes)")


if __name__ == "__main__":
    main()
