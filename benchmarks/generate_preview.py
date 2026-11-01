"""Build stepcheck-studio-preview.html: a zero-dependency, self-contained replay
of the real 50-turn benchmark (benchmarks/results.json) in the Studio's
four-pane layout — scrub turns, jump to the gate catches, read the patch diff,
attestation and preserved_symbols, follow the cost curve.

Run after coding_rot_benchmark.py:  python3 benchmarks/generate_preview.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = json.loads((ROOT / "benchmarks" / "results.json").read_text(encoding="utf-8"))

CSS = r"""
:root{--well:#0e1116;--pane:#151a21;--pane2:#1a212b;--line:#232b35;--ink:#d7dee7;--dim:#8a96a5;--faint:#5a6572;
--ok:#3fb87f;--act:#4c8dff;--dirty:#e0a33b;--bad:#e25d5d;--mono:ui-monospace,"Cascadia Code","JetBrains Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}html,body{margin:0;background:var(--well);color:var(--ink);font:14px/1.45 "Segoe UI","Helvetica Neue",Arial,system-ui,sans-serif;-webkit-text-size-adjust:100%}
button{font:inherit;color:inherit;background:none;border:0;cursor:pointer}
header{display:flex;flex-wrap:wrap;gap:6px 18px;align-items:center;padding:9px 14px;border-bottom:1px solid var(--line);background:var(--pane);font-size:13px}
header .brand{font-weight:600;letter-spacing:-.01em}
header .k{color:var(--dim)}header .v{font-family:var(--mono);color:var(--ink)}
header .save{margin-left:auto;font-family:var(--mono);font-weight:600;font-size:15px;color:var(--ok);font-variant-numeric:tabular-nums}
.scrub{display:grid;grid-template-columns:auto 1fr;gap:10px 14px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line);background:var(--well)}
.scrub .tl{font-family:var(--mono);font-size:13px;white-space:nowrap}
.scrub input[type=range]{width:100%;accent-color:var(--act);height:28px}
.pills{grid-column:1/-1;display:flex;flex-wrap:wrap;gap:6px}
.pill{border:1px solid var(--line);border-radius:999px;padding:4px 11px;font-size:12px;color:var(--dim);background:var(--pane)}
.pill b{font-family:var(--mono);color:var(--ink);font-weight:600;margin-right:4px}
.pill.on{border-color:var(--c);color:var(--ink)}.pill:focus-visible{outline:2px solid var(--act);outline-offset:2px}
main{display:grid;grid-template-columns:320px minmax(0,1fr) 320px;min-height:calc(100vh - 150px)}
section{border-right:1px solid var(--line);background:var(--pane);min-width:0;display:flex;flex-direction:column}
section:last-child{border-right:0}
.ph{padding:7px 12px;border-bottom:1px solid var(--line);font-size:12px;color:var(--dim);display:flex;gap:8px;align-items:center}
.ph .r{margin-left:auto;font-family:var(--mono);color:var(--faint)}
svg{display:block;width:100%;height:auto}
#graph{background:var(--well)}
.node rect{fill:var(--pane2);stroke-width:1.5}.node text{font-family:var(--mono);font-size:12px;fill:var(--ink)}
.node .st{font-size:9.5px;font-family:inherit}.node.sel rect{stroke-width:3}
.edge{stroke:var(--line);stroke-width:1.5;fill:none}
.legend{display:flex;flex-wrap:wrap;gap:6px 12px;padding:8px 12px;border-top:1px solid var(--line);font-size:11px;color:var(--dim)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:-1px}
.verdict{margin:10px 12px;padding:10px 12px;border:1px solid var(--line);border-left:3px solid var(--c,var(--line));background:var(--well);font-size:12.5px}
.verdict b{font-family:var(--mono)}.verdict .sub{font-family:var(--mono);font-size:10.5px;color:var(--dirty)}
.diff{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--line);flex:1;min-height:0}
.diff>div{min-width:0;display:flex;flex-direction:column}
.diff pre{margin:0;flex:1;padding:10px 12px;background:var(--well);font:12px/1.5 var(--mono);overflow:auto;white-space:pre;min-height:120px;max-height:46vh}
.diff .lbl{font-size:11px;color:var(--faint);padding:5px 12px;background:var(--pane)}
.ln{display:block}.ln.add{background:#3fb87f1f;color:#9fe0bf}.ln.del{background:#e25d5d22;color:#f1a3a3;text-decoration:line-through}
.meta{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--line);border-top:1px solid var(--line)}
.meta>div{background:var(--pane);padding:10px 12px;font:12px/1.5 var(--mono);overflow:auto}
.meta .t{color:var(--dim);font-family:inherit;margin-bottom:4px}
.chip{display:inline-block;border:1px solid var(--line);border-radius:3px;padding:1px 6px;margin:2px 3px 2px 0;font-size:11px;color:var(--ink)}
.chip.gone{border-color:var(--bad);color:#f1a3a3;text-decoration:line-through}
.badge{display:inline-block;font:10px/1.4 var(--mono);border:1px solid var(--act);color:var(--act);border-radius:3px;padding:0 5px;margin-right:6px;vertical-align:1px}
.badge.man{border-color:var(--faint);color:var(--dim)}
.invl{margin:3px 0;word-break:break-all}.invl code{font:11.5px var(--mono);color:var(--ink)}.invl.hit code{color:var(--act);text-decoration:underline}
.sha{word-break:break-all;color:var(--ok)}.dimt{color:var(--faint)}
ul.feed{list-style:none;margin:0;padding:0;overflow:auto;flex:1;max-height:38vh}
.feed li{padding:8px 12px;border-bottom:1px solid var(--line);font-size:12px}
.feed li .n{font-family:var(--mono)}.feed li .t{float:right;font-family:var(--mono);font-size:10px;color:var(--faint)}
.feed li.cur{background:var(--pane2)}
.curve{padding:8px 12px;border-top:1px solid var(--line)}
.curve .lg{display:flex;gap:14px;font-size:11px;margin-top:4px}.curve .lg span::before{content:"";display:inline-block;width:12px;height:2px;vertical-align:middle;margin-right:5px;background:var(--c)}
@media (max-width:960px){main{grid-template-columns:1fr}section{border-right:0;border-bottom:1px solid var(--line)}.diff pre{max-height:32vh}header .save{margin-left:0;width:100%}}
@media (max-width:560px){.diff{grid-template-columns:1fr}.meta{grid-template-columns:1fr}.scrub{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
"""

JS = r"""
const R = JSON.parse(document.getElementById('data').textContent);
const T = R.turns, N = T.length;
const COLOR = {LOCKED:'var(--ok)',VERIFIED:'var(--ok)',ACTIVE:'var(--act)',DIRTY_OMISSION_RISK:'var(--dirty)',REJECTED:'var(--bad)'};
const LABEL = {LOCKED:'verified & locked',VERIFIED:'verified',ACTIVE:'active',DIRTY_OMISSION_RISK:'dirty / omission risk',REJECTED:'rejected'};
const GATE = {A:'Gate A · mechanical / locked',B:'Gate B · omission',C:'Gate C · logical invariant'};
const $ = (id) => document.getElementById(id);
const fmt = new Intl.NumberFormat('en-US');
const esc = (s) => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

// --- graph layout: depth = longest path to a leaf dependency (deps drawn above)
const nodes = Object.keys(R.initial_sources);
const deps = {}; nodes.forEach(n => deps[n] = R.edges.filter(e => e.source === n).map(e => e.target));
const depth = {}; const d = (n, seen=new Set()) => { if (depth[n] != null) return depth[n]; if (seen.has(n)) return 0; seen.add(n);
  const v = deps[n].length ? 1 + Math.max(...deps[n].map(x => d(x, seen))) : 0; depth[n] = v; return v; };
nodes.forEach(n => d(n));
const rows = {}; nodes.forEach(n => (rows[depth[n]] ||= []).push(n));
const W = 300, NW = 118, NH = 40, GY = 78;
const pos = {}; Object.keys(rows).sort((a,b)=>a-b).forEach(r => { const ids = rows[r].sort(); const gap = W / ids.length;
  ids.forEach((id, i) => pos[id] = {x: gap*(i+.5) - NW/2, y: 18 + r*GY}); });
const H = 18 + (Math.max(...Object.keys(rows).map(Number))+1)*GY;

function graphSvg(turn) {
  const t = T[turn-1]; const st = {...t.statuses}; if (!t.accepted) st[t.node] = 'REJECTED';
  let s = `<svg id="graph" viewBox="0 0 ${W} ${H}" role="img" aria-label="OKF dependency graph at turn ${turn}">`;
  for (const e of R.edges) { const a = pos[e.source], b = pos[e.target];
    const dirty = st[e.source] === 'DIRTY_OMISSION_RISK';
    s += `<path class="edge" ${dirty?'stroke="var(--dirty)" stroke-dasharray="4 3"':''} d="M${a.x+NW/2},${a.y} C${a.x+NW/2},${(a.y+b.y+NH)/2} ${b.x+NW/2},${(a.y+b.y+NH)/2} ${b.x+NW/2},${b.y+NH}"/>`; }
  for (const n of nodes) { const p = pos[n], c = COLOR[st[n]], sel = n === t.node;
    s += `<g class="node${sel?' sel':''}" style="--c:${c}"><rect x="${p.x}" y="${p.y}" width="${NW}" height="${NH}" rx="4" stroke="${c}"/>
      <text x="${p.x+9}" y="${p.y+16}">${t.locked.includes(n)?'🔒 ':''}${n}</text>
      <text class="st" x="${p.x+9}" y="${p.y+30}" fill="${c}">${LABEL[st[n]]}</text></g>`; }
  return s + '</svg>';
}

// --- line diff (LCS) for the before/after panes
function lineDiff(a, b) { const A = a.split('\n'), B = b.split('\n'); if (A.length===1 && A[0]==='') A.length = 0;
  const m = A.length, n = B.length, L = Array.from({length:m+1}, () => new Array(n+1).fill(0));
  for (let i=m-1;i>=0;i--) for (let j=n-1;j>=0;j--) L[i][j] = A[i]===B[j] ? L[i+1][j+1]+1 : Math.max(L[i+1][j], L[i][j+1]);
  const left = [], right = []; let i=0, j=0;
  while (i<m && j<n) { if (A[i]===B[j]) { left.push(['',A[i]]); right.push(['',B[j]]); i++; j++; }
    else if (L[i+1][j] >= L[i][j+1]) { left.push(['del',A[i++]]); } else { right.push(['add',B[j++]]); } }
  while (i<m) left.push(['del',A[i++]]); while (j<n) right.push(['add',B[j++]]);
  const render = rows => rows.map(([k,l]) => `<span class="ln ${k}">${esc(l)||' '}</span>`).join('');
  return [render(left), render(right)];
}

function curveSvg(turn) {
  const W = 300, H = 150, pl = 44, pr = 10, pt = 10, pb = 22, mx = Math.max(...T.map(t => t.raw));
  const xs = i => pl + i/(N-1)*(W-pl-pr), ys = v => H-pb - v/mx*(H-pt-pb);
  const line = k => T.map((t,i) => `${xs(i).toFixed(1)},${ys(t[k]).toFixed(1)}`).join(' ');
  let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Cumulative tokens: raw vs StepCheck">`;
  for (const f of [0,.5,1]) { const y = H-pb - f*(H-pt-pb); s += `<line x1="${pl}" x2="${W-pr}" y1="${y}" y2="${y}" stroke="var(--line)"/><text x="${pl-6}" y="${y+3.5}" text-anchor="end" font-size="9" fill="var(--faint)">${Math.round(mx*f/1000)}k</text>`; }
  for (const g of R.gate_events.filter(e => e.gate)) { const x = xs(g.turn-1); s += `<line x1="${x}" x2="${x}" y1="${pt}" y2="${H-pb}" stroke="var(--dirty)" stroke-dasharray="2 3"/>`; }
  s += `<polyline points="${line('raw')}" fill="none" stroke="var(--bad)" stroke-width="2"/><polyline points="${line('compacted')}" fill="none" stroke="var(--ok)" stroke-width="2"/>`;
  const i = turn-1, x = xs(i), t = T[i];
  s += `<line x1="${x}" x2="${x}" y1="${pt}" y2="${H-pb}" stroke="var(--ink)" stroke-width="1"/>
        <circle cx="${x}" cy="${ys(t.raw)}" r="3.5" fill="var(--bad)"/><circle cx="${x}" cy="${ys(t.compacted)}" r="3.5" fill="var(--ok)"/>
        <text x="${x}" y="${H-6}" text-anchor="middle" font-size="9.5" fill="var(--ink)" font-family="var(--mono)">T${turn}</text>`;
  return s + '</svg>';
}

function render(turn) {
  const t = T[turn-1], pct = Math.round((t.raw - t.compacted)/t.raw*100);
  $('turn').textContent = turn; $('raw').textContent = fmt.format(t.raw); $('cmp').textContent = fmt.format(t.compacted);
  $('pct').textContent = pct + '% pruned'; $('usd').textContent = '$' + t.dollars.toFixed(4) + ' saved'; $('om').textContent = t.omissions_blocked;
  $('range').value = turn; $('tl').textContent = `Turn ${String(turn).padStart(2,'0')} / ${N}`;
  document.querySelectorAll('.pill').forEach(p => p.classList.toggle('on', +p.dataset.turn === turn));
  $('graphWrap').innerHTML = graphSvg(turn);
  const op = t.patch[0];
  const c = t.accepted ? (t.dirtied.length ? 'var(--dirty)' : 'var(--ok)') : (t.gate==='B' ? 'var(--dirty)' : t.gate==='C' ? 'var(--act)' : 'var(--bad)');
  $('verdict').style.setProperty('--c', c);
  $('verdict').innerHTML = t.accepted
    ? `<b style="color:var(--ok)">✓ accepted</b> — <b>${t.node}</b> · ${op.op}${op.name?` <b>${op.name}</b>`:''} passed Gates A·B·C and was attested${t.dirtied.length?`<br><span style="color:var(--dirty)">INTER_NODE_DIRTY · exported signature changed → <b>${t.dirtied.join(', ')}</b> now DIRTY_OMISSION_RISK</span>${t.finalize_blocked?`<br><span class="dimt">finalize_session() refused mid-flight until both are checked out and re-verified</span>`:''}`:''}${(!t.dirtied.length && t.statuses && Object.values(t.statuses).includes('DIRTY_OMISSION_RISK')) ? `<br><span class="dimt">re-verified <b>${t.node}</b>; still dirty: ${Object.entries(t.statuses).filter(([,s])=>s==='DIRTY_OMISSION_RISK').map(([n])=>n).join(', ')}</span>` : ''}`
    : `<b style="color:${c}">✕ rejected at ${GATE[t.gate]}</b> — <b>${t.node}</b> · ${op.op}${op.name?` <b>${op.name}</b>`:''}<br>${t.subtype?`<span class="sub">${t.subtype}</span> `:''}${t.auto_mined_catch?`<span class="badge">auto-mined · zero config</span> `:''}<span style="color:var(--dim)">${esc(t.error)}</span>${t.recovered?`<br><span class="dimt">agent recovered the same turn with an ordinary growth patch</span>`:''}`;
  $('focus').textContent = t.focus.length ? `focus=[${t.focus.join(', ')}]` : 'focus=[] (pure skeleton)';
  $('ctk').textContent = `${t.checkout_tokens} tok checkout`;
  const [l, r] = lineDiff(t.before, t.after);
  $('before').innerHTML = l || '<span class="dimt">(append — nothing replaced; new symbol folded at end of module)</span>'; $('after').innerHTML = r;
  $('patch').textContent = JSON.stringify(t.patch.map(o => ({...o, code: `<${o.code.split('\n').length-1} lines>`})));
  const staged = new Set(); // symbols present in the staged code
  (t.after.match(/^@([\w.]+)/gm)||[]).forEach(m => staged.add(m)); (t.after.match(/^def (\w+)/gm)||[]).forEach(m => staged.add(m));
  $('ps').innerHTML = t.preserved_symbols.map(s => { const gone = !t.accepted && t.subtype==='INTRA_NODE_SYMBOL_DROPPED' && s.startsWith('@') && !staged.has(s);
    return `<span class="chip${gone?' gone':''}">${esc(s)}</span>`; }).join('');
  $('inv').innerHTML = (t.invariants||[]).length ? t.invariants.map(i => {
    const mined = (t.invariants_auto_mined||[]).includes(i), hit = !t.accepted && t.gate==='C' && (t.error||'').includes(i);
    return `<div class="invl${hit?' hit':''}">${mined?'<span class="badge">auto-mined</span>':'<span class="badge man">manual</span>'}<code>${esc(i)}</code></div>`; }).join('')
    : '<span class="dimt">none for this module</span>';
  const a = t.attestation;
  $('att').innerHTML = a ? `<div>payloadType: <span class="dimt">${a.payloadType}</span></div><div>turn: ${a.payload.turn} · node: ${a.payload.node_id}</div><div class="sha">sha256: ${a.payload.sha256}</div><div class="dimt">keyid: ${a.signatures[0].keyid}</div><div class="dimt" style="word-break:break-all">sig: ${a.signatures[0].sig}</div>`
    : `<span class="dimt">no attestation this turn — ${t.gate==='A'?'locked module, mutation refused':'commit rejected'}</span>`;
  $('feed').innerHTML = [...R.gate_events].filter(e => e.turn <= turn).reverse().map(e =>
    `<li class="${e.turn===turn?'cur':''}"><span class="t">T${e.turn}</span><span class="n">${e.node}</span> · ${e.propagation ? `<span style="color:var(--dirty)">Gate B · dirty propagation</span><br><span style="color:var(--dim)">${esc(e.error)}</span>` : e.gate ? `<span style="color:${e.gate==='B'?'var(--dirty)':e.gate==='C'?'var(--act)':'var(--bad)'}">${GATE[e.gate]}</span><br><span style="color:var(--dim)">${esc(e.subtype||e.error)}</span>` : `<span style="color:var(--ok)">${esc(e.event)}</span>`}</li>`).join('')
    || '<li class="dimt">no gate events yet</li>';
  $('curve').innerHTML = curveSvg(turn);
  history.replaceState(null, '', '#t' + turn);
}

let cur = Math.min(N, Math.max(1, parseInt((location.hash.match(/t(\d+)/)||[])[1]) || N));
$('range').max = N; $('range').addEventListener('input', e => render(cur = +e.target.value));
document.querySelectorAll('.pill').forEach(p => p.addEventListener('click', () => render(cur = +p.dataset.turn)));
document.addEventListener('keydown', e => { if (e.key==='ArrowRight' && cur<N) render(++cur); if (e.key==='ArrowLeft' && cur>1) render(--cur); });
render(cur);
"""


def main() -> None:
    f = RESULTS["final"]
    pills = [
        (1, "Start", "var(--act)"),
        (5, "core locked", "var(--ok)"),
        (20, "Gate B · @audit omission caught", "var(--dirty)"),
        (25, "Gate B · dirty propagation (api, workers)", "var(--dirty)"),
        (35, "Gate C · auto-mined guard invariant caught", "var(--act)"),
        (36, "Gate A · locked mutation blocked", "var(--bad)"),
        (50, "Final · {pct}% saved".format(pct=f["savings_pct"]), "var(--ok)"),
    ]
    pill_html = "".join(
        f'<button class="pill" data-turn="{t}" style="--c:{c}"><b>T{t}</b>{label}</button>'
        for t, label, c in pills
    )
    data = json.dumps(RESULTS, separators=(",", ":")).replace("</", "<\\/")
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="color-scheme" content="dark"/>
<title>StepCheck Studio — 50-turn replay</title>
<style>{CSS}</style></head>
<body>
<header>
  <span class="brand">⚡ StepCheck Studio</span><span class="k">replay</span>
  <span class="k">Turn <span class="v" id="turn">–</span></span>
  <span class="k">Raw <span class="v" id="raw">–</span> → Compacted <span class="v" id="cmp">–</span> tokens <span class="v" id="pct" style="color:var(--ok)">–</span></span>
  <span class="k">Omissions caught <span class="v" id="om" style="color:var(--dirty)">–</span></span>
  <span class="save" id="usd">–</span>
</header>
<div class="scrub">
  <span class="tl" id="tl">Turn –</span>
  <input id="range" type="range" min="1" max="50" value="50" aria-label="Turn scrubber"/>
  <div class="pills">{pill_html}</div>
</div>
<main>
  <section>
    <div class="ph">OKF dependency graph<span class="r">{len(RESULTS["modules"])} modules</span></div>
    <div id="graphWrap"></div>
    <div class="legend"><span><i style="background:var(--ok)"></i>verified / locked</span><span><i style="background:var(--act)"></i>active</span><span><i style="background:var(--dirty)"></i>dirty / omission risk</span><span><i style="background:var(--bad)"></i>rejected</span></div>
    <div class="verdict" id="verdict"></div>
  </section>
  <section>
    <div class="ph">Patch diff — before / after<span id="focus" style="font-family:var(--mono);color:var(--faint)"></span><span class="r" id="ctk"></span></div>
    <div class="diff"><div><div class="lbl">canonical (before)</div><pre id="before"></pre></div><div><div class="lbl">staged (after)</div><pre id="after"></pre></div></div>
    <div class="meta">
      <div><div class="t">preserved_symbols[]</div><div id="ps"></div><div class="t" style="margin-top:8px">invariants[]</div><div id="inv"></div><div class="t" style="margin-top:8px">patch</div><div id="patch" class="dimt" style="word-break:break-all"></div></div>
      <div><div class="t">folded DSSE attestation</div><div id="att"></div></div>
    </div>
  </section>
  <section>
    <div class="ph">3-tier gate feed</div>
    <ul class="feed" id="feed"></ul>
    <div class="curve"><div class="ph" style="border:0;padding:0 0 4px">Cumulative tokens — {fmt(f["raw_bloated_tokens"])} raw vs {fmt(f["compacted_okf_tokens"])} compacted</div>
      <div id="curve"></div>
      <div class="lg"><span style="--c:var(--bad)">raw re-read baseline</span><span style="--c:var(--ok)">StepCheck (focused checkouts + folded patches)</span></div></div>
  </section>
</main>
<script id="data" type="application/json">{data}</script>
<script>{JS}</script>
</body></html>"""
    out = ROOT / "stepcheck-studio-preview.html"
    out.write_text(html, encoding="utf-8")
    print(f"wrote {out} ({len(html)/1024:.0f} KB)")


def fmt(n: int) -> str:
    return f"{n:,}"


if __name__ == "__main__":
    main()
