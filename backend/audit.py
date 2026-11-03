"""`stepcheck audit` — read real agent session logs and show what StepCheck
would have saved and blocked. Pure parsing + deterministic arithmetic; no LLM.

Input: Claude Code transcripts (`~/.claude/projects/<slug>/<session>.jsonl`),
one JSON object per line with `type` (user|assistant), `timestamp`, and
`message.content[]` blocks (`tool_use` / `tool_result`) plus `message.usage`
on assistant turns. Unknown shapes are skipped, never fatal.

Two questions, answered per session and in total:
  a) Cache-cliff waste — on assistant turns that start more than
     CACHE_CLIFF_SECONDS after the previous one, the prompt cache has expired
     and `cache_creation_input_tokens` is context re-written at full rate.
     Against that: what the agent pulled with the Read tool, and what the same
     files cost as AST skeleton checkouts.
  b) Regressions — Edit calls whose `old_string` carried a decorator or a
     leading `if …: raise` guard that `new_string` dropped, and the retry loop
     (further edits to the same file / failing tool results) that followed.
"""
from __future__ import annotations

import ast
import json
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from kernel import _okf, _telemetry

CACHE_CLIFF_SECONDS = _telemetry.CACHE_CLIFF_SECONDS
USD_FULL = _telemetry.USD_PER_MTOK_INPUT          # 3.00 / MTok input (conservative: cache *write* is 3.75)
USD_CACHE_READ = USD_FULL * _telemetry.CACHE_HIT_FRACTION
RETRY_WINDOW = 5  # assistant turns after a dropping edit in which later edits count as the retry loop

_DECORATOR_RE = re.compile(r"^\s*@([\w.]+)", re.M)
_GUARD_RE = re.compile(r"^\s*if\b[^\n]*:\s*\n\s+raise\s+(\w+)", re.M)
_NUMBERED_RE = re.compile(r"^\s*\d+→", re.M)  # Claude Code Read output: "     1→line"
_TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|spec)(/|$)|(^|/)(test_[^/]*|[^/]*_test|conftest)\.py$")


def _tokens(text: str) -> int:
    return math.ceil(len(text) / 4)


def _ts(row: dict) -> datetime | None:
    raw = row.get("timestamp")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def _blocks(row: dict) -> list[dict]:
    msg = row.get("message") or {}
    content = msg.get("content")
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    return [b for b in (content or []) if isinstance(b, dict)]


def _result_text(block: dict, row: dict | None = None) -> tuple[str, str]:
    """(text, kind) where kind is "text" | "image" | "empty". Prefers the raw
    file body Claude Code stores in the row-level `toolUseResult.file.content`
    over the line-numbered rendering inside the block."""
    tur = (row or {}).get("toolUseResult")
    if isinstance(tur, dict):
        if tur.get("type") == "image":
            return "", "image"
        f = tur.get("file")
        if isinstance(f, dict) and isinstance(f.get("content"), str):
            return f["content"], "text"
    c = block.get("content", "")
    if isinstance(c, list):
        if any(isinstance(x, dict) and x.get("type") == "image" for x in c):
            return "", "image"
        c = "\n".join(str(x.get("text", "")) for x in c if isinstance(x, dict))
    c = str(c)
    return c, ("text" if c else "empty")


def _skeleton_tokens(text: str) -> tuple[int, bool]:
    """(tokens of a focus=[] AST skeleton, exact?). Falls back to 25% when the
    text is not parseable Python."""
    src = _NUMBERED_RE.sub("", text)
    try:
        return _tokens(_okf.skeleton(src, [])), True
    except (SyntaxError, ValueError):
        return math.ceil(_tokens(text) * 0.25), False


@dataclass
class Regression:
    turn: int
    file: str
    kind: str          # "decorator" | "guard"
    symbol: str
    retries: int = 0
    failing_results: int = 0
    turns_to_recover: int | None = None


@dataclass
class SessionAudit:
    path: str
    session_id: str | None
    assistant_turns: int = 0
    billed_input_tokens: int = 0            # input + cache_creation across all turns
    cache_read_tokens: int = 0
    cache_gap_turns: list[int] = field(default_factory=list)
    gap_rebilled_tokens: int = 0            # cache_creation on gap turns
    gap_waste_usd: float = 0.0
    read_calls: int = 0
    image_reads: int = 0                    # screenshots etc. — no code to skeletonize
    read_tokens: int = 0
    skeleton_tokens: int = 0
    skeleton_exact: bool = True
    read_saving_usd: float = 0.0
    regressions: list[Regression] = field(default_factory=list)
    ignored_test_edits: list[Regression] = field(default_factory=list)

    @property
    def retry_turns(self) -> int:
        return sum(r.retries for r in self.regressions)


def audit_session(path: Path) -> SessionAudit:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    out = SessionAudit(path=str(path), session_id=next((r.get("sessionId") for r in rows if r.get("sessionId")), None))
    results: dict[str, tuple[str, bool, str]] = {}  # id -> (text, is_error, kind)
    for r in rows:
        for b in _blocks(r):
            if b.get("type") == "tool_result" and b.get("tool_use_id"):
                text, kind = _result_text(b, r)
                results[b["tool_use_id"]] = (text, bool(b.get("is_error")), kind)

    assistants = [r for r in rows if r.get("type") == "assistant" or (r.get("message") or {}).get("role") == "assistant"]
    out.assistant_turns = len(assistants)
    prev_ts: datetime | None = None
    edits_by_turn: list[tuple[int, str, dict]] = []  # (turn, file, input)

    for i, r in enumerate(assistants, start=1):
        usage = (r.get("message") or {}).get("usage") or {}
        inp = int(usage.get("input_tokens") or 0)
        created = int(usage.get("cache_creation_input_tokens") or 0)
        read = int(usage.get("cache_read_input_tokens") or 0)
        out.billed_input_tokens += inp + created
        out.cache_read_tokens += read

        ts = _ts(r)
        if ts and prev_ts and (ts - prev_ts).total_seconds() > CACHE_CLIFF_SECONDS:
            out.cache_gap_turns.append(i)
            out.gap_rebilled_tokens += created
        if ts:
            prev_ts = ts

        for b in _blocks(r):
            if b.get("type") != "tool_use":
                continue
            name, tool_input = b.get("name"), b.get("input") or {}
            if name == "Read":
                text, _, kind = results.get(b.get("id", ""), ("", False, "empty"))
                if kind == "image":
                    out.image_reads += 1
                    continue
                out.read_calls += 1
                if text:
                    rt = _tokens(text)
                    st, exact = _skeleton_tokens(text)
                    out.read_tokens += rt
                    out.skeleton_tokens += st
                    out.skeleton_exact &= exact
            elif name in ("Edit", "MultiEdit") and "old_string" in tool_input:
                edits_by_turn.append((i, str(tool_input.get("file_path", "?")), tool_input))
            elif name == "Write":
                edits_by_turn.append((i, str(tool_input.get("file_path", "?")), tool_input))

    # Regressions: a dropped decorator / guard, then the retry loop after it.
    for idx, (turn, file, inp) in enumerate(edits_by_turn):
        old, new = str(inp.get("old_string", "")), str(inp.get("new_string", ""))
        if not old:
            continue
        dropped: list[tuple[str, str]] = []
        for m in _DECORATOR_RE.finditer(old):
            if f"@{m.group(1)}" not in new:
                dropped.append(("decorator", f"@{m.group(1)}"))
        for m in _GUARD_RE.finditer(old):
            if not _GUARD_RE.search(new):
                dropped.append(("guard", f"if …: raise {m.group(1)}"))
        for kind, sym in dropped:
            reg = Regression(turn=turn, file=file, kind=kind, symbol=sym)
            later = [(t, f) for (t, f, _) in edits_by_turn[idx + 1:] if f == file and t - turn <= RETRY_WINDOW]
            reg.retries = len(later)
            if later:
                reg.turns_to_recover = later[-1][0] - turn
            # failing tool results between the drop and the last retry
            window_end = later[-1][0] if later else turn + RETRY_WINDOW
            for r2 in assistants[turn - 1: window_end]:
                for b in _blocks(r2):
                    if b.get("type") == "tool_use":
                        _, err, _ = results.get(b.get("id", ""), ("", False, "empty"))
                        reg.failing_results += int(err)
            out.regressions.append(reg)
    # Test files are where guards get edited on purpose; keep them out of the headline.
    out.ignored_test_edits = [r for r in out.regressions if _TEST_PATH_RE.search(r.file)]
    out.regressions = [r for r in out.regressions if not _TEST_PATH_RE.search(r.file)]

    out.gap_waste_usd = out.gap_rebilled_tokens * (USD_FULL - USD_CACHE_READ) / 1_000_000
    out.read_saving_usd = max(0, out.read_tokens - out.skeleton_tokens) * USD_FULL / 1_000_000
    return out


def find_logs(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(p for p in target.rglob("*.jsonl") if p.stat().st_size > 0)
    return []


def run(paths: list[Path]) -> dict:
    sessions = [audit_session(p) for p in paths]
    total = {
        "sessions": len(sessions),
        "assistant_turns": sum(s.assistant_turns for s in sessions),
        "billed_input_tokens": sum(s.billed_input_tokens for s in sessions),
        "cache_read_tokens": sum(s.cache_read_tokens for s in sessions),
        "cache_gap_turns": sum(len(s.cache_gap_turns) for s in sessions),
        "gap_rebilled_tokens": sum(s.gap_rebilled_tokens for s in sessions),
        "gap_waste_usd": round(sum(s.gap_waste_usd for s in sessions), 4),
        "read_calls": sum(s.read_calls for s in sessions),
        "image_reads": sum(s.image_reads for s in sessions),
        "ignored_test_edits": sum(len(s.ignored_test_edits) for s in sessions),
        "read_tokens": sum(s.read_tokens for s in sessions),
        "skeleton_tokens": sum(s.skeleton_tokens for s in sessions),
        "skeleton_exact": all(s.skeleton_exact for s in sessions),
        "read_saving_usd": round(sum(s.read_saving_usd for s in sessions), 4),
        "regressions": sum(len(s.regressions) for s in sessions),
        "retry_turns": sum(s.retry_turns for s in sessions),
        "failing_results": sum(r.failing_results for s in sessions for r in s.regressions),
    }
    total["read_saving_pct"] = (
        round(100 * (total["read_tokens"] - total["skeleton_tokens"]) / total["read_tokens"], 1)
        if total["read_tokens"] else 0.0
    )
    return {"total": total, "sessions": [asdict(s) | {"retry_turns": s.retry_turns} for s in sessions]}


# ----------------------------------------------------------------- output


def terminal_summary(report: dict, source_note: str) -> str:
    t = report["total"]
    lines = [
        f"StepCheck audit — {t['sessions']} session(s), {t['assistant_turns']} assistant turns   [{source_note}]",
        "-" * 72,
        "a) cache-cliff waste",
        f"   turns resumed >{int(CACHE_CLIFF_SECONDS//60)} min after the previous one : {t['cache_gap_turns']:>8}",
        f"   context re-written at full rate on those turns : {t['gap_rebilled_tokens']:>8,} tokens  (${t['gap_waste_usd']:.4f} vs cache-read)",
        f"   Read-tool file pulls                            : {t['read_calls']:>8}  = {t['read_tokens']:,} tokens"
        + (f"   (+{t['image_reads']} image reads, no code)" if t['image_reads'] else ""),
        f"   same files as AST skeleton checkouts            : {t['skeleton_tokens']:>8,} tokens  ({t['read_saving_pct']}% less{'' if t['skeleton_exact'] else ', estimated'})  ${t['read_saving_usd']:.4f}",
        "b) regressions a gate would have blocked",
        f"   edits that dropped a decorator / guard clause   : {t['regressions']:>8}",
        f"   retry edits that followed                       : {t['retry_turns']:>8}",
        f"   failing tool results inside those loops         : {t['failing_results']:>8}",
    ]
    if t["ignored_test_edits"]:
        lines.append(f"   (ignored {t['ignored_test_edits']} guard/decorator edit(s) inside test files)")
    for s in report["sessions"]:
        for r in s["regressions"]:
            lines.append(f"     · T{r['turn']:<3} {Path(r['file']).name:<16} dropped {r['kind']:<9} {r['symbol']:<28} "
                         f"→ {r['retries']} retr{'y' if r['retries']==1 else 'ies'}, {r['failing_results']} failing result(s)")
    return "\n".join(lines)


def html_receipt(report: dict, source_note: str) -> str:
    t = report["total"]
    reg_rows = "".join(
        f"<tr><td>T{r['turn']}</td><td><code>{Path(r['file']).name}</code></td><td>{r['kind']}</td>"
        f"<td><code>{r['symbol']}</code></td><td>{r['retries']}</td><td>{r['failing_results']}</td>"
        f"<td>{'' if r['turns_to_recover'] is None else str(r['turns_to_recover']) + ' turns'}</td></tr>"
        for s in report["sessions"] for r in s["regressions"]
    ) or "<tr><td colspan='7' class='dim'>none found</td></tr>"
    sess_rows = "".join(
        f"<tr><td><code>{s['session_id'] or Path(s['path']).stem}</code></td><td>{s['assistant_turns']}</td>"
        f"<td>{len(s['cache_gap_turns'])}</td><td>{s['gap_rebilled_tokens']:,}</td><td>{s['read_tokens']:,}</td>"
        f"<td>{s['skeleton_tokens']:,}</td><td>{len(s['regressions'])}</td><td>{s['retry_turns']}</td></tr>"
        for s in report["sessions"]
    )
    gen = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"/><link rel="llms-txt" href="https://lalithasutam.github.io/stepcheck-dev/llms.txt"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/><meta name="color-scheme" content="dark"/>
<title>StepCheck audit receipt</title>
<style>
:root{{--well:#0e1116;--pane:#151a21;--line:#232b35;--ink:#d7dee7;--dim:#8a96a5;--ok:#3fb87f;--dirty:#e0a33b;--bad:#e25d5d;--mono:ui-monospace,Consolas,monospace}}
body{{margin:0;background:var(--well);color:var(--ink);font:15px/1.5 "Segoe UI","Helvetica Neue",Arial,sans-serif}}
main{{max-width:880px;margin:0 auto;padding:36px 20px 70px}}h1{{font-size:24px;margin:0 0 4px}}h2{{font-size:16px;margin:32px 0 10px}}
.sub{{color:var(--dim);margin:0 0 22px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:1px;background:var(--line);border:1px solid var(--line)}}
.grid div{{background:var(--pane);padding:12px 14px}}.grid b{{display:block;font-size:22px;font-variant-numeric:tabular-nums}}.grid span{{color:var(--dim);font-size:12px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{border:1px solid var(--line);padding:6px 9px;text-align:left}}th{{background:var(--pane);color:var(--dim)}}
code{{font:12.5px var(--mono)}}.ok{{color:var(--ok)}}.bad{{color:var(--bad)}}.dirty{{color:var(--dirty)}}.dim{{color:var(--dim)}}p{{max-width:72ch}}
</style></head><body><main>
<h1>StepCheck audit receipt</h1>
<p class="sub">{t['sessions']} session(s) · {t['assistant_turns']} assistant turns · {source_note} · generated {gen}</p>

<h2>a) Cache-cliff waste</h2>
<div class="grid">
<div><b class="bad">{t['cache_gap_turns']}</b><span>turns resumed more than {int(CACHE_CLIFF_SECONDS//60)} min after the previous one</span></div>
<div><b class="bad">{t['gap_rebilled_tokens']:,}</b><span>tokens of context re-written at full rate on those turns</span></div>
<div><b class="bad">${t['gap_waste_usd']:.4f}</b><span>paid above cache-read price (${USD_FULL:.2f} vs ${USD_CACHE_READ:.2f} / MTok)</span></div>
<div><b>{t['read_tokens']:,}</b><span>tokens pulled with the Read tool across {t['read_calls']} call(s)</span></div>
<div><b class="ok">{t['skeleton_tokens']:,}</b><span>the same files as AST skeleton checkouts{'' if t['skeleton_exact'] else ' (estimated)'}</span></div>
<div><b class="ok">{t['read_saving_pct']}% · ${t['read_saving_usd']:.4f}</b><span>less context per read</span></div>
</div>

<h2>b) Regressions a commit gate would have blocked</h2>
<div class="grid">
<div><b class="dirty">{t['regressions']}</b><span>edits that dropped a decorator or a leading guard clause</span></div>
<div><b class="dirty">{t['retry_turns']}</b><span>retry edits that followed on the same file</span></div>
<div><b class="dirty">{t['failing_results']}</b><span>failing tool results inside those retry loops</span></div>
</div>
<table style="margin-top:12px"><tr><th>Turn</th><th>File</th><th>Dropped</th><th>Symbol</th><th>Retries</th><th>Failing results</th><th>Recovered after</th></tr>{reg_rows}</table>

<h2>Per session</h2>
<table><tr><th>Session</th><th>Turns</th><th>Cache gaps</th><th>Re-billed tokens</th><th>Read tokens</th><th>Skeleton tokens</th><th>Regressions</th><th>Retries</th></tr>{sess_rows}</table>

<h2>How this was computed</h2>
<p>Pure arithmetic over the transcript, no model calls. A turn is a cache-gap turn when its timestamp is more than {int(CACHE_CLIFF_SECONDS)} s after the previous assistant turn; its <code>cache_creation_input_tokens</code> is the prefix that had to be re-written. Skeleton tokens are the real <code>focus=[]</code> AST skeleton of each Read result where it parses as Python (otherwise a flat 25% estimate, flagged). A regression is an <code>Edit</code> whose <code>old_string</code> had a decorator or <code>if …: raise</code> that <code>new_string</code> lacks; retries are later edits to the same file within {RETRY_WINDOW} turns. Gate B catches the first kind, an auto-mined Gate C invariant the second.</p>
</main></body></html>"""


def display_path(path: Path) -> str:
    """Shareable form of a path: forward slashes, home directory shown as `~`,
    so receipts never carry an OS username."""
    try:
        relative = path.resolve().relative_to(Path.home().resolve())
    except ValueError:
        return path.as_posix()
    return "~" if relative == Path() else f"~/{relative.as_posix()}"
