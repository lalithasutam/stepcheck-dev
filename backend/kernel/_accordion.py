"""Door 1 age-banded context compaction (ContextCompactor). Private to the gateway.

Three bands over the non-system conversation a client proxies through Door 1:

  recent  — the last RECENT_BAND surviving messages, byte-identical;
  middle  — every older message, with each Python source block over
            CODE_TOKEN_THRESHOLD tokens replaced in place by its ``focus=[]``
            AST skeleton (signatures, decorators, docstrings; bodies elided);
  oldest  — when the gap since the previous turn exceeds CACHE_CLIFF_SECONDS the
            cached prefix is gone anyway, so the middle band is folded into one
            compact OKF session-state frame supplied by the gateway; the
            natural-language constraints users stated in those turns are
            pinned into the frame verbatim (`pinned_constraints`), while their
            tool output, file dumps and stack traces go.

Dead-end turns are pruned from every band: an assistant message that carries no
step (the gateway decides what a step is) or any message carrying
DEAD_END_MARKER. Language skeletonizers are a registry so a TypeScript
skeleton can plug in beside the Python one.
"""
from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from . import _okf, _tokens

RECENT_BAND = 4
CODE_TOKEN_THRESHOLD = 150
CACHE_CLIFF_SECONDS = 300.0
DEAD_END_MARKER = "[STEPCHECK_DEAD_END]"

_FENCE_RE = re.compile(r"```([A-Za-z0-9_+.-]*)[ \t]*\n(.*?)```", re.S)
_NUMBERED_RE = re.compile(r"^[ \t]*\d+(?:\t|→| {2,})", re.M)
_PY_FENCES = {"", "py", "python", "python3"}
_TS_FENCES = {"ts", "tsx", "typescript", "javascript", "js", "jsx"}


def skeleton_python(source: str) -> str | None:
    """``focus=[]`` skeleton of a Python module, or None when the text is not a
    module (no column-0 def/class/import, or it does not parse): prose, data,
    logs and diffs stay as they are. One parse, inside `_okf.skeleton`."""
    if not _PY_PREFILTER_RE.search(source):
        return None
    try:
        tree = ast.parse(source)  # verify the guess: `_okf.skeleton` would otherwise fall back to TypeScript
    except (SyntaxError, ValueError):
        return None
    if not any(isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for s in tree.body):
        return None
    return _okf.skeleton(source, [])


SKELETONIZERS: dict[str, Callable[[str], str | None]] = {"python": skeleton_python}


def _language(fence: str) -> str | None:
    """Registry language for a fence tag; None for prose / unknown tags."""
    tag = fence.strip().lower()
    if tag in _PY_FENCES:
        return "python"
    if tag in _TS_FENCES:
        return "typescript"
    for lang, tags in _OTHER_FENCES.items():
        if tag in tags:
            return lang
    return None


def compact_text(text: str, threshold: int = CODE_TOKEN_THRESHOLD, *, stats: dict | None = None,
                 tool_output: bool = False, log_threshold: int | None = None) -> str:
    """Replace every source block over `threshold` tokens by its skeleton.

    Fenced blocks keep their fence; an unfenced block (what Claude Code's Read
    tool returns: `cat -n` lines, `<n>\u2192` or `<n>\t` prefixed) is stripped
    of its line numbers, its language detected from a file-path hint or its own
    syntax, and skeletonized whole through the SKELETONIZERS registry. A language
    that is detected but has no registered skeletonizer (Go, Rust, Java until
    their modules land) is left intact and counted under `languages`. Non-code
    tool output over `log_threshold` tokens (pytest, git diff, grep) keeps its
    head, its failure lines and its tail (`elide_log`). `stats` collects
    skeletonized / logs_elided / prefixes_stripped / languages for the report."""
    stats = _stats(stats)
    log_threshold = LOG_TOKEN_THRESHOLD if log_threshold is None else log_threshold

    def swap(m: re.Match) -> str:
        body, stripped = strip_line_numbers(m.group(2))
        lang = _language(m.group(1)) if m.group(1).strip() else detect_language(body)
        if lang is None:
            lang = detect_language(body)
        if lang is None or _tokens.count(body) <= threshold:
            return m.group(0)
        sk, kind = _skeletonize(lang, body, stats)
        if sk is None:
            return m.group(0)
        stats["prefixes_stripped"] += stripped
        return f"```{m.group(1)}\n{sk.rstrip()}\n```"

    swapped, n = _FENCE_RE.subn(swap, text)
    if n:
        return swapped
    if _tokens.count(text) <= min(threshold, log_threshold):
        return text
    body, stripped = strip_line_numbers(text)
    lang = detect_language(body)
    if lang is not None and _tokens.count(body) > threshold:
        sk, kind = _skeletonize(lang, body, stats)
        if sk is not None:
            stats["prefixes_stripped"] += stripped
            return sk
        if kind == "unregistered":
            return text  # a real module in a language with no skeletonizer yet: keep it intact
    if tool_output and _tokens.count(text) > log_threshold:
        elided, n_lines = elide_log(text)
        if n_lines:
            stats["logs_elided"] += 1
            return elided
    return text


def message_text(message: dict) -> str:
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    parts = []
    for block in content:
        if not isinstance(block, dict):
            continue
        if isinstance(block.get("text"), str):
            parts.append(block["text"])
        elif isinstance(block.get("content"), str):  # tool_result
            parts.append(block["content"])
        elif isinstance(block.get("content"), list):
            parts.extend(b.get("text", "") for b in block["content"] if isinstance(b, dict))
    return "\n".join(parts)


def _compact_message(message: dict, threshold: int, stats: dict | None = None) -> dict:
    """One middle-band message: plain text, Anthropic content blocks (text and
    tool_result, with the tool_use_id and block structure kept so the provider
    accepts the conversation) or an OpenAI `role: "tool"` message."""
    stats = _stats(stats)
    out = dict(message)
    content = message.get("content", "")
    is_tool_msg = message.get("role") == "tool"
    if isinstance(content, str):
        out["content"] = compact_text(content, threshold, stats=stats, tool_output=is_tool_msg)
        return out
    blocks = []
    for block in content:
        if not isinstance(block, dict):
            blocks.append(block)
            continue
        b = dict(block)
        tool = is_tool_msg or b.get("type") == "tool_result"
        if isinstance(b.get("text"), str):
            b["text"] = compact_text(b["text"], threshold, stats=stats, tool_output=tool)
        elif isinstance(b.get("content"), str):
            b["content"] = compact_text(b["content"], threshold, stats=stats, tool_output=tool)
        elif isinstance(b.get("content"), list):
            b["content"] = [
                {**x, "text": compact_text(x["text"], threshold, stats=stats, tool_output=tool)}
                if isinstance(x, dict) and isinstance(x.get("text"), str) else x
                for x in b["content"]
            ]
        blocks.append(b)
    out["content"] = blocks
    return out


def parse_timestamp(value) -> float | None:
    """Epoch seconds from an epoch number/string or an ISO-8601 string."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def latest_message_timestamp(messages: list[dict]) -> float | None:
    stamps = [parse_timestamp(m.get("timestamp") or m.get("created_at")) for m in messages if isinstance(m, dict)]
    stamps = [s for s in stamps if s is not None]
    return max(stamps) if stamps else None


def default_is_step(message: dict) -> bool:
    text = message_text(message)
    return "```python" in text or "```stepcheck-patch" in text


PIN_SHORT_TOKENS = 60    # a user turn this short with no code or log in it is an instruction: kept whole
PIN_MAX_TOKENS = 400     # a longer prose turn carrying constraint keywords is kept whole up to this size…
PIN_LINE_TOKENS = 120    # …beyond it only its keyword lines are, each up to this size
_CONSTRAINT_RE = re.compile(
    r"\b(?:must(?:\s+not)?|never|always|critical|rule|invariant|constraint|required?|requirement|"
    r"mandatory|forbidden|do\s+not|don'?t|important|guarantee)\b",
    re.I,
)


def _user_prose(message: dict) -> str:
    """The text a user typed in one message: string content or text blocks, never
    tool_result blocks (tool output, not instructions), with fenced blocks removed."""
    if message.get("role") != "user":
        return ""
    content = message.get("content", "")
    if isinstance(content, str):
        parts = [content]
    else:
        parts = [b["text"] for b in content
                 if isinstance(b, dict) and b.get("type", "text") == "text" and isinstance(b.get("text"), str)]
    return _FENCE_RE.sub("", "\n".join(parts)).strip()


def _looks_like_code(text: str) -> bool:
    """Source by its own syntax (column-0 def / class / import, TS, Go, Rust, Java
    declarations), not by a file-name hint: "timestamps in events.py are ms" is
    prose that mentions a path."""
    return any(rx.search(text) for rx in (_PY_PREFILTER_RE, _TS_SYNTAX_RE, _GO_SYNTAX_RE,
                                          _RUST_SYNTAX_RE, _JAVA_SYNTAX_RE))


def pinned_constraints(messages: list[dict]) -> list[str]:
    """Natural-language user constraints in `messages`, verbatim and in order:
    a short instruction (≤ PIN_SHORT_TOKENS) is kept whole; a longer prose turn
    with constraint keywords whole up to PIN_MAX_TOKENS, else only its keyword
    lines. Pasted code, line-numbered reads and logs (Traceback / FAIL / ERROR
    lines) never pin: they are what the fold exists to drop."""
    out: list[str] = []
    for m in messages:
        prose = _user_prose(m)
        if not prose or DEAD_END_MARKER in prose:
            continue
        body, numbered = strip_line_numbers(prose)
        if numbered or _looks_like_code(body):
            continue
        tokens = _tokens.count(prose)
        keyed = bool(_CONSTRAINT_RE.search(prose))
        logish = bool(_LOG_KEEP_RE.search(prose))
        if not logish and (tokens <= PIN_SHORT_TOKENS or (keyed and tokens <= PIN_MAX_TOKENS)):
            pick = [prose]
        elif keyed:
            pick = [ln.strip() for ln in prose.splitlines()
                    if _CONSTRAINT_RE.search(ln) and not _LOG_KEEP_RE.search(ln) and _tokens.count(ln) <= PIN_LINE_TOKENS]
        else:
            pick = []
        for text in pick:
            if text and text not in out:
                out.append(text)
    return out


@dataclass
class Compaction:
    messages: list[dict]
    bands: dict[str, dict] = field(default_factory=dict)
    pruned: int = 0
    folded: int = 0
    cache_cliff: bool = False
    gap_seconds: float | None = None
    tokens_before: int = 0
    tokens_after: int = 0
    skeletonized: int = 0
    logs_elided: int = 0
    prefixes_stripped: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    pinned: int = 0

    @property
    def saved_pct(self) -> float:
        return 100.0 * (self.tokens_before - self.tokens_after) / self.tokens_before if self.tokens_before else 0.0

    def report(self) -> dict:
        return {
            "bands": self.bands, "pruned_messages": self.pruned, "folded_messages": self.folded,
            "cache_cliff": self.cache_cliff, "gap_seconds": self.gap_seconds,
            "tokens_before": self.tokens_before, "tokens_after": self.tokens_after, "saved_pct": round(self.saved_pct, 1),
            "blocks_skeletonized": self.skeletonized, "logs_elided": self.logs_elided,
            "line_prefixes_stripped": self.prefixes_stripped, "languages": dict(self.languages),
            "pinned_constraints": self.pinned,
            "elapsed_ms": round(self.elapsed_ms, 3),
        }


class ContextCompactor:
    def __init__(self, *, keep_recent: int = RECENT_BAND, code_token_threshold: int = CODE_TOKEN_THRESHOLD,
                 cache_cliff_seconds: float = CACHE_CLIFF_SECONDS, log_token_threshold: int | None = None) -> None:
        self.keep_recent = keep_recent
        self.threshold = code_token_threshold
        self.cache_cliff_seconds = cache_cliff_seconds
        self.log_threshold = log_token_threshold

    def is_dead_end(self, message: dict, is_step: Callable[[dict], bool]) -> bool:
        if DEAD_END_MARKER in message_text(message):
            return True
        return message.get("role") == "assistant" and not is_step(message)

    def compact(self, messages: list[dict], *, is_step: Callable[[dict], bool] = default_is_step,
                now: float | None = None, last_turn_at: float | None = None,
                summary: Callable[[], str] | str | None = None) -> Compaction:
        """Non-system messages only (the gateway carries system prompts itself).
        `summary` is the OKF session-state frame used when the oldest band folds."""
        started = time.perf_counter()
        convo = [m for m in messages if isinstance(m, dict) and m.get("role") != "system"]
        before = sum(_tokens.count(message_text(m)) for m in convo)
        kept = [m for m in convo if not self.is_dead_end(m, is_step)]
        pruned = len(convo) - len(kept)
        recent = kept[-self.keep_recent:] if self.keep_recent else []
        middle = kept[: len(kept) - len(recent)]

        now = time.time() if now is None else now
        gap = (now - last_turn_at) if last_turn_at is not None else None
        cliff = gap is not None and gap > self.cache_cliff_seconds

        middle_before = sum(_tokens.count(message_text(m)) for m in middle)
        folded = 0
        stats = _stats(None)
        log_t = LOG_TOKEN_THRESHOLD if self.log_threshold is None else self.log_threshold
        pinned: list[str] = []
        if cliff and middle and summary is not None:
            text = summary() if callable(summary) else summary
            folded = len(middle)
            pinned = pinned_constraints(middle)
            if pinned:
                text = (text.rstrip("\n") + "\n\n## User constraints pinned from the folded turns (verbatim)\n\n"
                        + "\n\n".join(pinned) + "\n")
            middle_out = [{"role": "user", "content": text}]
        else:
            middle_out = [_compact_message_with(m, self.threshold, log_t, stats) for m in middle]
        middle_after = sum(_tokens.count(message_text(m)) for m in middle_out)
        recent_tokens = sum(_tokens.count(message_text(m)) for m in recent)

        out = middle_out + list(recent)
        result = Compaction(messages=out, pruned=pruned, folded=folded, cache_cliff=cliff, gap_seconds=gap,
                            tokens_before=before, tokens_after=middle_after + recent_tokens,
                            skeletonized=stats["skeletonized"], logs_elided=stats["logs_elided"],
                            prefixes_stripped=stats["prefixes_stripped"], languages=stats["languages"],
                            pinned=len(pinned))
        result.bands = {
            "recent": {"messages": len(recent), "tokens_before": recent_tokens, "tokens_after": recent_tokens},
            "middle": {"messages_in": len(middle), "messages_out": len(middle_out), "tokens_before": middle_before,
                       "tokens_after": middle_after, "folded": folded > 0},
            "pruned": {"messages": pruned, "tokens_before": before - middle_before - recent_tokens, "tokens_after": 0},
        }
        result.elapsed_ms = (time.perf_counter() - started) * 1000
        return result


def compact(messages: list[dict], *, keep_recent: int = RECENT_BAND, code_token_threshold: int = CODE_TOKEN_THRESHOLD,
            cache_cliff_seconds: float = CACHE_CLIFF_SECONDS, log_token_threshold: int | None = None,
            **kwargs) -> Compaction:
    """Module-level form of `ContextCompactor(...).compact(messages, ...)`: the
    constructor options as keywords, everything else (`is_step`, `now`,
    `last_turn_at`, `summary`) passed through."""
    return ContextCompactor(keep_recent=keep_recent, code_token_threshold=code_token_threshold,
                            cache_cliff_seconds=cache_cliff_seconds,
                            log_token_threshold=log_token_threshold).compact(messages, **kwargs)


import functools

LOG_TOKEN_THRESHOLD = 300
LOG_HEAD_LINES = 15
LOG_TAIL_LINES = 20
_LOG_KEEP_RE = re.compile(r"FAIL|ERROR|AssertionError|Traceback")
_OTHER_FENCES = {"go": {"go", "golang"}, "rust": {"rs", "rust"}, "java": {"java"}}
_EXT_LANG = {"py": "python", "ts": "typescript", "tsx": "typescript", "js": "typescript", "jsx": "typescript",
             "mts": "typescript", "cts": "typescript", "go": "go", "rs": "rust", "java": "java"}
_PATH_HINT_RE = re.compile(r"[\w./\\-]+\.(py|tsx?|jsx?|mts|cts|go|rs|java)\b")
_TS_SYNTAX_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*\w+\s*[(<]"
    r"|^\s*(?:export\s+)?(?:declare\s+)?(?:interface|type|enum|namespace)\s+\w+"
    r"|^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+\w+[^\n(]*(?:\{|extends|implements)"
    r"|^\s*import\s+(?:type\s+)?[\w{},*\s]+\s+from\s+['\"]"
    r"|^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*(?::\s*[\w<>\[\]|]+)?\s*=\s*(?:async\s*)?\(?[^;]*=>"
    r"|:\s*(?:string|number|boolean|void|unknown|never)\b", re.M)
_GO_SYNTAX_RE = re.compile(r"^package\s+\w+|^func\s+(?:\([^)]*\)\s*)?\w+\s*\(|^import\s*\(", re.M)
_RUST_SYNTAX_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+\w+|^use\s+[\w:]+|^\s*impl(?:<[^>]*>)?\s+\w|^#\[derive|^\s*(?:pub\s+)?(?:struct|enum|trait|mod)\s+\w+", re.M)
_JAVA_SYNTAX_RE = re.compile(r"^\s*(?:public|private|protected)\s+(?:static\s+|final\s+|abstract\s+)*(?:class|interface|enum|record)\s+\w+"
                             r"|^import\s+(?:static\s+)?(?:java|javax|jakarta|org|com)\.[\w.]+;|^package\s+[\w.]+;"
                             r"|^\s*@(?:Override|Transactional|Test|Autowired|RestController)\b", re.M)


def _stats(stats: dict | None) -> dict:
    if stats is None:
        stats = {}
    stats.setdefault("skeletonized", 0)
    stats.setdefault("logs_elided", 0)
    stats.setdefault("prefixes_stripped", 0)
    stats.setdefault("languages", {})
    return stats


def strip_line_numbers(text: str) -> tuple[str, int]:
    """Remove `cat -n` style prefixes (`<n>\u2192`, `<n>\t`, `<n>  `) when most
    non-empty lines carry one; the code's own indentation after the prefix is
    kept. Returns (text, lines stripped) — 0 when the text is not numbered."""
    lines = text.splitlines(keepends=True)
    nonempty = [ln for ln in lines if ln.strip()]
    if not nonempty:
        return text, 0
    numbered = sum(1 for ln in nonempty if _NUMBERED_RE.match(ln))
    if numbered * 2 < len(nonempty):
        return text, 0
    out = [_NUMBERED_RE.sub("", ln, count=1) for ln in lines]
    return "".join(out), numbered


def detect_language(text: str) -> str | None:
    """Language of an unfenced source block, decided on its first DETECT_LINES
    lines: a file-path hint in the first three, then syntax — a column-0
    def/class/import for Python (a log or a diff never has one), two distinct
    signature-level matches for the others. The skeletonizer verifies the guess
    by parsing; a wrong guess falls back to the log path, never to a bad
    skeleton."""
    lines = text.splitlines()
    head = "\n".join(lines[:3])
    sample = "\n".join(lines[:DETECT_LINES])
    m = _PATH_HINT_RE.search(head)
    if m and _EXT_LANG.get(m.group(1).lower()):
        return _EXT_LANG[m.group(1).lower()]
    # Brace languages first: Go/Java `import` and TypeScript `class` lines would
    # also satisfy the Python prefilter, and the Python verifier only rejects.
    for lang, rx in (("go", _GO_SYNTAX_RE), ("rust", _RUST_SYNTAX_RE), ("java", _JAVA_SYNTAX_RE), ("typescript", _TS_SYNTAX_RE)):
        if len({mm.group(0).split()[0] for mm in rx.finditer(sample)}) >= 2 or len(rx.findall(sample)) >= 3:
            return lang
    if _PY_PREFILTER_RE.search(sample):
        return "python"
    return None


DETECT_LINES = 120
_PY_PREFILTER_RE = re.compile(r"^(?:async def|def|class|import|from|@\w)\b", re.M)


_REGISTRY_VERSION = [0]


@functools.lru_cache(maxsize=512)
def _render_cached(lang: str, body: str, _version: int) -> str | None:
    """Memoized skeleton: a long session re-sends the same old tool outputs on
    every turn, so each block is rendered once per process, not once per turn."""
    fn = SKELETONIZERS.get(lang)
    return fn(body) if fn is not None else None


def _skeletonize(lang: str, body: str, stats: dict) -> tuple[str | None, str]:
    """(skeleton, kind): kind is "skeletonized", "unregistered" (a language the
    accordion recognises but cannot render yet — counted, kept intact) or
    "not_a_module" (the hint was wrong: a diff or a log naming a file)."""
    if lang not in SKELETONIZERS:
        stats["languages"][lang] = stats["languages"].get(lang, 0) + 1
        return None, "unregistered"
    sk = _render_cached(lang, body, _REGISTRY_VERSION[0])
    if sk is None:
        return None, "not_a_module"
    stats["languages"][lang] = stats["languages"].get(lang, 0) + 1
    stats["skeletonized"] += 1
    return sk, "skeletonized"


def elide_log(text: str, head: int = LOG_HEAD_LINES, tail: int = LOG_TAIL_LINES) -> tuple[str, int]:
    """Keep the first `head` lines, every line matching _LOG_KEEP_RE and the
    last `tail` lines of a non-code tool output; the rest becomes one elision
    line. Returns (text, lines elided) — (text, 0) when nothing is elided."""
    lines = text.splitlines()
    if len(lines) <= head + tail + 1:
        return text, 0
    keep = set(range(head)) | set(range(len(lines) - tail, len(lines)))
    keep |= {i for i, ln in enumerate(lines) if _LOG_KEEP_RE.search(ln)}
    out: list[str] = []
    elided = 0
    run = 0
    for i, ln in enumerate(lines):
        if i in keep:
            if run:
                out.append(f"\u2026 [{run} lines elided by StepCheck accordion]")
                elided += run
                run = 0
            out.append(ln)
        else:
            run += 1
    if run:
        out.append(f"\u2026 [{run} lines elided by StepCheck accordion]")
        elided += run
    return "\n".join(out) + ("\n" if text.endswith("\n") else ""), elided


def skeleton_typescript(source: str) -> str | None:
    """``focus=[]`` skeleton of a TypeScript / JavaScript module, or None when the
    text has no top-level declaration or does not scan cleanly."""
    from . import _ts

    try:
        decls, _stmts = _ts.parse(source)
        if not decls or _ts.syntax_problem(source) is not None:
            return None
        return _ts.skeleton(source, [])
    except Exception:  # noqa: BLE001 — a scanner failure means "not a module", never an error
        return None


def register_skeletonizer(language: str, fn: Callable[[str], str | None]) -> None:
    """Plug a language into the accordion: `fn(source)` returns the focus=[]
    skeleton or None when the text is not a module of that language. Bumps the
    memo version so earlier "no skeletonizer" results are not reused."""
    SKELETONIZERS[language] = fn
    _REGISTRY_VERSION[0] += 1


def _compact_message_with(message: dict, threshold: int, log_threshold: int, stats: dict) -> dict:
    """`_compact_message` with an explicit log threshold (ContextCompactor option)."""
    out = dict(message)
    content = message.get("content", "")
    is_tool_msg = message.get("role") == "tool"
    if isinstance(content, str):
        out["content"] = compact_text(content, threshold, stats=stats, tool_output=is_tool_msg, log_threshold=log_threshold)
        return out
    blocks = []
    for block in content:
        if not isinstance(block, dict):
            blocks.append(block)
            continue
        b = dict(block)
        tool = is_tool_msg or b.get("type") == "tool_result"
        if isinstance(b.get("text"), str):
            b["text"] = compact_text(b["text"], threshold, stats=stats, tool_output=tool, log_threshold=log_threshold)
        elif isinstance(b.get("content"), str):
            b["content"] = compact_text(b["content"], threshold, stats=stats, tool_output=tool, log_threshold=log_threshold)
        elif isinstance(b.get("content"), list):
            b["content"] = [
                {**x, "text": compact_text(x["text"], threshold, stats=stats, tool_output=tool, log_threshold=log_threshold)}
                if isinstance(x, dict) and isinstance(x.get("text"), str) else x
                for x in b["content"]
            ]
        blocks.append(b)
    out["content"] = blocks
    return out


register_skeletonizer("typescript", skeleton_typescript)
