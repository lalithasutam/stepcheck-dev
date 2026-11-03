"""Door 1 age-banded context compaction (ContextCompactor). Private to the gateway.

Three bands over the non-system conversation a client proxies through Door 1:

  recent  — the last RECENT_BAND surviving messages, byte-identical;
  middle  — every older message, with each Python source block over
            CODE_TOKEN_THRESHOLD tokens replaced in place by its ``focus=[]``
            AST skeleton (signatures, decorators, docstrings; bodies elided);
  oldest  — when the gap since the previous turn exceeds CACHE_CLIFF_SECONDS the
            cached prefix is gone anyway, so the middle band is folded into one
            compact OKF session-state frame supplied by the gateway.

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
    module with at least one def/class (prose and data stay as they are)."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    if not any(isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for s in tree.body):
        return None
    return _okf.skeleton(source, [])


SKELETONIZERS: dict[str, Callable[[str], str | None]] = {"python": skeleton_python}


def _language(fence: str) -> str | None:
    tag = fence.strip().lower()
    if tag in _PY_FENCES:
        return "python"
    if tag in _TS_FENCES:
        return "typescript"
    return None


def compact_text(text: str, threshold: int = CODE_TOKEN_THRESHOLD) -> str:
    """Replace every registered-language source block over `threshold` tokens by
    its skeleton; fenced blocks keep their fence, an unfenced message that is a
    (possibly line-numbered) module is skeletonized whole."""
    def swap(m: re.Match) -> str:
        lang = _language(m.group(1))
        fn = SKELETONIZERS.get(lang or "")
        body = m.group(2)
        if fn is None or _tokens.count(body) <= threshold:
            return m.group(0)
        sk = fn(body)
        return m.group(0) if sk is None else f"```{m.group(1)}\n{sk.rstrip()}\n```"

    swapped, n = _FENCE_RE.subn(swap, text)
    if n:
        return swapped
    if _tokens.count(text) <= threshold:
        return text
    sk = skeleton_python(_NUMBERED_RE.sub("", text))
    return text if sk is None else sk


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


def _compact_message(message: dict, threshold: int) -> dict:
    out = dict(message)
    content = message.get("content", "")
    if isinstance(content, str):
        out["content"] = compact_text(content, threshold)
        return out
    blocks = []
    for block in content:
        if not isinstance(block, dict):
            blocks.append(block)
            continue
        b = dict(block)
        if isinstance(b.get("text"), str):
            b["text"] = compact_text(b["text"], threshold)
        elif isinstance(b.get("content"), str):
            b["content"] = compact_text(b["content"], threshold)
        elif isinstance(b.get("content"), list):
            b["content"] = [
                {**x, "text": compact_text(x["text"], threshold)} if isinstance(x, dict) and isinstance(x.get("text"), str) else x
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

    @property
    def saved_pct(self) -> float:
        return 100.0 * (self.tokens_before - self.tokens_after) / self.tokens_before if self.tokens_before else 0.0

    def report(self) -> dict:
        return {
            "bands": self.bands, "pruned_messages": self.pruned, "folded_messages": self.folded,
            "cache_cliff": self.cache_cliff, "gap_seconds": self.gap_seconds,
            "tokens_before": self.tokens_before, "tokens_after": self.tokens_after, "saved_pct": round(self.saved_pct, 1),
        }


class ContextCompactor:
    def __init__(self, *, keep_recent: int = RECENT_BAND, code_token_threshold: int = CODE_TOKEN_THRESHOLD,
                 cache_cliff_seconds: float = CACHE_CLIFF_SECONDS) -> None:
        self.keep_recent = keep_recent
        self.threshold = code_token_threshold
        self.cache_cliff_seconds = cache_cliff_seconds

    def is_dead_end(self, message: dict, is_step: Callable[[dict], bool]) -> bool:
        if DEAD_END_MARKER in message_text(message):
            return True
        return message.get("role") == "assistant" and not is_step(message)

    def compact(self, messages: list[dict], *, is_step: Callable[[dict], bool] = default_is_step,
                now: float | None = None, last_turn_at: float | None = None,
                summary: Callable[[], str] | str | None = None) -> Compaction:
        """Non-system messages only (the gateway carries system prompts itself).
        `summary` is the OKF session-state frame used when the oldest band folds."""
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
        if cliff and middle and summary is not None:
            text = summary() if callable(summary) else summary
            folded = len(middle)
            middle_out = [{"role": "user", "content": text}]
        else:
            middle_out = [_compact_message(m, self.threshold) for m in middle]
        middle_after = sum(_tokens.count(message_text(m)) for m in middle_out)
        recent_tokens = sum(_tokens.count(message_text(m)) for m in recent)

        out = middle_out + list(recent)
        result = Compaction(messages=out, pruned=pruned, folded=folded, cache_cliff=cliff, gap_seconds=gap,
                            tokens_before=before, tokens_after=middle_after + recent_tokens)
        result.bands = {
            "recent": {"messages": len(recent), "tokens_before": recent_tokens, "tokens_after": recent_tokens},
            "middle": {"messages_in": len(middle), "messages_out": len(middle_out), "tokens_before": middle_before,
                       "tokens_after": middle_after, "folded": folded > 0},
            "pruned": {"messages": pruned, "tokens_before": before - middle_before - recent_tokens, "tokens_after": 0},
        }
        return result
