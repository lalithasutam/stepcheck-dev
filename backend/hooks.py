"""Claude Code lifecycle hooks evaluated against a warm StateKernel.

`decide(event, kernel)` is the whole policy. It is served by `DualDoorGateway`
as `POST /v1/step/hook` (the warm fast path the installed hook script relays
to) and callable offline by the CLI, so both paths give the same answer.

Contract (Claude Code hooks; verified in `~/.claude/skills/update-config` and
the official `plugin-dev/hook-development` skill): the hook receives one JSON
object (`hook_event_name`, `session_id`, `cwd`, `tool_name`, `tool_input`,
`stop_hook_active`, …). For `PreToolUse` the decision is
`{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision":
"allow" | "deny" | "ask", "permissionDecisionReason": …, "additionalContext": …}}`;
for `Stop` it is `{"decision": "block", "reason": …}`; an empty object means
"no opinion" and the tool / stop proceeds.

Policy:
- PreToolUse `Read` of a tracked Python module whose raw text exceeds the
  token threshold: deny, and hand back the `focus=[]` OKF skeleton as
  `additionalContext` — orientation at skeleton cost instead of the whole file.
- PreToolUse `Edit` / `Write` / `MultiEdit` / `NotebookEdit` of a LOCKED module:
  deny with the Gate A diagnostic the kernel itself produces.
- `Stop`: block while any module of the project's session holds
  `DIRTY_OMISSION_RISK`, naming them; `stop_hook_active` short-circuits.
Everything else is allowed silently.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from kernel import StateKernel, _tokens

DEFAULT_READ_THRESHOLD = 1500
EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")


def registry() -> dict[str, str]:
    """session_id -> project root, from the per-user registry (`STEPCHECK_HOME`
    overrides `~/.stepcheck`, exactly as the kernel reads it)."""
    home = Path(os.environ.get("STEPCHECK_HOME") or Path.home() / ".stepcheck")
    try:
        data = json.loads((home / "sessions.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {sid: root for sid, root in data.items() if isinstance(root, str)}


def sessions_for(path: Path) -> list[tuple[str, Path]]:
    """Registered sessions whose root contains `path` (or equals it), oldest first."""
    path = path.resolve()
    out = []
    for sid, root in registry().items():
        r = Path(root).resolve()
        if path == r or r in path.parents:
            out.append((sid, r))
    return out


def _session(event: dict, path: Path | None) -> tuple[str, Path] | None:
    explicit = event.get("stepcheck_session_id")
    if explicit:
        root = registry().get(explicit)
        return explicit, Path(root).resolve() if root else Path(event.get("cwd") or os.getcwd()).resolve()
    if path is None:
        return None
    found = sessions_for(path)
    return found[-1] if found else None  # the newest session wins


def _node_for(kernel: StateKernel, sid: str, root: Path, target: Path) -> dict | None:
    try:
        graph = kernel.graph(sid)
    except KeyError:
        return None
    target = target.resolve()
    return next((n for n in graph["nodes"] if (root / n["path"]).resolve() == target), None)


def _deny(reason: str, context: str | None = None) -> dict:
    out = {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}
    if context is not None:
        out["additionalContext"] = context
    return {"hookSpecificOutput": out}


def _pre_tool_use(event: dict, kernel: StateKernel) -> dict:
    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not file_path:
        return {}
    target = Path(str(file_path))
    found = _session(event, target)
    if found is None:
        return {}
    sid, root = found
    node = _node_for(kernel, sid, root, target)
    if node is None:
        return {}  # not a tracked module: the tool is fine
    if tool == "Read":
        threshold = int(event.get("threshold") or DEFAULT_READ_THRESHOLD)
        raw_tokens = _tokens.count(node["source"])
        if raw_tokens <= threshold:
            return {}
        payload = kernel.checkout(sid, node["node_id"], focus=[])
        context = (
            f"StepCheck context firewall: raw Read of `{node['path']}` ({raw_tokens:,} tokens) was replaced by "
            f"its OKF skeleton ({payload.token_count:,} tokens). Session `{sid}`, node `{node['node_id']}`. "
            "To see a body verbatim call checkout_context_frame(session_id, node_id, focus=[<symbol>]); "
            "edit through commit_verified_step patches.\n\n" + payload.rendered()
        )
        return _deny(
            f"StepCheck: `{node['path']}` is a tracked module of session {sid} "
            f"({raw_tokens:,} tokens > {threshold:,}); its AST skeleton was supplied instead.",
            context,
        )
    if tool in EDIT_TOOLS and node["status"] == "LOCKED":
        verdict = kernel.commit(sid, node["node_id"], source=node["source"])  # Gate A speaks for itself
        reason = str(verdict.error) if verdict.error else f"node '{node['node_id']}' is LOCKED"
        return _deny(f"StepCheck Gate A: {reason}. Unlock it or edit through the gates.")
    return {}


def _stop(event: dict, kernel: StateKernel) -> dict:
    if event.get("stop_hook_active"):
        return {}  # already blocked once this turn; never loop
    explicit = event.get("stepcheck_session_id")
    candidates = [(explicit, None)] if explicit else sessions_for(Path(event.get("cwd") or os.getcwd()))
    dirty: dict[str, list[str]] = {}
    for sid, _root in candidates:
        try:
            graph = kernel.graph(sid)
        except KeyError:
            continue
        nodes = sorted(n["node_id"] for n in graph["nodes"] if n["status"] == "DIRTY_OMISSION_RISK")
        if nodes:
            dirty[sid] = nodes
    if not dirty:
        return {}
    detail = "; ".join(f"session {sid}: {', '.join(nodes)}" for sid, nodes in dirty.items())
    return {
        "decision": "block",
        "reason": (
            "StepCheck omission guard: these modules hold DIRTY_OMISSION_RISK because an exported "
            "signature they depend on changed. Check each out (checkout_context_frame, focus=[]) and "
            "re-commit it (commit_verified_step) until check_omission_risks reports can_finalize: true. "
            + detail
        ),
    }


def decide(event: dict, kernel: StateKernel) -> dict:
    """The hook answer for one lifecycle event, or `{}` for "no opinion"."""
    name = event.get("hook_event_name") or ("Stop" if "stop_hook_active" in event else "PreToolUse")
    if name == "Stop":
        return _stop(event, kernel)
    if name == "PreToolUse":
        return _pre_tool_use(event, kernel)
    return {}
