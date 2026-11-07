"""Claude Code lifecycle hooks evaluated against a warm StateKernel.

decide(event, kernel) is the whole policy. It is served by DualDoorGateway
as POST /v1/step/hook (the warm fast path the installed hook script relays
to) and callable offline by the CLI, so both paths give the same answer.

Contract (Claude Code hooks; verified in ~/.claude/skills/update-config and
the official plugin-dev/hook-development skill): the hook receives one JSON
object (hook_event_name, session_id, cwd, tool_name, tool_input,
stop_hook_active, ...). For PreToolUse the decision is
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision":
"allow" | "deny" | "ask", "permissionDecisionReason": ..., "additionalContext": ...}};
for Stop it is {"decision": "block", "reason": ...}; an empty object means
"no opinion" and the tool / stop proceeds.

Policy:
- Zero-touch session auto-init: if a hook arrives for a project root with no
  registered session yet, the kernel automatically opens one on cwd.
- PreToolUse Read of a tracked Python/TS module whose raw text exceeds the
  token threshold: deny unscoped full-file reads and hand back the focus=[]
  OKF skeleton as additionalContext; allow scoped line-slice reads
  (limit <= 120) so agents can inspect individual symbol spans directly.
- PreToolUse Edit / Write / MultiEdit / NotebookEdit:
  - on a LOCKED module: deny with the Gate A diagnostic.
  - on an active tracked module when edit content is supplied: apply the edit
    to the file as it is on disk (what the tool will write) and verify the
    result through Gates A, B, and C with a dry-run commit; deny on any gate
    violation so the agent self-corrects on the next turn. Nothing is written:
    the tool writes, and the next hook call adopts those bytes.
- Every PreToolUse first `sync`s the target node, and Stop syncs the whole
  session: bytes the agent's tools (or git, or a formatter) wrote are adopted
  through the gates, so the session never goes stale and dependents of a
  changed signature turn DIRTY_OMISSION_RISK.
- PostToolUse Edit / Write / MultiEdit / NotebookEdit: `sync` the written
  node at once (so `stepcheck ci` is green right after the edit); if the bytes
  fail a gate, say so as additionalContext.
- Stop: block while any module of the project's session holds
  DIRTY_OMISSION_RISK, naming them; stop_hook_active short-circuits.
Everything else is allowed silently.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from kernel import StateKernel, _okf, _tokens

DEFAULT_READ_THRESHOLD = 1500
SCOPED_READ_MAX_LINES = 120
EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")


def registry() -> dict[str, str]:
    """session_id -> project root, from the per-user registry (STEPCHECK_HOME
    overrides ~/.stepcheck, exactly as the kernel reads it)."""
    home = Path(os.environ.get("STEPCHECK_HOME") or Path.home() / ".stepcheck")
    try:
        data = json.loads((home / "sessions.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {sid: root for sid, root in data.items() if isinstance(root, str)}


def sessions_for(path: Path) -> list[tuple[str, Path]]:
    """Registered sessions whose root contains path (or equals it), oldest first."""
    path = path.resolve()
    out = []
    for sid, root in registry().items():
        r = Path(root).resolve()
        if path == r or r in path.parents:
            out.append((sid, r))
    return out


def _session(event: dict, path: Path | None, kernel: StateKernel | None = None) -> tuple[str, Path] | None:
    explicit = event.get("stepcheck_session_id")
    if explicit:
        root = registry().get(explicit)
        return explicit, Path(root).resolve() if root else Path(event.get("cwd") or os.getcwd()).resolve()
    if path is None:
        return None
    found = sessions_for(path)
    if found:
        return found[-1]  # the newest session wins
    if kernel is not None and event.get("auto_init", True):
        cwd_raw = event.get("cwd")
        root = Path(cwd_raw).resolve() if cwd_raw else path.resolve().parent
        if root.is_dir() and (path.resolve() == root or root in path.resolve().parents) and _okf.tracked_files(root):
            sid = kernel.init_session(root)
            return sid, root
    return None


def _node_for(kernel: StateKernel, sid: str, root: Path, target: Path) -> dict | None:
    try:
        return kernel.locate(sid, target)  # no sources, no graph: one path comparison
    except KeyError:
        return None


def _deny(reason: str, context: str | None = None) -> dict:
    out = {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}
    if context is not None:
        out["additionalContext"] = context
    return {"hookSpecificOutput": out}


def _has_edit_payload(tool: str, tool_input: dict) -> bool:
    if tool == "Write":
        return isinstance(tool_input.get("content"), str)
    if tool == "Edit":
        old_s, new_s = tool_input.get("old_string"), tool_input.get("new_string")
        return isinstance(old_s, str) and isinstance(new_s, str) and bool(old_s) and old_s != new_s
    if tool == "MultiEdit":
        return isinstance(tool_input.get("edits"), list) and bool(tool_input.get("edits"))
    return False


def _stage_edit(tool: str, tool_input: dict, current: str) -> str | None:
    """Compute the staged full-module source for a native Edit/Write/MultiEdit
    call, or None when the tool input does not specify an applicable mutation."""
    if tool == "Write":
        content = tool_input.get("content")
        return content if isinstance(content, str) and content != current else None
    if tool == "Edit":
        old_s = tool_input.get("old_string")
        new_s = tool_input.get("new_string")
        if not isinstance(old_s, str) or not isinstance(new_s, str) or not old_s or old_s == new_s:
            return None
        if old_s not in current:
            return None
        if tool_input.get("replace_all"):
            return current.replace(old_s, new_s)
        return current.replace(old_s, new_s, 1)
    if tool == "MultiEdit":
        edits = tool_input.get("edits")
        if not isinstance(edits, list) or not edits:
            return None
        staged = current
        for item in edits:
            if not isinstance(item, dict):
                return None
            old_s = item.get("old_string")
            new_s = item.get("new_string")
            if not isinstance(old_s, str) or not isinstance(new_s, str) or not old_s or old_s not in staged:
                return None
            staged = staged.replace(old_s, new_s) if item.get("replace_all") else staged.replace(old_s, new_s, 1)
        return staged if staged != current else None
    return None


def _pre_tool_use(event: dict, kernel: StateKernel) -> dict:
    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not file_path:
        return {}
    try:
        target = Path(str(file_path))
    except (TypeError, ValueError):
        return {}
    found = _session(event, target, kernel)
    if found is None:
        return {}
    sid, root = found
    node = _node_for(kernel, sid, root, target)
    if node is None:
        return {}  # not a tracked module: the tool is fine
    if kernel.sync(sid, node["node_id"])["synced"]:
        node = _node_for(kernel, sid, root, target)  # status / size after adopting the tool's last write
    if tool == "Read":
        limit = tool_input.get("limit")
        if limit is not None:
            try:
                if 0 < int(limit) <= SCOPED_READ_MAX_LINES:
                    return {}  # bounded symbol slice read is allowed
            except (TypeError, ValueError):
                pass
        threshold = int(event.get("threshold") or DEFAULT_READ_THRESHOLD)
        raw_tokens = node["source_tokens"]
        if raw_tokens <= threshold:
            return {}
        payload = kernel.checkout(sid, node["node_id"], focus=[])
        context = (
            f"StepCheck context firewall: raw Read of {node['path']} ({raw_tokens:,} tokens) was replaced by "
            f"its OKF skeleton ({payload.token_count:,} tokens). Session {sid}, node {node['node_id']}. "
            "To see a body verbatim call checkout_context_frame(session_id, node_id, focus=[<symbol>]) "
            f"or Read with offset/limit (<= {SCOPED_READ_MAX_LINES} lines); "
            "edits are automatically verified through Gates A/B/C.\n\n" + payload.rendered()
        )
        return _deny(
            f"StepCheck: {node['path']} is a tracked module of session {sid} "
            f"({raw_tokens:,} tokens > {threshold:,}); its AST skeleton was supplied instead.",
            context,
        )
    if tool in EDIT_TOOLS and node["status"] == "LOCKED":
        # Any edit is a mutation, which Gate A rejects on a locked node. (A probe commit
        # of the unchanged source no longer works for this: a byte-identical commit is
        # the re-verification a locked node accepts.)
        reason = f"node '{node['node_id']}' is LOCKED — mutations are rejected at Gate A"
        return _deny(f"StepCheck Gate A: {reason}. Unlock it or edit through the gates.")
    if tool in EDIT_TOOLS and _has_edit_payload(tool, tool_input):
        try:  # the tool edits the file as it is now, which `sync` may have refused to adopt
            current = _okf.decode_source((root / node["path"]).read_bytes()).replace("\r\n", "\n")
        except (OSError, UnicodeError):
            current = kernel.node_source(sid, node["node_id"])
        staged = _stage_edit(tool, tool_input, current)
        if staged is not None:
            verdict = kernel.commit(sid, node["node_id"], source=staged, dry_run=True)
            if not verdict.accepted:
                return _deny(
                    f"StepCheck Gate {verdict.gate}: {verdict.error}. "
                    "Fix the violation (preserve required exports, decorators, and guard invariants) and retry the edit."
                )
    return {}


def _stop(event: dict, kernel: StateKernel) -> dict:
    if event.get("stop_hook_active"):
        return {}  # already blocked once this turn; never loop
    explicit = event.get("stepcheck_session_id")
    candidates = [(explicit, None)] if explicit else sessions_for(Path(event.get("cwd") or os.getcwd()))
    dirty: dict[str, list[str]] = {}
    for sid, _root in candidates:
        try:
            kernel.sync(sid)  # adopt the turn's last writes before judging it
            nodes = kernel.omission_report(sid)["dirty"]
        except KeyError:
            continue
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


def _post_tool_use(event: dict, kernel: StateKernel) -> dict:
    """Adopt the bytes an Edit / Write just wrote, through the gates, so the session
    (and `stepcheck ci`) is current the moment the tool returns."""
    if event.get("tool_name") not in EDIT_TOOLS:
        return {}
    tool_input = event.get("tool_input") or {}
    file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not file_path:
        return {}
    target = Path(str(file_path))
    found = _session(event, target, kernel)
    if found is None:
        return {}
    sid, root = found
    node = _node_for(kernel, sid, root, target)
    if node is None:
        return {}
    refused = kernel.sync(sid, node["node_id"])["rejected"].get(node["node_id"])
    if not refused:
        return {}
    return {"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": (
            f"StepCheck: the bytes just written to {node['path']} were NOT adopted by session {sid} "
            f"(Gate {refused}). The file on disk now violates a gate; restore or fix it."
        ),
    }}


def decide(event: dict, kernel: StateKernel) -> dict:
    """The hook answer for one lifecycle event, or {} for "no opinion"."""
    name = event.get("hook_event_name") or ("Stop" if "stop_hook_active" in event else "PreToolUse")
    if name == "Stop":
        return _stop(event, kernel)
    if name == "PreToolUse":
        return _pre_tool_use(event, kernel)
    if name == "PostToolUse":
        return _post_tool_use(event, kernel)
    return {}
