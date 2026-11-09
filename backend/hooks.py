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
- PreToolUse Read of a tracked module whose raw text exceeds the token
  threshold: ALLOW it (the module is synced into the session and a focus=[]
  checkout is charged like any frame) and ride the causal-cone frame — exports,
  preserved symbols, dependency interfaces — plus every Gate C invariant the
  module carries as additionalContext, so the agent sees the contract on the
  turn it first reads the file. Strict mode (STEPCHECK_STRICT_READ=1, or
  `strict_read: true` on the event) restores the skeleton-for-source denial.
  Scoped line-slice reads (limit <= 120) and modules under the threshold pass
  silently.
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
  fail a gate, say so as additionalContext. PostToolUse Bash syncs every
  registered session for the cwd and reports the files the gates refused.
- Stop: block while any module of the project's session holds
  DIRTY_OMISSION_RISK or is REJECTED, naming them; stop_hook_active
  short-circuits.
- Catch receipt: every block at Gate A / B / C (a denied edit, a refused Bash
  write, a blocked Stop) is phrased as a human-visible banner
  `[STEPCHECK CATCH — Gate X] <module> (<symbol>): <what would have broken>`
  and appended as one JSON line to <project>/.stepcheck/catches.jsonl
  (timestamp, module, symbol, gate, code, reason, hook, tool, session_id).
Everything else is allowed silently.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
from pathlib import Path

import declared
from kernel import StateKernel, _okf, _tokens

DEFAULT_READ_THRESHOLD = 1500
SCOPED_READ_MAX_LINES = 120
EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
STRICT_READ_ENV = "STEPCHECK_STRICT_READ"
CATCH_LOG = Path(".stepcheck") / "catches.jsonl"
INVARIANTS_SHOWN = 120  # the longest Gate C list a Read rides along; the rest is counted


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


def _allow(context: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow", "additionalContext": context}}


def _strict_read(event: dict) -> bool:
    if "strict_read" in event:
        return bool(event["strict_read"])
    return os.environ.get(STRICT_READ_ENV, "") not in ("", "0", "false", "no")


# ------------------------------------------------------------------ catch receipt


def banner(gate: str, module: str, symbol: str, what: str) -> str:
    """The human-visible form of one catch."""
    return f"[STEPCHECK CATCH — Gate {gate}] {module} ({symbol}): {what}"


_QUOTED = re.compile(r"'([^']+)'|\"([^\"]+)\"")


def symbol_of(error_text: str, module: str) -> str:
    """The symbol a gate verdict names, read back from its message: the first quoted
    token (`'@require_auth on charge'`, `'def charge'`, `'guard:charge:…'`,
    `'call:charge(…)'`), reduced to the bare name; `module` when the verdict is
    about the module itself (LOCKED, syntax, a missing export)."""
    m = _QUOTED.search(error_text)
    if not m:
        return "module"
    tok = m.group(1) or m.group(2)
    if " on " in tok:
        tok = tok.rsplit(" on ", 1)[1]
    tok = re.sub(r"^(async def|def|class) ", "", tok)
    if tok.startswith(("guard:", "call:")):
        tok = tok.split(":", 2)[1].split("(")[0]
    tok = tok.split(" x", 1)[0].strip()
    if not tok or tok == module or "/" in tok or tok.endswith((".py", ".ts", ".go", ".rs", ".java")):
        return "module"
    return tok


def changed_symbols(path: str, before: str, after: str) -> list[str]:
    """The definitions that differ between two sources of a Python module — top-level
    functions and classes, a method as `Class.method` — in source order; [] when it
    cannot be told (another language, a syntax error). Decorators are part of a
    definition, so a stripped `@dec` names its function."""
    if not str(path).endswith(".py"):
        return []
    import ast

    try:
        trees = ast.parse(before), ast.parse(after)
    except SyntaxError:
        return []

    def table(tree) -> dict[str, str]:
        out: dict[str, str] = {}
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out[n.name] = ast.dump(n)
                if isinstance(n, ast.ClassDef):
                    for m in n.body:
                        if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            out[f"{n.name}.{m.name}"] = ast.dump(m)
        return out

    old, new = table(trees[0]), table(trees[1])
    changed = [k for k in old if old[k] != new.get(k)]
    return [k for k in changed if "." in k or not any(c.startswith(k + ".") for c in changed)]


def code_of(gate: str, error, text: str) -> str:
    """A stable machine-readable code for a verdict: the Gate B subtype, or the
    kind of Gate A / C failure its message describes."""
    sub = getattr(error, "subtype", None)
    if sub:
        return str(sub)
    m = re.match(r"\s*([A-Z][A-Z_]{3,}):", text)
    if m:
        return m.group(1)
    if gate == "A":
        if "LOCKED" in text:
            return "LOCKED"
        if "syntax" in text.lower():
            return "SYNTAX"
        if "export" in text:
            return "EXPORT_REQUIRED"
        if "changed on disk" in text:
            return "STALE_SESSION"
        return "MECHANICAL"
    if gate == "C":
        if "'guard:" in text or "auto-mined" in text:
            return "GUARD_INVARIANT"
        if "'call:" in text:
            return "CALL_INVARIANT"
        if "budget" in text:
            return "EXECUTION_BUDGET"
        return "FRAME_INVARIANT"  # a declared `# okf-invariant:` expression over src / tree / ns
    return "OMISSION"


def record_catch(root: Path, *, module: str, symbol: str, gate: str, code: str, reason: str,
                 hook: str, tool: str | None, session_id: str | None) -> None:
    """Append one catch to <root>/.stepcheck/catches.jsonl; a receipt a human can read
    without the kernel. The same unchanged refusal reported again (a fresh in-process hook
    judging the same bytes) is not a new line: when the most recent line for this
    (session, module) already carries the same gate, code and reason, nothing is appended.
    Never raises: the hook's answer is the safety property."""
    line = {"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "module": module,
            "symbol": symbol, "gate": gate, "code": code, "reason": reason, "hook": hook, "tool": tool,
            "session_id": session_id}
    try:
        path = root / CATCH_LOG
        path.parent.mkdir(parents=True, exist_ok=True)
        if _same_as_last_catch(path, line):
            return
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _same_as_last_catch(path: Path, line: dict, tail_bytes: int = 65536) -> bool:
    """True when the newest logged catch for line's (session_id, module) has the same
    gate, code and reason. Reads only the file's tail."""
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - tail_bytes))
            chunk = f.read().decode("utf-8", errors="replace")
    except OSError:
        return False
    for raw in reversed(chunk.splitlines()):
        if not raw.strip():
            continue
        try:
            prev = json.loads(raw)
        except ValueError:
            continue
        if prev.get("session_id") == line["session_id"] and prev.get("module") == line["module"]:
            return all(prev.get(k) == line[k] for k in ("gate", "code", "reason"))
    return False


def _split_refusal(reason: str) -> tuple[str, str]:
    """`"B: INTRA_NODE_BODY_STUBBED: symbol 'compute' …"` -> ("B", "INTRA_NODE_BODY_STUBBED: symbol …")."""
    gate, _, rest = reason.partition(":")
    gate = gate.strip()
    return (gate if gate in ("A", "B", "C") else "B"), rest.strip() or reason


# ------------------------------------------------------------------ edits


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


def _read_context(sid: str, node: dict, raw_tokens: int, payload) -> str:
    """What rides along an allowed Read: the frame and the module's Gate C contract."""
    executed = list(node.get("invariants") or [])
    invariants = [i for i in node.get("invariants_auto_mined") or [] if i not in executed] + executed  # guards first
    shown = invariants[:INVARIANTS_SHOWN]
    tail = f"\n- … and {len(invariants) - len(shown)} more" if len(invariants) > len(shown) else ""
    contract = ("\n\n## Gate C invariants of this module (an edit that drops or weakens one is rejected)\n"
                + "".join(f"- {inv}\n" for inv in shown) + tail) if invariants else \
        "\n\n## Gate C invariants of this module\n- none mined yet (no leading `if …: raise` / `assert` guards)\n"
    return (
        f"StepCheck context firewall: {node['path']} is a tracked module of session {sid} "
        f"({raw_tokens:,} tokens; node {node['node_id']}, status {node['status']}). The Read is allowed; "
        "alongside it is the module's causal-cone frame — exports, preserved symbols and dependency interfaces — "
        "and the Gate C invariants every edit must keep. Edit through the gates (commit_verified_step, or the "
        f"native tools: this hook verifies them before any byte lands); re-read one symbol with offset/limit "
        f"(<= {SCOPED_READ_MAX_LINES} lines).\n\n" + payload.rendered() + contract
    )


def _ask(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": reason}}


def _bash_guard(tool_input: dict) -> dict:
    """An agent declaring its own allowance (`stepcheck allow …`, or a write to
    `.stepcheck/declared.jsonl`) is a request the human must approve, not a rubber stamp."""
    command = str(tool_input.get("command") or "")
    if not declared.is_tampering_command(command):
        return {}
    return _ask("StepCheck: this command declares a contract change (a guard or preserved symbol may be dropped on the "
                f"next edit). Approve only if you asked for it. Command: {command.strip()[:400]}")


def _pre_tool_use(event: dict, kernel: StateKernel) -> dict:
    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    if tool == "Bash":
        return _bash_guard(tool_input)
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
        if not _strict_read(event):
            return _allow(_read_context(sid, node, raw_tokens, payload))
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
        what = f"node '{node['node_id']}' is LOCKED — mutations are rejected at Gate A. Unlock it or edit through the gates."
        reason = banner("A", node["node_id"], "module", what)
        record_catch(root, module=node["node_id"], symbol="module", gate="A", code="LOCKED", reason=reason,
                     hook="PreToolUse", tool=tool, session_id=sid)
        return _deny(reason)
    if tool in EDIT_TOOLS and _has_edit_payload(tool, tool_input):
        try:  # the tool edits the file as it is now, which `sync` may have refused to adopt
            current = _okf.decode_source((root / node["path"]).read_bytes()).replace("\r\n", "\n")
        except (OSError, UnicodeError):
            current = kernel.node_source(sid, node["node_id"])
        staged = _stage_edit(tool, tool_input, current)
        if staged is not None:
            verdict = kernel.commit(sid, node["node_id"], source=staged, dry_run=True)
            if not verdict.accepted and verdict.gate in ("B", "C"):
                touched = changed_symbols(node["path"], current, staged)
                allowance = declared.find(root, node["path"], current, touched)
                if allowance is not None:
                    declared_verdict = kernel.commit(sid, node["node_id"], source=staged, dry_run=True, allow_deletion=True)
                    if declared_verdict.accepted:
                        declared.consume(root, allowance, staged)
                        note = (f"StepCheck: Gate {verdict.gate} would have refused this edit ({str(verdict.error)[:160]}); it passes "
                                f"as the contract change declared by `stepcheck allow` — reason: {allowance.get('reason')}. "
                                "The allowance is now used; the next edit of this file is gated strictly again.")
                        record_catch(root, module=node["node_id"], symbol=(touched[0] if touched else allowance.get("symbol") or "module"),
                                     gate=verdict.gate, code="DECLARED_ALLOWANCE", reason=note, hook="PreToolUse", tool=tool, session_id=sid)
                        return _allow(note)
            if not verdict.accepted:
                text = str(verdict.error)
                touched = changed_symbols(node["path"], current, staged)
                symbol = touched[0] if len(touched) == 1 else symbol_of(text, node["node_id"])
                if symbol == "module" and touched:
                    symbol = touched[0]
                hint = (" " + declared.hint(node["path"], symbol)) if verdict.gate in ("B", "C") else ""
                reason = banner(verdict.gate, node["node_id"], symbol,
                                f"{text}. Fix the violation (preserve required exports, decorators, and guard "
                                f"invariants) and retry the edit.{hint}")
                record_catch(root, module=node["node_id"], symbol=symbol, gate=verdict.gate,
                             code=code_of(verdict.gate, verdict.error, text), reason=reason,
                             hook="PreToolUse", tool=tool, session_id=sid)
                return _deny(reason)
    return {}


def _stop(event: dict, kernel: StateKernel) -> dict:
    if event.get("stop_hook_active"):
        return {}  # already blocked once this turn; never loop
    explicit = event.get("stepcheck_session_id")
    candidates = [(explicit, None)] if explicit else sessions_for(Path(event.get("cwd") or os.getcwd()))
    roots = dict(registry())
    dirty: dict[str, list[str]] = {}
    rejected: dict[str, list[str]] = {}
    catches: list[tuple[str, str, str, str, str, str]] = []  # (sid, module, symbol, gate, code, banner)
    for sid, _root in candidates:
        try:
            refused = {**kernel.refusals(sid), **kernel.sync(sid)["rejected"]}  # adopt the turn's last writes before judging it
            report = kernel.omission_report(sid)
        except KeyError:
            continue
        if report["dirty"]:
            dirty[sid] = report["dirty"]
            for nid in report["dirty"]:
                what = ("an exported signature it depends on changed, so its contract is unverified — check it out "
                        "(checkout_context_frame, focus=[]) and re-commit it (commit_verified_step)")
                catches.append((sid, nid, "DIRTY_OMISSION_RISK", "B", "INTER_NODE_DIRTY",
                                banner("B", nid, "DIRTY_OMISSION_RISK", what)))
        if report["rejected"]:
            rejected[sid] = [f"{nid} (Gate {refused[nid]})" if nid in refused else nid for nid in report["rejected"]]
            for nid in report["rejected"]:
                if nid in refused:
                    gate, rest = _split_refusal(refused[nid])
                    code = code_of(gate, None, rest)
                    what = f"the bytes on disk failed Gate {gate} and were not adopted — {rest}"
                else:
                    gate, code = "B", "REJECTED"
                    what = "the bytes on disk failed a gate earlier and were not adopted"
                catches.append((sid, nid, "REJECTED", gate, code, banner(gate, nid, "REJECTED", what)))
    if not dirty and not rejected:
        return {}
    for sid, module, symbol, gate, code, text in catches:
        root = Path(roots.get(sid) or event.get("cwd") or os.getcwd())
        record_catch(root, module=module, symbol=symbol, gate=gate, code=code, reason=text,
                     hook="Stop", tool=None, session_id=sid)
    parts = []
    if dirty:
        parts.append(
            "these modules hold DIRTY_OMISSION_RISK because an exported signature they depend on changed. "
            "Check each out (checkout_context_frame, focus=[]) and re-commit it (commit_verified_step) until "
            "check_omission_risks reports can_finalize: true. "
            + "; ".join(f"session {sid}: {', '.join(nodes)}" for sid, nodes in dirty.items())
        )
    if rejected:
        parts.append(
            "these modules are REJECTED: the bytes on disk (a shell command, a script, an editor) failed a gate "
            "and were not adopted. Restore the file or re-commit it through the gates (declare an intended "
            "deletion with allow_deletion). "
            + "; ".join(f"session {sid}: {', '.join(nodes)}" for sid, nodes in rejected.items())
        )
    banners = "\n".join(text for _sid, _m, _s, _g, _c, text in catches)
    return {"decision": "block", "reason": f"StepCheck omission guard:\n{banners}\n" + " ".join(parts)}


def _post_tool_use(event: dict, kernel: StateKernel) -> dict:
    """Adopt the bytes an Edit / Write just wrote, through the gates, so the session
    (and `stepcheck ci`) is current the moment the tool returns. A Bash command may
    have written anything: every registered session for the cwd is synced whole,
    and a file the gates refuse is reported (the Stop hook then blocks on it)."""
    if event.get("tool_name") == "Bash":
        explicit = event.get("stepcheck_session_id")
        candidates = [(explicit, None)] if explicit else sessions_for(Path(event.get("cwd") or os.getcwd()))
        roots = dict(registry())
        refused: list[str] = []
        for sid, _root in candidates:
            try:
                rejected = kernel.sync(sid)["rejected"]
            except KeyError:
                continue
            if rejected:
                paths = kernel.node_paths(sid)  # no analysis of the whole tree for a path lookup
                root = Path(roots.get(sid) or event.get("cwd") or os.getcwd())
                for nid, why in rejected.items():
                    gate, rest = _split_refusal(why)
                    module = paths.get(nid, nid)
                    symbol = symbol_of(rest, nid)
                    text = banner(gate, module, symbol, f"the shell command left bytes the gates refused to adopt "
                                                        f"(session {sid}) — {rest}")
                    record_catch(root, module=module, symbol=symbol, gate=gate, code=code_of(gate, None, rest),
                                 reason=text, hook="PostToolUse", tool="Bash", session_id=sid)
                    refused.append(text)
        if not refused:
            return {}
        return {"hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                "\n".join(refused) + "\nRestore each file or re-commit it through the gates; the Stop hook "
                "blocks while a module stays REJECTED."
            ),
        }}
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
    try:  # the bytes a declared allowance let through land as the declared deletion they are
        disk = _okf.decode_source((root / node["path"]).read_bytes())
    except (OSError, UnicodeError):
        disk = None
    if disk is not None and declared.declared_result(root, node["path"], disk) is not None:
        landed = kernel.commit(sid, node["node_id"], source=disk, allow_deletion=True)
        if landed.accepted:
            return {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                           "additionalContext": f"StepCheck: adopted the declared contract change of {node['path']} "
                                                                f"(attestation {landed.attestation['payload']['sha256'][:12]}…)."}}
    gate, rest = _split_refusal(refused)
    symbol = symbol_of(rest, node["node_id"])
    text = banner(gate, node["path"], symbol,
                  f"the bytes just written were NOT adopted by session {sid} — {rest}. The file on disk now "
                  "violates a gate; restore or fix it.")
    record_catch(root, module=node["path"], symbol=symbol, gate=gate, code=code_of(gate, None, rest), reason=text,
                 hook="PostToolUse", tool=event.get("tool_name"), session_id=sid)
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": text}}


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
