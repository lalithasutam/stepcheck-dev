"""Slice 39 — soundness of the structural judgement, and daemon / session coherence.

1. The `covered` guard: a leading guard on a typed or defaulted top-level function is owned by
   a runtime `call:` probe and left out of the full analysis's structural `guard:` set. A
   judgement without probes must hold it anyway: `stepcheck retro` (structural by default)
   catches `if amount <= 0: raise` dropped from `def charge(amount: int) -> int` at Gate C,
   loads no sandbox, mines it under its own `-structural` cache key, and that key never answers
   (or poisons) a full analysis in either order. (Pinned as a contract: the committed Slice 38
   code already held it; Slice 39 gives the structural facts their own key and skips the probe
   and branch miners for them.)
2. `kernel.build_id()` identifies the kernel code a process runs; the gateway reports it on
   `/health` and on every hook answer; the installed relay computes the same id from disk
   with the standard library and retires a daemon whose id differs.
3. A `stepcheck allow` written by the CLI is honoured at once by a live gateway's
   PreToolUse and its Stop (the declaration is read from disk, the session reloaded).
4. Older sessions of a root are history: after a declared edit in the active session they do
   not block Stop, and `prune_sessions` archives the clean idle ones beyond the three most
   recent while keeping one that still has something to say.
5. The active session is bound to the Claude chat driving it (`.stepcheck/chat.json`). When a
   different chat takes over, the session it inherits is reconciled with the committed tree
   first: after `allow` + commit, `checkout -b`, `reset --hard` and a commit made outside any
   chat, the second chat's Stop is not blocked by the first chat's baseline. Inside one chat a
   commit launders nothing, and an uncommitted refused write survives a change of chat.
6. A real daemon on a stale build: `/health` says so, the relay retires it, decides the call
   with the code on disk and a fresh daemon comes up on the new build; a `stepcheck allow` from
   the CLI is then honoured by that live daemon's PreToolUse, PostToolUse and Stop.
7. The relay runs as whatever `python` is on PATH. When that interpreter cannot import the
   kernel, the decision is delegated to the interpreter `stepcheck hooks` recorded — a guard
   drop is denied, not waved through — and the daemon is started with it.
8. `connect` wires MCP as a stdio command (`stepcheck mcp`) for Claude Code and Cursor: it
   answers with nothing listening on any port (a cold boot), keeps stdout pure JSON-RPC, and
   shares the session files with the hooks' gateway.
9. The wheel built from `pyproject.toml` carries every backend module and runs `--version`,
   `retro`, `diff`, `allow` and `connect` with no checkout on the path.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

from fastapi.testclient import TestClient

import cli
import hooks
import kernel as K
from kernel import StateKernel

BACKEND = Path(__file__).resolve().parents[1]

CHARGE = textwrap.dedent('''\
    def charge(amount: int) -> int:
        if amount <= 0:
            raise ValueError(amount)
        return amount * 2


    def note(x):
        return x
    ''')
CHARGE_DROPPED = CHARGE.replace("    if amount <= 0:\n        raise ValueError(amount)\n", "")

GUARDED = "def f(x):\n    if x < 0:\n        raise ValueError(x)\n    return x + 1\n\n\ndef g(y):\n    return y\n"
DROPPED = "def f(x):\n    return x + 1\n\n\ndef g(y):\n    return y\n"


def _git(root: Path, *args: str) -> str:
    done = subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "user.email=t@t", "-c", "user.name=t",
                           "-c", "commit.gpgsign=false", *args], cwd=root, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=300)
    if done.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {done.stderr[-400:]}")
    return done.stdout


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")


# ------------------------------------------------------- 1. the covered guard gap


def test_retro_holds_a_probe_covered_leading_guard_structurally_and_loads_no_sandbox(tmp_path, capsys):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _write(root, "billing.py", CHARGE)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "charge with its guard")
    _write(root, "billing.py", CHARGE_DROPPED)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "simplify charge")
    sha = _git(root, "rev-parse", "--short=7", "HEAD").strip()

    loads0 = StateKernel().perf_stats()["gate_c_sandbox_loads"]
    assert cli.main(["retro", str(root), "--jobs", "1", "--json"]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["run_probes"] is False
    assert [(f["short"], f["gate"], f["symbol"]) for f in r["tier1"]] == [(sha, "C", "charge")], r["tier1"]
    assert any(g == "guard:charge:if amount <= 0 raises ValueError" for g in r["tier1"][0]["guards_removed"])
    assert StateKernel().perf_stats()["gate_c_sandbox_loads"] == loads0  # zero probe execution on either side

    k = StateKernel()
    v = k.judge_transition("billing.py", CHARGE, CHARGE_DROPPED, root=root, run_probes=False)
    assert not v.accepted and v.gate == "C" and "charge" in str(v.error)
    # the structural analysis lives under its own key: a full analysis of the same text still mines the probe
    assert "call:charge(amount=0) raises ValueError" in k.mined_invariants("billing.py", CHARGE, root=root)
    assert "guard:charge:if amount <= 0 raises ValueError" in k.structural_guards("billing.py", CHARGE, root=root)
    assert "guard:charge:if amount <= 0 raises ValueError" not in k.mined_invariants("billing.py", CHARGE, root=root)

    # the structural facts live under their own `-structural` key and are remembered there: a repeat judgement
    # of the same text is a memory hit, not another parse, and it can never be recalled by a full analysis
    before = k.perf_stats()
    assert k.judge_transition("billing.py", CHARGE, CHARGE_DROPPED, root=root, run_probes=False).gate == "C"
    after = k.perf_stats()
    assert after["full_parses"] == before["full_parses"], (before, after)
    assert after["analysis_memory_hits"] > before["analysis_memory_hits"]  # not analysis_full


def test_a_structural_analysis_never_answers_a_full_one_through_the_disk_cache(tmp_path):
    root = tmp_path / "proj"
    _write(root, "billing.py", CHARGE)
    first = StateKernel()  # writes the disk cache for this root
    sid = first.init_session(root)
    assert first.judge_transition("billing.py", CHARGE, CHARGE_DROPPED, root=root, run_probes=False).gate == "C"
    second = StateKernel()  # a fresh process in spirit: the disk cache is all it shares with `first`
    node = next(n for n in second.graph(sid)["nodes"] if n["path"] == "billing.py")
    assert "call:charge(amount=0) raises ValueError" in node["invariants_auto_mined"]
    assert second.judge_transition("billing.py", CHARGE, CHARGE_DROPPED, root=root, run_probes=True).gate == "C"


# ------------------------------------------------------- 2. kernel build id


def test_build_id_identifies_the_kernel_code_and_the_gateway_and_relay_agree(tmp_path, monkeypatch):
    import server

    a = K.build_id()
    assert a == K.build_id() and re.fullmatch(r"[0-9a-f]{16}", a)
    copy = tmp_path / "backend"
    shutil.copytree(BACKEND, copy, ignore=shutil.ignore_patterns("__pycache__", "tests", ".stepcheck", "*.pyc"))
    assert K.build_id(copy) == a  # the same bytes are the same build
    with (copy / "kernel" / "_okf.py").open("a", encoding="utf-8") as f:
        f.write("\n# a one-line change is a different build\n")
    changed = K.build_id(copy)
    assert changed != a

    # the installed relay computes the same id from disk with the standard library alone
    ns: dict = {"__name__": "relay"}
    exec(compile(cli._HOOK_SCRIPT.replace("__STEPCHECK_HOOK_URL__", "http://127.0.0.1:1/v1/step/hook"), "stepcheck_hook", "exec"), ns)
    assert ns["_local_build_id"](str(BACKEND)) == a and ns["_local_build_id"](str(copy)) == changed
    monkeypatch.setenv("STEPCHECK_BACKEND", str(BACKEND))
    monkeypatch.setenv("STEPCHECK_HOOK_AUTOSTART", "0")
    assert ns["_retire_if_stale"]({"build_id": a, "daemon": True, "pid": 1}) is False
    assert ns["_retire_if_stale"]({"build_id": "0" * 16, "daemon": False, "pid": 1}) is True  # a hand-started gateway: reported, not killed

    with TestClient(server.app) as c:
        h = c.get("/health").json()
        assert h["status"] == "ok" and h["kernel_build_id"] == server.BUILD_ID == a
        assert h["kernel_build_id_on_disk"] == a and h["stale"] is False
        resp = c.post("/v1/step/hook", json={"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(tmp_path),
                                            "tool_input": {"command": "git status"}})
        assert resp.json() == {}  # the body stays the bare hook answer: an allow is still `{}`
        assert resp.headers["x-stepcheck-build"] == a and resp.headers["x-stepcheck-daemon"] == "0"
        assert resp.headers["x-stepcheck-pid"].isdigit()


# ------------------------------------------------------- 3. CLI allow honoured by a live gateway


def test_cli_allow_is_honoured_at_once_by_a_live_gateway_pretooluse_and_stop(tmp_path, capsys):
    import server

    root = tmp_path / "proj"
    _write(root, "mod.py", GUARDED)
    path = root / "mod.py"
    with TestClient(server.app) as c:
        sid = server.KERNEL.init_session(root)
        event = {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(root), "stepcheck_session_id": sid,
                 "tool_input": {"file_path": str(path), "old_string": "    if x < 0:\n        raise ValueError(x)\n", "new_string": ""}}
        denied = c.post("/v1/step/hook", json=event).json()
        assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "stepcheck allow mod.py f" in denied["hookSpecificOutput"]["permissionDecisionReason"]

        assert cli.main(["allow", str(path), "f", "--reason", "the caller validates x", "--root", str(root)]) == 0  # the CLI, out of band
        capsys.readouterr()
        allowed = c.post("/v1/step/hook", json=event).json()
        assert allowed["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert "the caller validates x" in allowed["hookSpecificOutput"]["additionalContext"]

        path.write_text(DROPPED, encoding="utf-8", newline="\n")
        post = c.post("/v1/step/hook", json={**event, "hook_event_name": "PostToolUse"}).json()
        assert "adopted the declared contract change" in post["hookSpecificOutput"]["additionalContext"]
        stop = c.post("/v1/step/hook", json={"hook_event_name": "Stop", "cwd": str(root), "stepcheck_session_id": sid}).json()
        assert "decision" not in stop, stop
        assert server.KERNEL.omission_report(sid) == {"dirty": [], "rejected": [], "can_finalize": True}


# ------------------------------------------------------- 4. older sessions are history


def test_older_sessions_do_not_block_stop_after_a_declared_edit_and_idle_ones_are_pruned(tmp_path):
    root = tmp_path / "proj"
    _write(root, "mod.py", GUARDED)
    k = StateKernel()
    old = k.init_session(root)
    active = k.init_session(root)
    assert k.commit(active, "mod", source=DROPPED, allow_deletion=True).accepted  # declared in the active session
    assert "mod" in k.sync(old)["rejected"]  # the historical session would veto the tree it never saw

    assert hooks.active_sessions_for(root) == [(active, root.resolve())]
    assert hooks.decide({"hook_event_name": "Stop", "cwd": str(root)}, k) == {}  # only the active session speaks
    blocked = hooks.decide({"hook_event_name": "Stop", "cwd": str(root), "stepcheck_session_id": old}, k)
    assert blocked.get("decision") == "block"  # asked explicitly, history still answers for itself

    # a commit advancing HEAD: a session opened on the new HEAD is clean, the older ones stay quiet
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "the dropped guard is the committed truth now")
    newest = k.init_session(root)
    assert hooks.decide({"hook_event_name": "Stop", "cwd": str(root)}, k) == {}
    assert k.omission_report(newest)["can_finalize"]

    # pruning: clean idle sessions beyond the three most recent retire; the one holding a REJECTED node is kept
    for _ in range(3):
        k.init_session(root)
    before = sorted(p.stem for p in (root / ".stepcheck" / "sessions").glob("sk-*.json"))
    archived = K.prune_sessions(root, keep=3)
    after = sorted(p.stem for p in (root / ".stepcheck" / "sessions").glob("sk-*.json"))
    assert len(before) == 6 and old in after and len(after) == 4 and set(archived) == set(before) - set(after)
    assert all((root / ".stepcheck" / "sessions_archive" / f"{sid}.json").exists() for sid in archived)
    assert not any(sid in hooks.registry() for sid in archived)
    assert K.prune_sessions(root, keep=3) == []  # idempotent


# ------------------------------------------------------- 5. git chaos across two chats

TWO_GUARDS = ("def f(x):\n    if x < 0:\n        raise ValueError(x)\n    return x + 1\n\n\n"
              "def g(y):\n    if y is None:\n        raise TypeError(y)\n    return y\n")
F_GUARD = "    if x < 0:\n        raise ValueError(x)\n"
G_GUARD = "    if y is None:\n        raise TypeError(y)\n"


def _event(root: Path, name: str, chat: str, **extra) -> dict:
    return {"hook_event_name": name, "cwd": str(root), "session_id": chat, **extra}


def test_git_chaos_between_two_chats_never_lets_the_first_chats_baseline_block_the_second(tmp_path, capsys):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _write(root, "mod.py", TWO_GUARDS)
    _write(root, ".gitignore", ".stepcheck/\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "c1")
    path = root / "mod.py"
    edit = {"tool_name": "Edit", "tool_input": {"file_path": str(path), "old_string": F_GUARD, "new_string": ""}}

    # chat A: an edit the gates refuse, declared by the human (`stepcheck allow`), made, adopted, committed
    a = StateKernel()
    assert hooks.decide(_event(root, "PreToolUse", "chat-A", **edit), a)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert cli.main(["allow", str(path), "f", "--reason", "the caller validates x", "--root", str(root)]) == 0
    capsys.readouterr()
    assert hooks.decide(_event(root, "PreToolUse", "chat-A", **edit), a)["hookSpecificOutput"]["permissionDecision"] == "allow"
    _write(root, "mod.py", TWO_GUARDS.replace(F_GUARD, ""))
    hooks.decide(_event(root, "PostToolUse", "chat-A", **edit), a)
    _git(root, "add", "mod.py")
    _git(root, "commit", "-q", "-m", "c2: the declared drop")
    c2 = _git(root, "rev-parse", "HEAD").strip()
    assert hooks.decide(_event(root, "Stop", "chat-A"), a) == {}
    session_a = [p.stem for p in (root / ".stepcheck" / "sessions").glob("sk-*.json")]
    assert len(session_a) == 1
    assert json.loads((root / ".stepcheck" / "chat.json").read_text(encoding="utf-8")) == {"chat": "chat-A", "session": session_a[0]}

    # between chats: a branch, a hard reset back to c1 (f's guard returns) …
    _git(root, "checkout", "-q", "-b", "feature")
    _git(root, "reset", "-q", "--hard", "HEAD~1")
    assert hooks.decide(_event(root, "Stop", "chat-between"), StateKernel()) == {}  # a guard coming back is no regression
    # … forward to c2 again, and a commit nobody declared, made in a plain editor: g's guard goes too
    _git(root, "reset", "-q", "--hard", c2)
    _write(root, "mod.py", TWO_GUARDS.replace(F_GUARD, "").replace(G_GUARD, ""))
    _git(root, "commit", "-q", "-am", "c3: a human drops g's guard outside any chat")

    # chat B, a fresh process: session A's baseline (it last saw c1) does not veto the committed tree
    b = StateKernel()
    assert hooks.decide(_event(root, "Stop", "chat-B"), b) == {}
    assert b.omission_report(session_a[0]) == {"dirty": [], "rejected": [], "can_finalize": True}
    assert json.loads((root / ".stepcheck" / "chat.json").read_text(encoding="utf-8"))["chat"] == "chat-B"
    # and the session is not blind afterwards: chat B's own guard drop is still denied
    h = "\n\ndef h(z):\n    if not z:\n        raise KeyError(z)\n    return z\n"
    _write(root, "mod.py", path.read_text(encoding="utf-8") + h)
    assert hooks.decide(_event(root, "Stop", "chat-B"), b) == {}  # adding a guarded function is clean
    _git(root, "commit", "-q", "-am", "c4: h, guarded")
    drop_h = {"tool_name": "Edit", "tool_input": {"file_path": str(path), "old_string": "    if not z:\n        raise KeyError(z)\n", "new_string": ""}}
    assert hooks.decide(_event(root, "PreToolUse", "chat-B", **drop_h), b)["hookSpecificOutput"]["permissionDecision"] == "deny"

    # the boundary, both ways. Inside ONE chat a commit launders nothing: bytes the gates refused
    # stay REJECTED after the agent commits them itself …
    _write(root, "mod.py", path.read_text(encoding="utf-8").replace("    if not z:\n        raise KeyError(z)\n", ""))
    _git(root, "commit", "-q", "-am", "c5: chat B commits its own undeclared drop")
    blocked = hooks.decide(_event(root, "Stop", "chat-B"), b)
    assert blocked.get("decision") == "block" and "REJECTED" in blocked["reason"]
    # … and an UNCOMMITTED refused write survives a change of chat: it is not history, it is an open risk
    _git(root, "reset", "-q", "--hard", "HEAD~1")  # h's guard back, committed truth again
    assert hooks.decide(_event(root, "Stop", "chat-B"), b) == {}
    _write(root, "mod.py", path.read_text(encoding="utf-8").replace("    if not z:\n        raise KeyError(z)\n", ""))
    still = hooks.decide(_event(root, "Stop", "chat-C"), StateKernel())
    assert still.get("decision") == "block" and "REJECTED" in still["reason"]


# ------------------------------------------------------- 6. a live daemon: stale build replaced, `allow` honoured


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _health(port: int) -> dict | None:
    import urllib.request

    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as r:
            return json.loads(r.read())
    except (OSError, ValueError):
        return None


def _until(fn, seconds: float = 90.0):
    import time

    deadline = time.monotonic() + seconds
    while True:
        value = fn()
        if value or time.monotonic() >= deadline:
            return value
        time.sleep(0.25)


def _relay(script: Path, event: dict, env: dict, python: list[str] | None = None) -> subprocess.CompletedProcess:
    import sys

    return subprocess.run([*(python or [sys.executable]), str(script)], input=json.dumps(event), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env, timeout=180)


def _kill(pid) -> None:
    import os
    import signal

    try:
        os.kill(int(pid), signal.SIGTERM)
    except (OSError, TypeError, ValueError):
        pass


def test_a_live_daemon_on_a_stale_build_is_replaced_by_the_relay_and_honours_cli_allow_at_once(tmp_path, capsys):
    import os

    backend = tmp_path / "backend"  # the daemon's code: a copy, so the test can move its build id
    shutil.copytree(BACKEND, backend, ignore=shutil.ignore_patterns("__pycache__", "tests", ".stepcheck", "*.pyc"))
    root = tmp_path / "proj"
    _write(root, "mod.py", GUARDED)
    port = _free_port()
    assert cli.main(["hooks", str(root), "--url", f"http://127.0.0.1:{port}/v1/step/hook"]) == 0
    capsys.readouterr()
    script = root / ".claude" / "hooks" / "stepcheck_hook.py"
    env = dict(os.environ, STEPCHECK_BACKEND=str(backend), STEPCHECK_HOOK_AUTOSTART="1", STEPCHECK_HOOK_WARM_WAIT="90",
               STEPCHECK_HOOK_TIMEOUT="30", CLAUDE_PROJECT_DIR=str(root))
    env.pop("STEPCHECK_PYTHON", None)
    pids: list = []
    try:
        # SessionStart, nothing listening: the relay starts the daemon and waits for it
        assert _relay(script, _event(root, "SessionStart", "chat-1"), env).returncode == 0
        first = _until(lambda: _health(port))
        assert first, (Path(os.environ["STEPCHECK_HOME"]) / f"gateway-{port}.log").read_text(encoding="utf-8", errors="replace")[-2000:]
        pids.append(first["pid"])
        built = K.build_id(backend)
        assert first["daemon"] is True and first["kernel_build_id"] == built and first["stale"] is False

        # the code on disk moves on; the daemon keeps answering from the code it loaded
        with (backend / "kernel" / "_okf.py").open("a", encoding="utf-8") as f:
            f.write("\n# a later build\n")
        moved = K.build_id(backend)
        stale = _health(port)
        assert moved != built and stale["kernel_build_id"] == built and stale["kernel_build_id_on_disk"] == moved and stale["stale"] is True

        # the next gated hook call notices, retires that daemon, decides in-process, and a fresh one comes up
        edit = {"tool_name": "Edit", "tool_input": {"file_path": str(root / "mod.py"),
                                                    "old_string": "    if x < 0:\n        raise ValueError(x)\n", "new_string": ""}}
        denied = _relay(script, _event(root, "PreToolUse", "chat-1", **edit), env)
        assert "stale kernel code" in denied.stderr and f"build {built} vs {moved}" in denied.stderr, denied.stderr
        assert denied.returncode == 2 and "Gate C" in denied.stderr  # decided by the code on disk, not waved through
        fresh = _until(lambda: (lambda h: h if h and h["kernel_build_id"] == moved else None)(_health(port)))
        assert fresh and fresh["pid"] != first["pid"] and fresh["stale"] is False and fresh["daemon"] is True
        pids.append(fresh["pid"])

        # `stepcheck allow` from the CLI, out of band: the LIVE daemon honours it on the very next call
        again = _relay(script, _event(root, "PreToolUse", "chat-1", **edit), env)
        assert again.returncode == 2 and "stale kernel code" not in again.stderr  # answered warm by the fresh daemon
        assert cli.main(["allow", str(root / "mod.py"), "f", "--reason", "the caller validates x", "--root", str(root)]) == 0
        capsys.readouterr()
        allowed = _relay(script, _event(root, "PreToolUse", "chat-1", **edit), env)
        assert allowed.returncode == 0, allowed.stderr
        assert json.loads(allowed.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"
        _write(root, "mod.py", DROPPED)
        post = _relay(script, _event(root, "PostToolUse", "chat-1", **edit), env)
        assert "adopted the declared contract change" in post.stdout, post.stdout + post.stderr
        stop = _relay(script, _event(root, "Stop", "chat-1"), env)
        assert stop.returncode == 0 and "block" not in stop.stdout, stop.stdout + stop.stderr
        assert _health(port)["pid"] == fresh["pid"]  # all of it by the same live daemon
    finally:
        live = _health(port)
        for pid in {*pids, *([live["pid"]] if live else [])}:
            _kill(pid)


# ------------------------------------------------------- 7. the relay's interpreter


def test_the_relay_gates_through_the_recorded_interpreter_when_the_python_on_path_lacks_the_kernels_dependencies(tmp_path, capsys):
    import os
    import sys

    import pytest

    bare = getattr(sys, "_base_executable", None) or sys.executable
    if os.path.normcase(os.path.abspath(bare)) == os.path.normcase(os.path.abspath(sys.executable)) or subprocess.run(
            [bare, "-c", "import yaml, fastapi"], capture_output=True).returncode == 0:
        pytest.skip("needs a second interpreter without StepCheck's dependencies (a virtualenv's base python)")
    root = tmp_path / "proj"
    _write(root, "mod.py", GUARDED)
    port = _free_port()  # nothing listens here: the gateway is offline, as after a reboot
    assert cli.main(["hooks", str(root), "--url", f"http://127.0.0.1:{port}/v1/step/hook"]) == 0
    capsys.readouterr()
    recorded = json.loads((Path(os.environ["STEPCHECK_HOME"]) / "interpreters.json").read_text(encoding="utf-8"))
    assert list(recorded.values()) == [sys.executable]  # `stepcheck hooks` recorded the interpreter that has the kernel
    script = root / ".claude" / "hooks" / "stepcheck_hook.py"
    env = dict(os.environ, STEPCHECK_BACKEND=str(BACKEND), STEPCHECK_HOOK_AUTOSTART="0", CLAUDE_PROJECT_DIR=str(root))
    env.pop("STEPCHECK_PYTHON", None)
    drop = _event(root, "PreToolUse", "chat-1", tool_name="Edit", tool_input={
        "file_path": str(root / "mod.py"), "old_string": "    if x < 0:\n        raise ValueError(x)\n", "new_string": ""})

    # run as the hooks are installed (`python -S`) by the bare interpreter: the guard drop is still denied
    denied = _relay(script, drop, env, python=[bare, "-S"])
    assert denied.returncode == 2 and "Gate C" in denied.stderr, denied.stderr
    assert json.loads(denied.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    clean = dict(drop, tool_input={"file_path": str(root / "mod.py"), "old_string": "return x + 1", "new_string": "return x + 2"})
    assert _relay(script, clean, env, python=[bare, "-S"]).returncode == 0

    # the daemon is launched with that interpreter too
    ns: dict = {"__name__": "relay"}
    exec(compile(script.read_text(encoding="utf-8"), "stepcheck_hook", "exec"), ns)
    assert ns["_python"](str(BACKEND)) == sys.executable

    # with no interpreter recorded there is nobody to ask: the documented last resort, said out loud
    (Path(os.environ["STEPCHECK_HOME"]) / "interpreters.json").unlink()
    lost = _relay(script, drop, env, python=[bare, "-S"])
    assert lost.returncode == 0 and "in-process check failed" in lost.stderr


# ------------------------------------------------------- 8. MCP over stdio: a cold boot connects


def test_connect_wires_a_stdio_mcp_server_that_answers_with_no_gateway_listening(tmp_path, capsys):
    import os
    import queue
    import threading

    root = tmp_path / "proj"
    _write(root, "mod.py", GUARDED)
    assert cli.main(["connect", str(root), "--cursor", "--no-git-hook", "--no-retro"]) == 0
    assert ".mcp.json: wired stepcheck -> stdio" in capsys.readouterr().out
    claude = json.loads((root / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["stepcheck"]
    cursor = json.loads((root / ".cursor" / "mcp.json").read_text(encoding="utf-8"))["mcpServers"]["stepcheck"]
    assert claude["type"] == "stdio" and claude["args"][-1] == "mcp" and Path(claude["command"]).is_file()
    assert cursor == {"command": claude["command"], "args": claude["args"]}
    for text in ((root / ".mcp.json").read_text(encoding="utf-8"), (root / ".cursor" / "mcp.json").read_text(encoding="utf-8")):
        assert "8420" not in text and "http" not in text  # nothing that needs a listening port
    before = (root / ".mcp.json").read_bytes()
    assert cli.main(["connect", str(root), "--cursor", "--no-git-hook", "--no-retro"]) == 0  # idempotent
    capsys.readouterr()
    assert (root / ".mcp.json").read_bytes() == before

    # launch it exactly as the editor would, with no gateway anywhere
    proc = subprocess.Popen([claude["command"], *claude["args"]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, cwd=tmp_path, env=dict(os.environ))
    lines: "queue.Queue[bytes]" = queue.Queue()
    threading.Thread(target=lambda: [lines.put(ln) for ln in proc.stdout], daemon=True).start()
    seen: list[dict] = []

    def call(method: str, params: dict, rid: int | None = None) -> dict | None:
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        if rid is not None:
            msg["id"] = rid
        proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        proc.stdin.flush()
        while rid is not None:
            answer = json.loads(lines.get(timeout=120))  # stdout is JSON-RPC and nothing else
            seen.append(answer)
            if answer.get("id") == rid:
                assert "error" not in answer, answer
                return answer["result"]
        return None

    def tool(name: str, arguments: dict, rid: int) -> dict:
        result = call("tools/call", {"name": name, "arguments": arguments}, rid)
        assert not result.get("isError"), result
        return json.loads(result["content"][0]["text"])

    try:
        init = call("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                   "clientInfo": {"name": "cold-boot", "version": "0"}}, 1)
        assert init["serverInfo"]["name"] == "stepcheck-dev"
        call("notifications/initialized", {})
        names = {t["name"] for t in call("tools/list", {}, 2)["tools"]}
        assert names == {"init_project_session", "checkout_context_frame", "commit_verified_step", "lock_module_invariants",
                         "check_omission_risks", "get_token_savings"}
        sid = tool("init_project_session", {"project_root": str(root)}, 3)["session_id"]
        assert sid.startswith("sk-") and (root / ".stepcheck" / "sessions" / f"{sid}.json").is_file()
        refused = tool("commit_verified_step", {"session_id": sid, "node_id": "mod", "source": DROPPED}, 4)
        assert refused["accepted"] is False and refused["gate"] == "C"

        # the stdio server and the hooks share the session files: a commit another process lands
        # (here: this one, as the hooks' gateway would) is what the next tool call answers from
        other = StateKernel()
        assert other.commit(sid, "mod", source=GUARDED + "\n\ndef added(z):\n    return z\n").accepted
        frame = tool("checkout_context_frame", {"session_id": sid, "node_id": "mod", "focus": []}, 5)
        assert "added" in frame["rendered"]
        assert tool("check_omission_risks", {"session_id": sid}, 6)["can_finalize"] is True
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
    assert all(m.get("jsonrpc") == "2.0" for m in seen)


# ------------------------------------------------------- 9. the wheel, away from the checkout


def test_the_built_wheel_runs_every_command_without_the_checkout_on_the_path(tmp_path):
    import os
    import sys
    import zipfile

    import pytest

    src = tmp_path / "src"
    src.mkdir()
    for name in ("pyproject.toml", "README.md"):
        shutil.copy2(BACKEND.parent / name, src / name)
    shutil.copytree(BACKEND, src / "backend", ignore=shutil.ignore_patterns("__pycache__", ".stepcheck", "*.pyc", ".pytest_cache"))
    out = tmp_path / "dist"
    built = subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--disable-pip-version-check", "-q", "-w", str(out), str(src)],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, cwd=tmp_path)
    if built.returncode != 0 and re.search(r"Could not find a version|No matching distribution|getaddrinfo|Connection|Temporary failure|"
                                           r"ProxyError|timed out|Network is unreachable", built.stdout + built.stderr, re.I):
        pytest.skip("the isolated wheel build needs setuptools>=68 from the package index (offline)")
    assert built.returncode == 0, (built.stdout + built.stderr)[-3000:]
    (wheel,) = out.glob("stepcheck_dev-*.whl")
    import tomllib

    version = tomllib.loads((BACKEND.parent / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert wheel.name.startswith(f"stepcheck_dev-{version}-")
    with zipfile.ZipFile(wheel) as z:
        names = set(z.namelist())
        meta = z.read(next(n for n in names if n.endswith(".dist-info/METADATA"))).decode("utf-8").replace("\r\n", "\n")
        entry = z.read(next(n for n in names if n.endswith(".dist-info/entry_points.txt"))).decode("utf-8")
    shipped = {p.relative_to(BACKEND.parent).as_posix() for p in [*BACKEND.glob("*.py"), *(BACKEND / "kernel").glob("*.py")]}
    assert shipped <= names, sorted(shipped - names)  # every backend module, `retro`, `declared` and `wiring` among them
    assert {"backend/retro.py", "backend/declared.py", "backend/wiring.py", "backend/hooks.py", "backend/server.py"} <= shipped
    assert not any(n.startswith("backend/tests/") for n in names)
    assert f"\nVersion: {version}\n" in meta and "stepcheck = backend.cli:main" in entry

    site = tmp_path / "site"  # the wheel unpacked on its own; dependencies come from this interpreter
    installed = subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "--disable-pip-version-check", "-q",
                                "--target", str(site), str(wheel)], capture_output=True, text=True, timeout=600, cwd=tmp_path)
    assert installed.returncode == 0, installed.stderr[-2000:]
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _write(repo, "billing.py", CHARGE)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "charge with its guard")
    _write(repo, "billing.py", CHARGE_DROPPED)
    _git(repo, "commit", "-q", "-am", "simplify charge")

    # -I: no PYTHONPATH, no cwd on sys.path; the wheel's `backend` is first, the checkout's is never imported
    boot = ("import sys; sys.path.insert(0, sys.argv.pop(1)); from backend.cli import main; "
            "sys.argv[0] = 'stepcheck'; sys.exit(main(sys.argv[1:]))")
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "STEPCHECK_BACKEND")}

    def run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-I", "-X", "utf8", "-c", boot, str(site), *args], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", env=env, cwd=repo, timeout=600)

    where = subprocess.run([sys.executable, "-I", "-c",
                            "import sys; sys.path.insert(0, sys.argv[1]); import backend.cli as c, json; import retro, declared, "
                            "wiring, hooks, kernel, server; print(json.dumps([m.__file__ for m in (c, retro, declared, wiring, "
                            "hooks, kernel, server)]))", str(site)], capture_output=True, text=True, env=env, cwd=repo, timeout=600)
    assert where.returncode == 0, where.stderr[-2000:]
    files = [Path(p).resolve() for p in json.loads(where.stdout.strip().splitlines()[-1])]
    assert all(site.resolve() in p.parents for p in files), files  # not one module from the checkout

    v = run("--version")
    assert v.returncode == 0 and v.stdout.strip() == f"stepcheck {version}", v.stdout + v.stderr
    retro = run("retro", str(repo), "--jobs", "1", "--json")
    assert retro.returncode == 0, retro.stderr[-2000:]
    report = json.loads(retro.stdout)
    assert [(f["gate"], f["symbol"]) for f in report["tier1"]] == [("C", "charge")]
    clean = run("diff", str(repo))
    assert clean.returncode == 0, clean.stdout + clean.stderr
    _write(repo, "billing.py", CHARGE_DROPPED.replace("return amount * 2", "return amount * 3"))
    assert run("diff", str(repo)).returncode == 0  # a body change, no contract lost
    _git(repo, "checkout", "-q", "HEAD~1", "--", "billing.py")
    _write(repo, "billing.py", CHARGE_DROPPED)
    dirty = run("diff", str(repo), "--base", "HEAD~1")
    assert dirty.returncode == 1 and "charge" in dirty.stdout, dirty.stdout + dirty.stderr
    allow = run("allow", str(repo / "billing.py"), "charge", "--reason", "validated upstream", "--root", str(repo))
    assert allow.returncode == 0 and (repo / ".stepcheck" / "declared.jsonl").is_file(), allow.stdout + allow.stderr
    connect = run("connect", str(repo), "--cursor", "--no-retro")
    assert connect.returncode == 0, connect.stdout + connect.stderr
    wired = json.loads((repo / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["stepcheck"]
    assert site.resolve() in Path(wired["args"][0]).resolve().parents  # the MCP command is the wheel's own cli.py
    assert "stepcheck pre-commit" in (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert (repo / ".claude" / "hooks" / "stepcheck_hook.py").is_file() and (repo / ".cursor" / "mcp.json").is_file()
