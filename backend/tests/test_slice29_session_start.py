"""Slice 29 — SessionStart warm-up and stale-gateway reload (Seam 2 and the installed
hook script; zero mocks, real detached gateways).

1. `stepcheck hooks` registers SessionStart next to PreToolUse / PostToolUse / Stop.
2. The gateway answers a SessionStart relay with its identity: its pid, when it
   started, and whether it is the hook's own detached daemon.
3. SessionStart with the gateway down starts the daemon and returns only once it
   listens; with a daemon older than the newest backend source (kernel/, hooks.py,
   server.py) it restarts it, so a session never talks to stale in-memory kernel
   code. A stale gateway the user started by hand is never killed: the session is
   told to restart it instead.
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import cli

BACKEND = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
            return True
    except OSError:
        return False


def _identity(port: int) -> dict:
    body = json.dumps({"hook_event_name": "SessionStart"}).encode()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall((f"POST /v1/step/hook HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
        data = b""
        while chunk := s.recv(65536):
            data += chunk
    return json.loads(data.partition(b"\r\n\r\n")[2])["stepcheck_gateway"]


def _alive(pid: int) -> bool:
    if os.name == "nt":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


@pytest.fixture()
def backend_copy(tmp_path: Path) -> Path:
    """A private copy of the backend, so touching its sources marks only our daemons stale."""
    dst = tmp_path / "backend"
    shutil.copytree(BACKEND, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".stepcheck", "tests"))
    return dst


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "m.py").write_text("def f() -> int:\n    return 1\n", encoding="utf-8", newline="\n")
    return root


def test_hooks_register_session_start(project, capsys):
    assert cli.main(["hooks", str(project)]) == 0
    hooks = json.loads((project / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    assert set(hooks) == {"SessionStart", "PreToolUse", "PostToolUse", "Stop"}
    (entry,) = hooks["SessionStart"]
    assert "matcher" not in entry and "stepcheck_hook.py" in entry["hooks"][0]["command"]
    assert entry["hooks"][0]["command"].startswith("python -S ")
    before = (project / ".claude" / "settings.json").read_bytes()
    assert cli.main(["hooks", str(project)]) == 0  # idempotent
    assert (project / ".claude" / "settings.json").read_bytes() == before


def test_gateway_answers_session_start_with_its_identity():
    import server

    with TestClient(server.app) as client:
        r = client.post("/v1/step/hook", json={"hook_event_name": "SessionStart", "source": "startup"})
    ident = r.json()["stepcheck_gateway"]
    assert ident["pid"] == os.getpid() and ident["daemon"] is False
    assert 0 < ident["started"] <= time.time()


def _env(port: int, backend: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PROJECT_DIR", "STEPCHECK_BACKEND", "STEPCHECK_DAEMON")}
    env.update(STEPCHECK_HOOK_URL=f"http://127.0.0.1:{port}/v1/step/hook", PYTHONUTF8="1",
               STEPCHECK_BACKEND=str(backend), STEPCHECK_HOOK_AUTOSTART="1", STEPCHECK_HOOK_WARM_WAIT="90")
    return env


def _session_start(script: Path, project: Path, env: dict) -> subprocess.CompletedProcess:
    event = {"hook_event_name": "SessionStart", "source": "startup", "cwd": str(project)}
    return subprocess.run([sys.executable, "-S", str(script)], input=json.dumps(event), capture_output=True,
                          text=True, env=env, timeout=180)


def _touch_newer(backend: Path) -> None:
    future = time.time() + 5
    os.utime(backend / "kernel" / "_okf.py", (future, future))


def test_session_start_warms_the_gateway_and_reloads_a_stale_daemon(project, backend_copy, capsys):
    assert cli.main(["hooks", str(project)]) == 0
    script = project / ".claude" / "hooks" / "stepcheck_hook.py"
    port = _free_port()
    env = _env(port, backend_copy)
    pids: list[int] = []
    try:
        cold = _session_start(script, project, env)
        assert cold.returncode == 0 and cold.stdout == "", (cold.stdout, cold.stderr)
        assert _listening(port)  # warm before the session's first tool call
        first = _identity(port)
        pids.append(first["pid"])
        assert first["daemon"] is True

        fresh = _session_start(script, project, env)  # up to date: left alone
        assert fresh.returncode == 0 and _identity(port)["pid"] == first["pid"]

        _touch_newer(backend_copy)  # an upgrade landed after the daemon started
        reload = _session_start(script, project, env)
        assert reload.returncode == 0 and reload.stdout == "", (reload.stdout, reload.stderr)
        second = _identity(port)
        pids.append(second["pid"])
        assert second["pid"] != first["pid"] and second["started"] > first["started"]
        assert not _alive(first["pid"])
    finally:
        for pid in pids:
            if _alive(pid):
                os.kill(pid, signal.SIGTERM)


def test_a_stale_gateway_started_by_hand_is_flagged_not_killed(project, backend_copy, capsys):
    assert cli.main(["hooks", str(project)]) == 0
    script = project / ".claude" / "hooks" / "stepcheck_hook.py"
    port = _free_port()
    env = _env(port, backend_copy)
    manual = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.path.insert(0, sys.argv[1]); import cli; "
         "sys.exit(cli.main(['up', '--host', '127.0.0.1', '--port', sys.argv[2], '--log-level', 'warning']))",
         str(backend_copy), str(port)],
        cwd=str(backend_copy), env={k: v for k, v in env.items() if k != "STEPCHECK_DAEMON"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 90
        while not _listening(port) and time.monotonic() < deadline:
            time.sleep(0.2)
        assert _listening(port)
        before = _identity(port)  # (on Windows a venv's python.exe is a launcher: use the served pid)
        assert before["daemon"] is False
        _touch_newer(backend_copy)
        out = _session_start(script, project, env)
        assert out.returncode == 0, out.stderr
        ctx = json.loads(out.stdout)["hookSpecificOutput"]
        assert ctx["hookEventName"] == "SessionStart" and "restart `stepcheck up`" in ctx["additionalContext"]
        assert manual.poll() is None and _identity(port)["pid"] == before["pid"]  # still the user's process
    finally:
        manual.terminate()
        manual.wait(timeout=30)
