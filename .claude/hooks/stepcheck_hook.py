#!/usr/bin/env python3
"""StepCheck lifecycle hook, installed by `stepcheck hooks`. Relays Claude Code's
hook payload (stdin JSON) to the warm gateway endpoint and prints its answer.

Gateway unreachable: Edit / Write / MultiEdit / NotebookEdit and Stop are decided
in-process by the same policy (`backend/hooks.py`: Gates A, B and C against the
project's session), so a dead socket never lets a broken write through. Read stays
fail-open offline (the skeleton swap saves tokens; it is not a safety gate), and
so does every event when no StepCheck install can be found (STEPCHECK_BACKEND,
an installed `backend` package, or $CLAUDE_PROJECT_DIR/backend) or the kernel
itself fails — one line on stderr says so.

A gate denial on an editing tool prints the structured PreToolUse deny and exits 2:
Claude Code blocks the call before any byte lands and hands stderr to the agent.

Offline is detected with a short connect probe (STEPCHECK_HOOK_CONNECT_TIMEOUT,
default 0.25 s). When the gateway URL is local and an install is found, the cold
call also starts `stepcheck up` detached on that port (at most once a minute;
pid in $STEPCHECK_HOME/gateway-<port>.json, output in gateway-<port>.log), so
later calls are answered warm. STEPCHECK_HOOK_AUTOSTART=0 turns that off."""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlsplit

URL = os.environ.get("STEPCHECK_HOOK_URL", "http://127.0.0.1:8420/v1/step/hook")
EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
_DAEMON = ("import json, os, sys; backend, port, state = sys.argv[1:4]; sys.path.insert(0, backend); "
           "open(state, 'w').write(json.dumps({'pid': os.getpid(), 'port': int(port)})); import cli; "
           "sys.exit(cli.main(['up', '--host', '127.0.0.1', '--port', port, '--log-level', 'warning']))")


def _endpoint():
    parts = urlsplit(URL)
    return parts.hostname or "127.0.0.1", parts.port or (443 if parts.scheme == "https" else 80)


def _reachable() -> bool:
    try:
        timeout = float(os.environ.get("STEPCHECK_HOOK_CONNECT_TIMEOUT", "0.25"))
        with socket.create_connection(_endpoint(), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def _warm_gateway(backend) -> bool:
    """Start a detached local gateway on the hook URL's port; True when one was launched."""
    host, port = _endpoint()
    if backend is None or os.environ.get("STEPCHECK_HOOK_AUTOSTART", "1") == "0" or host not in ("127.0.0.1", "localhost"):
        return False
    home = os.environ.get("STEPCHECK_HOME") or os.path.join(os.path.expanduser("~"), ".stepcheck")
    try:
        os.makedirs(home, exist_ok=True)
        lock = os.path.join(home, f"gateway-{port}.lock")
        if os.path.exists(lock) and time.time() - os.path.getmtime(lock) < 60:
            return False  # another hook call launched one moments ago
        if os.path.exists(lock):
            os.remove(lock)
        os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        kwargs = {"stdin": subprocess.DEVNULL, "close_fds": True, "cwd": backend}
        if os.name == "nt":
            kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        with open(os.path.join(home, f"gateway-{port}.log"), "ab") as log:
            subprocess.Popen([sys.executable, "-c", _DAEMON, backend, str(port),
                              os.path.join(home, f"gateway-{port}.json")], stdout=log, stderr=log, **kwargs)
        return True
    except OSError:
        return False


def _backend_dir():
    candidates = [os.environ.get("STEPCHECK_BACKEND")]
    try:
        import importlib.util

        spec = importlib.util.find_spec("backend")
        candidates += list(spec.submodule_search_locations or []) if spec else []
    except (ImportError, ValueError):
        pass
    if os.environ.get("CLAUDE_PROJECT_DIR"):
        candidates.append(os.path.join(os.environ["CLAUDE_PROJECT_DIR"], "backend"))
    for c in candidates:
        if c and os.path.isfile(os.path.join(c, "hooks.py")) and os.path.isfile(os.path.join(c, "kernel", "_gates.py")):
            return c
    return None


def _in_process(event, backend):
    """The gateway's answer computed here, or None when it cannot be."""
    if backend is None:
        return None
    sys.path.insert(0, backend)
    import hooks
    from kernel import StateKernel

    return hooks.decide(event, StateKernel())


def _emit(event, out) -> int:
    if not out:
        return 0
    sys.stdout.write(json.dumps(out, ensure_ascii=False))
    hso = out.get("hookSpecificOutput") or {}
    if hso.get("permissionDecision") == "deny" and event.get("tool_name") in EDIT_TOOLS:
        sys.stderr.write(str(hso.get("permissionDecisionReason") or "StepCheck denied the edit") + "\n")
        return 2
    return 0


def main() -> int:
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0
    if not isinstance(event, dict):
        return 0
    event.setdefault("cwd", os.getcwd())
    try:
        if not _reachable():
            raise ConnectionRefusedError("connect probe")
        req = urllib.request.Request(URL, data=json.dumps(event).encode("utf-8"),
                                     headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=float(os.environ.get("STEPCHECK_HOOK_TIMEOUT", "2"))) as r:
            out = json.loads(r.read() or b"{}")
    except Exception as exc:  # noqa: BLE001 — offline gateway, bad JSON, timeout
        offline = f"gateway offline ({exc.__class__.__name__})"
        backend = _backend_dir()
        hint = "warming it in the background" if _warm_gateway(backend) else "Run `stepcheck up`."
        if event.get("tool_name") == "Read":
            sys.stderr.write(f"stepcheck hook: {offline}; allowing the Read; {hint}\n")
            return 0
        try:
            out = _in_process(event, backend)
        except Exception as inner:  # noqa: BLE001 — a kernel failure must not brick the agent
            sys.stderr.write(f"stepcheck hook: {offline}, in-process check failed ({inner!r}); allowing.\n")
            return 0
        if out is None:
            sys.stderr.write(f"stepcheck hook: {offline}, no StepCheck install found; allowing. Run `stepcheck up`.\n")
            return 0
    return _emit(event, out)


if __name__ == '__main__':
    sys.exit(main())
