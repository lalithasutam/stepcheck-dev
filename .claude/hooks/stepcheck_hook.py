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
later calls are answered warm. STEPCHECK_HOOK_AUTOSTART=0 turns that off.

The relay imports only the standard library and is installed as `python -S` (no
site / .pth scan at start-up); the offline fallback runs site.main() itself
before importing the kernel. PostToolUse on an editing tool adopts the written
bytes into the session at once.

SessionStart warms the gateway before the session's first tool call: offline, it
starts the detached daemon and waits until it listens (STEPCHECK_HOOK_WARM_WAIT,
default 8 s). Online, the gateway reports its pid, start time and whether it is
that daemon; if any backend source (kernel/*, hooks.py, server.py) is newer than
its start, a daemon is restarted so the session never runs stale kernel code, and
a gateway started by hand is left running with a note asking for a restart."""
import json
import os
import socket
import sys
import time
from urllib.parse import urlsplit

URL = os.environ.get("STEPCHECK_HOOK_URL", "http://127.0.0.1:8420/v1/step/hook")
EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
_DAEMON = ("import json, os, sys; backend, port, state = sys.argv[1:4]; sys.path.insert(0, backend); "
           "os.environ['STEPCHECK_DAEMON'] = '1'; "
           "open(state, 'w').write(json.dumps({'pid': os.getpid(), 'port': int(port)})); import cli; "
           "sys.exit(cli.main(['up', '--host', '127.0.0.1', '--port', port, '--log-level', 'warning']))")


def _endpoint():
    parts = urlsplit(URL)
    return parts.hostname or "127.0.0.1", parts.port or (443 if parts.scheme == "https" else 80)


def _post(payload: bytes) -> bytes:
    """POST the event to the gateway. Plain http goes over a raw socket (importing
    urllib.request costs ~0.1 s per hook); the connect itself is the offline probe."""
    parts = urlsplit(URL)
    if parts.scheme != "http":
        import urllib.request

        req = urllib.request.Request(URL, data=payload, headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=float(os.environ.get("STEPCHECK_HOOK_TIMEOUT", "2"))) as r:
            return r.read()
    host, port = _endpoint()
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    with socket.create_connection((host, port), timeout=float(os.environ.get("STEPCHECK_HOOK_CONNECT_TIMEOUT", "0.25"))) as s:
        s.settimeout(float(os.environ.get("STEPCHECK_HOOK_TIMEOUT", "2")))
        s.sendall((f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\n"
                   f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n").encode("ascii") + payload)
        chunks = []
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    head, _, body = b"".join(chunks).partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    if status_line.split(b" ", 2)[1:2] != [b"200"]:
        raise OSError(f"gateway answered {status_line!r}")
    if b"transfer-encoding: chunked" in head.lower():
        out, rest = b"", body
        while rest:
            size_line, _, rest = rest.partition(b"\r\n")
            size = int(size_line.split(b";")[0] or b"0", 16)
            if size == 0:
                break
            out, rest = out + rest[:size], rest[size + 2:]
        body = out
    return body


def _warm_gateway(backend, force=False) -> bool:
    """Start a detached local gateway on the hook URL's port; True when one was launched.
    `force` ignores the once-a-minute launch lock (a deliberate restart)."""
    host, port = _endpoint()
    if backend is None or os.environ.get("STEPCHECK_HOOK_AUTOSTART", "1") == "0" or host not in ("127.0.0.1", "localhost"):
        return False
    home = os.environ.get("STEPCHECK_HOME") or os.path.join(os.path.expanduser("~"), ".stepcheck")
    try:
        import subprocess

        os.makedirs(home, exist_ok=True)
        lock = os.path.join(home, f"gateway-{port}.lock")
        if not force and os.path.exists(lock) and time.time() - os.path.getmtime(lock) < 60:
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


def _listening(timeout=0.25) -> bool:
    try:
        with socket.create_connection(_endpoint(), timeout=timeout):
            return True
    except OSError:
        return False


def _wait(up, seconds) -> bool:
    """Poll until the gateway port is (up=True) or is not (up=False) listening."""
    deadline = time.monotonic() + seconds
    while _listening() != up:
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)
    return True


def _source_mtime(backend) -> float:
    """Newest mtime among the sources a running gateway holds in memory."""
    paths = [os.path.join(backend, "hooks.py"), os.path.join(backend, "server.py")]
    try:
        paths += [e.path for e in os.scandir(os.path.join(backend, "kernel")) if e.name.endswith(".py")]
    except OSError:
        pass
    newest = 0.0
    for p in paths:
        try:
            newest = max(newest, os.path.getmtime(p))
        except OSError:
            pass
    return newest


def _session_start(event) -> int:
    """Warm the gateway now, and replace a daemon older than the backend sources."""
    host, port = _endpoint()
    try:
        out = json.loads(_post(json.dumps(event).encode("utf-8")) or b"{}")
        ident, online = out.get("stepcheck_gateway"), True
    except Exception:  # noqa: BLE001 — offline, or not a StepCheck gateway
        ident, online = None, False
    if sys.flags.no_site:  # `python -S`: an installed backend is found through site-packages
        import site

        site.main()
    backend = _backend_dir()
    force, note = False, None
    if online and backend is not None:
        stale = ident is None or _source_mtime(backend) > float(ident.get("started") or 0)
        if stale and ident and ident.get("daemon") and ident.get("pid") and int(ident["pid"]) != os.getpid():
            import signal

            try:
                os.kill(int(ident["pid"]), signal.SIGTERM)  # our own daemon: restart on the new code
            except OSError:
                pass
            online, force = not _wait(False, 10), True
        elif stale:
            note = (f"StepCheck: the gateway on {host}:{port} is older than the StepCheck backend on disk"
                    f" ({backend}), so it is running stale kernel code; restart `stepcheck up`.")
    if not online and _warm_gateway(backend, force=force):
        _wait(True, float(os.environ.get("STEPCHECK_HOOK_WARM_WAIT", "8")))
    if note:
        return _emit(event, {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": note}})
    return 0


def _emit(event, out) -> int:
    out = {k: v for k, v in (out or {}).items() if k != "stepcheck_gateway"}
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
    if event.get("hook_event_name") == "SessionStart":
        return _session_start(event)
    try:
        out = json.loads(_post(json.dumps(event).encode("utf-8")) or b"{}")
    except Exception as exc:  # noqa: BLE001 — offline gateway, bad JSON, timeout
        offline = f"gateway offline ({exc.__class__.__name__})"
        if sys.flags.no_site:  # installed as `python -S`: load site-packages only now, for the kernel
            import site

            site.main()
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
