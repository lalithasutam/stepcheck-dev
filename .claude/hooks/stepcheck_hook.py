#!/usr/bin/env python3
"""StepCheck lifecycle hook, installed by `stepcheck hooks`. Relays Claude Code's
hook payload (stdin JSON) to the warm gateway endpoint and prints its answer.

Gateway unreachable: Edit / Write / MultiEdit / NotebookEdit and Stop are decided
in-process by the same policy (`backend/hooks.py`: Gates A, B and C against the
project's session), so a dead socket never lets a broken write through. Read stays
fail-open offline (online, a Read of a large tracked module is allowed and rides
the module's causal-cone frame and Gate C invariants as additionalContext;
STEPCHECK_STRICT_READ=1 swaps the Read for the skeleton instead — neither is a
safety gate), and so does every event when no StepCheck install can be found
(STEPCHECK_BACKEND, an installed `backend` package, or $CLAUDE_PROJECT_DIR/backend)
or the kernel itself fails — one line on stderr says so.

A gate denial on an editing tool prints the structured PreToolUse deny and exits 2:
Claude Code blocks the call before any byte lands and hands stderr to the agent —
the `[STEPCHECK CATCH — Gate X] <module> (<symbol>): …` banner, also appended to
<project>/.stepcheck/catches.jsonl by the policy.

Offline is detected with a 15 ms connect probe on the loopback socket
(STEPCHECK_HOOK_CONNECT_TIMEOUT), before anything beyond the standard library is
imported. A Read — any PreToolUse on a non-editing tool — then exits at once: the
offline fast path, well under 50 ms of hook time (STEPCHECK_HOOK_TRACE=1 prints
it on stderr). An editing tool, PostToolUse and Stop still pay for the in-process
gates: that is the safety property, not a cost to shave. When the gateway URL is
local and an install is found, the cold call also starts `stepcheck up` detached
on that port (at most once a minute; pid in $STEPCHECK_HOME/gateway-<port>.json,
output in gateway-<port>.log), so later calls are answered warm.
STEPCHECK_HOOK_AUTOSTART=0 turns that off.

The relay imports only the standard library and is installed as `python -S` (no
site / .pth scan at start-up); the offline fallback runs site.main() itself
before importing the kernel. PostToolUse on an editing tool adopts the written
bytes into the session at once. The gateway is started with the interpreter
`stepcheck hooks` recorded for this install ($STEPCHECK_HOME/interpreters.json,
or $STEPCHECK_PYTHON), and when the `python` on PATH cannot import the kernel
the in-process decision is delegated to that interpreter instead of failing open.

SessionStart warms the gateway before the session's first tool call: offline, it
starts the detached daemon and waits until it listens (STEPCHECK_HOOK_WARM_WAIT,
default 8 s). Online, the gateway reports its pid, start time and whether it is
that daemon; if any backend source (kernel/*, hooks.py, server.py) is newer than
its start, a daemon is restarted so the session never runs stale kernel code, and
a gateway started by hand is left running with a note asking for a restart."""
import json
import os
import re
import socket
import sys
import time
from urllib.parse import urlsplit

_T0 = time.perf_counter()
URL = os.environ.get("STEPCHECK_HOOK_URL", "http://127.0.0.1:8420/v1/step/hook")
EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
IDENT: dict = {}  # the gateway's identity from the last answer's X-StepCheck-* headers (the body stays the bare answer)


def _note_identity(headers) -> None:
    for k, v in headers:
        k = k.strip().lower()
        if k == "x-stepcheck-build":
            IDENT["build_id"] = v.strip()
        elif k == "x-stepcheck-pid":
            IDENT["pid"] = v.strip()
        elif k == "x-stepcheck-daemon":
            IDENT["daemon"] = v.strip() == "1"


def _health_identity():
    """GET /health on the gateway (a few ms): the identity of a gateway whose hook answer
    carried no headers — a broken build answering 422 before the endpoint ever runs."""
    try:
        host, port = _endpoint()
        with socket.create_connection((host, port), timeout=0.05) as s:
            s.settimeout(1.0)
            s.sendall(f"GET /health HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode("ascii"))
            data = b""
            while chunk := s.recv(65536):
                data += chunk
        body = data.partition(b"\r\n\r\n")[2]
        h = json.loads(body[body.find(b"{"):body.rfind(b"}") + 1])
        return {"build_id": h.get("kernel_build_id"), "pid": h.get("pid"), "daemon": bool(h.get("daemon"))}
    except Exception:  # noqa: BLE001 — not a StepCheck gateway, or gone
        return None
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
            _note_identity(r.headers.items())
            return r.read()
    host, port = _endpoint()
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    with socket.create_connection((host, port), timeout=float(os.environ.get("STEPCHECK_HOOK_CONNECT_TIMEOUT", "0.015"))) as s:
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
    _note_identity(line.decode("latin-1").partition(":")[::2] for line in head.split(b"\r\n")[1:] if b":" in line)
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
            # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP: a hidden console of its own, so the daemon
            # outlives the hook and ignores its Ctrl+C. Not DETACHED_PROCESS: a venv's redirecting
            # python.exe launched detached can stall before the interpreter starts.
            kwargs["creationflags"] = 0x08000000 | 0x00000200
        else:
            kwargs["start_new_session"] = True
        with open(os.path.join(home, f"gateway-{port}.log"), "ab") as log:
            subprocess.Popen([_python(backend), "-c", _DAEMON, backend, str(port),
                              os.path.join(home, f"gateway-{port}.json")], stdout=log, stderr=log, **kwargs)
        return True
    except OSError:
        return False


def _is_backend(c) -> bool:
    return bool(c) and os.path.isfile(os.path.join(c, "hooks.py")) and os.path.isfile(os.path.join(c, "kernel", "_gates.py"))


def _python(backend):
    """The interpreter for the gateway and the in-process gates: $STEPCHECK_PYTHON, else the
    one `stepcheck hooks` recorded for this backend ($STEPCHECK_HOME/interpreters.json), else
    this one. The relay runs as whatever `python` is first on PATH, and after a reboot that
    is often not the virtualenv StepCheck's dependencies live in."""
    cands = [os.environ.get("STEPCHECK_PYTHON")]
    try:
        home = os.environ.get("STEPCHECK_HOME") or os.path.join(os.path.expanduser("~"), ".stepcheck")
        with open(os.path.join(home, "interpreters.json"), encoding="utf-8") as f:
            cands.append(json.load(f).get(os.path.normcase(os.path.abspath(backend))))
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return sys.executable


def _delegate(event, backend):
    """This interpreter cannot import the kernel (StepCheck's dependencies are not installed
    in it): run the same hook under the recorded interpreter and relay its answer and exit
    code. None when there is no other interpreter to ask."""
    script = globals().get("__file__")
    if backend is None or not script or os.environ.get("STEPCHECK_HOOK_DELEGATED"):
        return None
    py = _python(backend)
    if os.path.normcase(os.path.abspath(py)) == os.path.normcase(os.path.abspath(sys.executable)):
        return None
    import subprocess

    try:
        done = subprocess.run([py, script], input=json.dumps(event).encode("utf-8"), capture_output=True,
                              env=dict(os.environ, STEPCHECK_HOOK_DELEGATED="1", STEPCHECK_BACKEND=backend),
                              timeout=float(os.environ.get("STEPCHECK_HOOK_DELEGATE_TIMEOUT", "9")))
    except (OSError, subprocess.SubprocessError):
        return None
    sys.stdout.flush()
    sys.stdout.buffer.write(done.stdout)
    sys.stdout.flush()
    sys.stderr.flush()
    sys.stderr.buffer.write(done.stderr)
    sys.stderr.flush()
    return done.returncode


def _load_site() -> None:
    """Installed as `python -S`: load site-packages now (the kernel needs them)."""
    if sys.flags.no_site:
        import site

        site.main()


def _backend_dir():
    """The StepCheck backend: $STEPCHECK_BACKEND or $CLAUDE_PROJECT_DIR/backend first
    (no site scan), then the installed `backend` package."""
    for c in (os.environ.get("STEPCHECK_BACKEND"),
              os.path.join(os.environ["CLAUDE_PROJECT_DIR"], "backend") if os.environ.get("CLAUDE_PROJECT_DIR") else None):
        if _is_backend(c):
            return c
    try:
        _load_site()
        import importlib.util

        spec = importlib.util.find_spec("backend")
        for c in list(spec.submodule_search_locations or []) if spec else []:
            if _is_backend(c):
                return c
    except (ImportError, ValueError):
        pass
    return None


def _trace(rc: int) -> int:
    if os.environ.get("STEPCHECK_HOOK_TRACE"):
        sys.stderr.write(f"stepcheck hook: {(time.perf_counter() - _T0) * 1000:.1f} ms in hook\n")
    return rc


def _in_process(event, backend):
    """The gateway's answer computed here, or None when it cannot be."""
    if backend is None:
        return None
    _load_site()
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


def _local_build_id(backend=None):
    """`kernel.build_id()` computed here from the code on disk, standard library only: sha256
    over the path and bytes of every backend/*.py and backend/kernel/*.py, 16 hex chars."""
    import hashlib

    backend = backend or _backend_dir()
    if backend is None:
        return None
    h = hashlib.sha256()
    files = sorted([os.path.join(backend, n) for n in os.listdir(backend) if n.endswith(".py")]
                   + [os.path.join(backend, "kernel", n) for n in os.listdir(os.path.join(backend, "kernel")) if n.endswith(".py")],
                  key=lambda p: os.path.relpath(p, backend).replace(os.sep, "/"))
    for p in files:
        try:
            with open(p, "rb") as f:
                data = f.read()
        except OSError:
            continue
        h.update(os.path.relpath(p, backend).replace(os.sep, "/").encode("utf-8"))
        h.update(b"\0")
        h.update(data)
        h.update(b"\0")
    return h.hexdigest()[:16]


def _retire_if_stale(ident) -> bool:
    """True when the gateway that answered runs a kernel build other than the one on disk.
    Our own daemon is told to exit (its pid is in the identity) so the next call warms a
    fresh one; a gateway started by hand is left running and reported on stderr."""
    local = _local_build_id()
    if local is None or ident.get("build_id") == local:
        return False
    if ident.get("daemon") and ident.get("pid") and int(ident["pid"]) != os.getpid():
        import signal

        try:
            os.kill(int(ident["pid"]), signal.SIGTERM)
        except OSError:
            pass
        _wait(False, 5)
        _warm_gateway(_backend_dir(), force=True)
        sys.stderr.write("stepcheck hook: the gateway ran stale kernel code (build "
                         f"{ident.get('build_id')} vs {local} on disk); restarted it, this call is decided in-process\n")
    else:
        sys.stderr.write(f"stepcheck hook: the gateway runs stale kernel code (build {ident.get('build_id')} vs {local} "
                         "on disk); this call is decided in-process — restart `stepcheck up`\n")
    return True


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
    for stream in (sys.stdout, sys.stderr):  # the answer and the banner are UTF-8 whatever the console code page
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
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
        ident = dict(IDENT) or (out.get("stepcheck_gateway") if isinstance(out, dict) else None)
        if ident and ident.get("build_id") and _retire_if_stale(ident):
            raise RuntimeError("stale gateway build")  # answered by old RAM: decide in-process, a fresh daemon warms
    except Exception as exc:  # noqa: BLE001 — offline gateway, bad JSON, timeout, stale build
        if not isinstance(exc, RuntimeError):
            # the gateway answered, just not usefully (a non-200, a body that is not JSON): its
            # identity headers, or failing those its /health, still say which build it runs,
            # so a stale daemon is retired here as well
            ident = dict(IDENT) if IDENT.get("build_id") else (_health_identity() if "gateway answered" in str(exc) else None)
            if ident and ident.get("build_id"):
                _retire_if_stale(ident)
        offline = f"gateway offline ({exc.__class__.__name__})"
        command = str((event.get("tool_input") or {}).get("command") or "") if event.get("tool_name") == "Bash" else ""
        sovereign = bool(re.search(r"(?:^|[\s;&|(`])stepcheck(?:\.exe)?\s+allow\b|declared\.jsonl", command, re.I))
        if event.get("hook_event_name", "PreToolUse") == "PreToolUse" and event.get("tool_name") not in EDIT_TOOLS and not sovereign:
            # Read: nothing to gate, so leave before importing anything heavier — the
            # offline fast path. Autostart, when on, still kicks the daemon so the
            # next call is answered warm.
            hint = "Run `stepcheck up`."
            if os.environ.get("STEPCHECK_HOOK_AUTOSTART", "1") != "0" and _warm_gateway(_backend_dir()):
                hint = "warming it in the background"
            sys.stderr.write(f"stepcheck hook: {offline}; allowing the {event.get('tool_name')}; {hint}\n")
            return _trace(0)
        backend = _backend_dir()
        hint = "warming it in the background" if _warm_gateway(backend) else "Run `stepcheck up`."
        try:
            out = _in_process(event, backend)
        except Exception as inner:  # noqa: BLE001 — a kernel failure must not brick the agent
            rc = _delegate(event, backend) if isinstance(inner, ImportError) else None
            if rc is not None:
                return _trace(rc)
            sys.stderr.write(f"stepcheck hook: {offline}, in-process check failed ({inner!r}); allowing.\n")
            return _trace(0)
        if out is None:
            sys.stderr.write(f"stepcheck hook: {offline}, no StepCheck install found; allowing. {hint}\n")
            return _trace(0)
    return _trace(_emit(event, out))


if __name__ == '__main__':
    sys.exit(main())
