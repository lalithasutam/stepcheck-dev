#!/usr/bin/env python3
"""StepCheck lifecycle hook, installed by `stepcheck hooks`. Relays Claude Code's
hook payload (stdin JSON) to the warm gateway endpoint and prints its answer.
When the gateway is offline it allows the tool / stop silently with one line on
stderr: a dead socket must never block the agent. Standard library only."""
import json
import os
import sys
import urllib.request

URL = os.environ.get("STEPCHECK_HOOK_URL", "http://127.0.0.1:8420/v1/step/hook")


def main() -> int:
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0
    if not isinstance(event, dict):
        return 0
    event.setdefault("cwd", os.getcwd())
    try:
        req = urllib.request.Request(URL, data=json.dumps(event).encode("utf-8"),
                                     headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=float(os.environ.get("STEPCHECK_HOOK_TIMEOUT", "2"))) as r:
            out = json.loads(r.read() or b"{}")
    except Exception as exc:  # noqa: BLE001 — offline gateway, bad JSON, timeout: allow
        sys.stderr.write(f"stepcheck hook: gateway offline ({exc.__class__.__name__}); allowing. Run `stepcheck up`.\n")
        return 0
    if out:
        sys.stdout.write(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
