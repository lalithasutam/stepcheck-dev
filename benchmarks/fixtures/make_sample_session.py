"""Generate benchmarks/fixtures/sample_session.jsonl — a synthetic Claude Code
session transcript in the ~/.claude/projects/<slug>/<session>.jsonl shape.

14 assistant turns on a small payments module. Two turns resume after a
>5-minute pause (cache expired, prefix re-written at full rate); one Edit
silently drops the @audit decorator and takes two retries to land; one Edit
removes the positive-amount guard and takes one retry. Everything else is
ordinary. Re-run this file to regenerate the fixture deterministically.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "benchmarks"))
from coding_rot_benchmark import PAYMENTS  # noqa: E402  (the same module the replay uses)

T0 = datetime(2026, 10, 30, 9, 0, 0, tzinfo=timezone.utc)
PATH = "/Users/dev/acme/payments.py"


def _numbered(src: str) -> str:
    return "\n".join(f"{i+1:6d}→{line}" for i, line in enumerate(src.splitlines()))


def main() -> None:
    rows: list[dict] = []
    clock = T0
    uid = 0

    def emit(kind: str, content: list[dict], usage: dict | None = None, dt: int = 40) -> None:
        nonlocal clock, uid
        clock += timedelta(seconds=dt)
        uid += 1
        row = {
            "type": kind,
            "uuid": f"u{uid:03d}",
            "sessionId": "sess-sample-0001",
            "cwd": "/Users/dev/acme",
            "timestamp": clock.isoformat().replace("+00:00", "Z"),
            "message": {"role": kind, "content": content},
        }
        if usage:
            row["message"]["usage"] = usage
        rows.append(row)

    def assistant(blocks: list[dict], *, cache_read: int, cache_create: int, inp: int = 20, out: int = 220, dt: int = 40) -> None:
        emit("assistant", blocks, {"input_tokens": inp, "cache_creation_input_tokens": cache_create,
                                   "cache_read_input_tokens": cache_read, "output_tokens": out}, dt=dt)

    def result(tool_id: str, text: str, is_error: bool = False) -> None:
        emit("user", [{"type": "tool_result", "tool_use_id": tool_id, "content": text, "is_error": is_error}], dt=3)

    src = PAYMENTS
    emit("user", [{"type": "text", "text": "Refactor payments.charge to add a currency arg and keep the audit trail."}], dt=0)

    # T1 Read full file
    assistant([{"type": "text", "text": "Let me read the module first."},
               {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": PATH}}],
              cache_read=0, cache_create=14200)
    result("t1", _numbered(src))

    # T2 Grep
    assistant([{"type": "tool_use", "id": "t2", "name": "Grep", "input": {"pattern": "charge\\(", "path": "/Users/dev/acme"}}],
              cache_read=14200, cache_create=1900)
    result("t2", "/Users/dev/acme/api.py:5:    return charge(account_key(account), cents)\n/Users/dev/acme/workers.py:4:    return charge(account, cents)")

    # T3 Edit — drops @audit while rewriting the signature
    old = src[src.index("@audit"):src.index('    return {"account": key')]
    new = old.replace("@audit\n", "").replace("def charge(account: str, amount_cents: int) -> dict:",
                                                'def charge(account: str, amount_cents: int, currency: str = "USD") -> dict:')
    assistant([{"type": "text", "text": "Updating the signature."},
               {"type": "tool_use", "id": "t3", "name": "Edit", "input": {"file_path": PATH, "old_string": old, "new_string": new}}],
              cache_read=16100, cache_create=900)
    result("t3", "The file /Users/dev/acme/payments.py has been updated.")
    src = src.replace(old, new)

    # T4 run tests → failure (audit trail missing)
    assistant([{"type": "tool_use", "id": "t4", "name": "Bash", "input": {"command": "pytest -q tests/test_payments.py"}}],
              cache_read=17000, cache_create=600)
    result("t4", "FAILED tests/test_payments.py::test_charge_is_audited - AssertionError: no audit entry\n1 failed, 3 passed", is_error=True)

    # T5 retry edit #1 (wrong fix)
    assistant([{"type": "text", "text": "The audit assertion fails; adjusting."},
               {"type": "tool_use", "id": "t5", "name": "Edit", "input": {"file_path": PATH, "old_string": "    key = account_key(account)\n", "new_string": "    key = account_key(account)\n    print(\"audit\", key)\n"}}],
              cache_read=17600, cache_create=700)
    result("t5", "The file /Users/dev/acme/payments.py has been updated.")

    # --- 7 minute pause: cache expired ---
    # T6 re-read whole file after the gap (prefix re-created at full rate)
    assistant([{"type": "text", "text": "Re-reading to re-sync."},
               {"type": "tool_use", "id": "t6", "name": "Read", "input": {"file_path": PATH}}],
              cache_read=0, cache_create=18900, dt=7 * 60 + 12)
    result("t6", _numbered(src))

    # T7 retry edit #2 — restores @audit (the real fix)
    assistant([{"type": "tool_use", "id": "t7", "name": "Edit", "input": {"file_path": PATH,
               "old_string": 'def charge(account: str, amount_cents: int, currency: str = "USD") -> dict:',
               "new_string": '@audit\ndef charge(account: str, amount_cents: int, currency: str = "USD") -> dict:'}}],
              cache_read=18900, cache_create=800)
    result("t7", "The file /Users/dev/acme/payments.py has been updated.")

    # T8 tests pass
    assistant([{"type": "tool_use", "id": "t8", "name": "Bash", "input": {"command": "pytest -q tests/test_payments.py"}}],
              cache_read=19700, cache_create=500)
    result("t8", "4 passed")

    # T9 Edit — "simplify" removes the positive-amount guard
    assistant([{"type": "text", "text": "Simplifying the validation."},
               {"type": "tool_use", "id": "t9", "name": "Edit", "input": {"file_path": PATH,
               "old_string": '    if amount_cents <= 0:\n        raise ValueError("amount must be positive")\n',
               "new_string": "    amount_cents = max(amount_cents, 1)\n"}}],
              cache_read=20200, cache_create=600)
    result("t9", "The file /Users/dev/acme/payments.py has been updated.")

    # T10 tests fail
    assistant([{"type": "tool_use", "id": "t10", "name": "Bash", "input": {"command": "pytest -q"}}],
              cache_read=20800, cache_create=500)
    result("t10", "FAILED tests/test_payments.py::test_rejects_zero - DID NOT RAISE ValueError\n1 failed, 5 passed", is_error=True)

    # --- 6 minute pause ---
    # T11 re-read after gap
    assistant([{"type": "tool_use", "id": "t11", "name": "Read", "input": {"file_path": PATH}}],
              cache_read=0, cache_create=21300, dt=6 * 60 + 5)
    result("t11", _numbered(src))

    # T12 retry edit restores the guard
    assistant([{"type": "tool_use", "id": "t12", "name": "Edit", "input": {"file_path": PATH,
               "old_string": "    amount_cents = max(amount_cents, 1)\n",
               "new_string": '    if amount_cents <= 0:\n        raise ValueError("amount must be positive")\n'}}],
              cache_read=21300, cache_create=700)
    result("t12", "The file /Users/dev/acme/payments.py has been updated.")

    # T13 tests pass
    assistant([{"type": "tool_use", "id": "t13", "name": "Bash", "input": {"command": "pytest -q"}}],
              cache_read=22000, cache_create=400)
    result("t13", "6 passed")

    # T14 done
    assistant([{"type": "text", "text": "Done: charge() takes a currency argument; audit trail and validation preserved."}],
              cache_read=22400, cache_create=300, out=120)

    out = HERE / "sample_session.jsonl"
    out.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
