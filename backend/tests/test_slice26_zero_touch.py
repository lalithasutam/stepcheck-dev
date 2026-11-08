"""Slice 26 — Zero-touch connection & live Gate A/B/C enforcement on native
Claude Code tools (Read, Edit, Write, MultiEdit) plus stepcheck connect."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import cli


@pytest.fixture()
def client(project):
    import server

    with TestClient(server.app) as c:
        yield c


def _hook(client, **event) -> dict:
    r = client.post("/v1/step/hook", json=event)
    assert r.status_code == 200, r.text
    return r.json()


def test_zero_touch_auto_initializes_session_on_first_hook_without_manual_init(client, project):
    big = "import hashlib\n\n" + "".join(
        f"def fn_{i}(x: int) -> int:\n    if x < 0:\n        raise ValueError({i})\n    return x + {i}\n\n"
        for i in range(60)
    )
    (project / "big.py").write_text(big, encoding="utf-8", newline="\n")
    out = _hook(
        client,
        hook_event_name="PreToolUse",
        tool_name="Read",
        cwd=str(project),
        tool_input={"file_path": str(project / "big.py")},
        threshold=100,
        strict_read=True,  # strict mode is opt-in since Slice 34; the auto-init is what this test is about
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "def fn_0(" in hso["additionalContext"]

    scoped = _hook(
        client,
        hook_event_name="PreToolUse",
        tool_name="Read",
        cwd=str(project),
        tool_input={"file_path": str(project / "big.py"), "offset": 1, "limit": 25},
        threshold=100,
    )
    assert scoped == {}


def test_native_edit_and_write_enforce_gates_a_b_c_on_active_modules(client, project):
    bad_drop_decorator = _hook(
        client,
        hook_event_name="PreToolUse",
        tool_name="Edit",
        cwd=str(project),
        tool_input={
            "file_path": str(project / "billing.py"),
            "old_string": "@require_auth\ndef charge(",
            "new_string": "def charge(",
        },
    )
    hso_b = bad_drop_decorator["hookSpecificOutput"]
    assert hso_b["permissionDecision"] == "deny"
    assert "Gate B" in hso_b["permissionDecisionReason"]

    bad_drop_guard = _hook(
        client,
        hook_event_name="PreToolUse",
        tool_name="Edit",
        cwd=str(project),
        tool_input={
            "file_path": str(project / "billing.py"),
            "old_string": '    if amount_cents <= 0:\n        raise ValueError("amount must be positive")\n',
            "new_string": "",
        },
    )
    hso_c = bad_drop_guard["hookSpecificOutput"]
    assert hso_c["permissionDecision"] == "deny"
    assert "Gate C" in hso_c["permissionDecisionReason"]

    bad_drop_export = _hook(
        client,
        hook_event_name="PreToolUse",
        tool_name="Write",
        cwd=str(project),
        tool_input={
            "file_path": str(project / "billing.py"),
            "content": "def unrelated() -> int:\n    return 1\n",
        },
    )
    hso_a = bad_drop_export["hookSpecificOutput"]
    assert hso_a["permissionDecision"] == "deny"
    assert "Gate A" in hso_a["permissionDecisionReason"]

    valid_sig_edit = _hook(
        client,
        hook_event_name="PreToolUse",
        tool_name="Edit",
        cwd=str(project),
        tool_input={
            "file_path": str(project / "billing.py"),
            "old_string": "def charge(user: str, amount_cents: int) -> dict:",
            "new_string": 'def charge(user: str, amount_cents: int, currency: str = "USD") -> dict:',
        },
    )
    assert valid_sig_edit == {}
    # The hook only verifies (dry run); the agent's Edit tool writes the bytes …
    billing = project / "billing.py"
    assert "currency" not in billing.read_text(encoding="utf-8")
    billing.write_text(billing.read_text(encoding="utf-8").replace(
        "def charge(user: str, amount_cents: int) -> dict:",
        'def charge(user: str, amount_cents: int, currency: str = "USD") -> dict:'), encoding="utf-8", newline="\n")

    # … and the Stop hook adopts them through the gates, dirtying the dependent.
    stop_out = _hook(client, hook_event_name="Stop", cwd=str(project))
    assert stop_out["decision"] == "block" and "reports" in stop_out["reason"]


def test_stepcheck_connect_wires_hooks_mcp_and_session_idempotently(project, capsys):
    assert cli.main(["connect", str(project)]) == 0
    out = capsys.readouterr().out
    assert ".mcp.json" in out and "session" in out
    mcp = json.loads((project / ".mcp.json").read_text(encoding="utf-8"))
    assert mcp["mcpServers"]["stepcheck"]["url"].endswith("/mcp/")
    assert (project / ".claude" / "settings.json").exists()
    assert (project / ".claude" / "hooks" / "stepcheck_hook.py").exists()
