"""Slice 19 — Door 1 three-band accordion compaction and gate-backed model tiering
(Seam 2, real ASGI app, zero mocks).

A 12-message conversation carrying raw file reads of this repository's own
modules goes through `/v1/chat/completions` and `/v1/messages` in dry-run mode:
the recent band comes back byte-identical, middle-band source blocks come back
as valid AST skeletons, dead-end turns are pruned, a cache cliff folds the
oldest band into a session-state frame, and `x-stepcheck-tier: auto` routes a
focused single-symbol turn to the fast tier and escalates on a gate rejection."""
import ast
import json
import re
import time
from pathlib import Path

import pytest
from conftest import BILLING_SRC
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
AUDIT_SRC = (BACKEND / "audit.py").read_text(encoding="utf-8")
CLI_SRC = (BACKEND / "cli.py").read_text(encoding="utf-8")
DEAD_END = "[STEPCHECK_DEAD_END]"


@pytest.fixture()
def client(project):
    import server

    with TestClient(server.app) as c:
        yield c


def _init(client, project) -> str:
    r = client.post("/v1/step/init", json={"project_root": str(project)})
    assert r.status_code == 200, r.text
    return r.json()["session_id"]


def _numbered(source: str) -> str:
    """Claude Code's Read-tool rendering: `<lineno>\\t<line>`."""
    return "\n".join(f"{i:6d}\t{ln}" for i, ln in enumerate(source.splitlines(), 1))


def _patch(ops: list[dict]) -> str:
    return f"```stepcheck-patch\n{json.dumps(ops)}\n```"


KEEP_CHARGE = [{"op": "replace_symbol", "name": "charge", "code":
                "@require_auth\ndef charge(user: str, amount_cents: int) -> dict:\n"
                '    # okf-invariant: "amount_cents <= 0" in src and "raise ValueError" in src\n'
                "    if amount_cents <= 0:\n        raise ValueError(\"amount must be positive\")\n"
                "    if not check_permission(user, \"charge\"):\n        raise PermissionError(user)\n"
                '    return {"user": user, "amount_cents": amount_cents, "status": "charged", "v": 2}\n'}]
DROP_DECORATOR = [{"op": "replace_symbol", "name": "charge", "code":
                   "def charge(user: str, amount_cents: int) -> dict:\n"
                   "    if amount_cents <= 0:\n        raise ValueError(\"amount must be positive\")\n"
                   "    if not check_permission(user, \"charge\"):\n        raise PermissionError(user)\n"
                   '    return {"user": user, "amount_cents": amount_cents, "status": "charged"}\n'}]


def conversation(final_step: list[dict], *, with_system: bool = True) -> list[dict]:
    """12 messages: a system prompt, raw reads of audit.py (fenced) and cli.py
    (line-numbered, unfenced), three dead-end assistant turns, an older step and
    the step under verification. Indices in comments are the message numbers."""
    msgs = [{"role": "system", "content": "You are a careful coding agent."}] if with_system else []
    msgs += [
        {"role": "user", "content": "Read billing.py, audit.py and cli.py, then harden charge()."},            # 1
        {"role": "assistant", "content": f"Let me explore the whole tree first. {DEAD_END}"},                   # 2
        {"role": "user", "content": f"Read result for audit.py:\n```python\n{AUDIT_SRC}```"},                  # 3
        {"role": "assistant", "content": "I think I should look at cli too before deciding."},                 # 4
        {"role": "user", "content": _numbered(CLI_SRC)},                                                        # 5
        {"role": "assistant", "content": "First a helper:\n" + _patch([{"op": "append", "code": "def _h1() -> int:\n    return 1\n"}])},  # 6
        {"role": "user", "content": "Good, continue with charge()."},                                           # 7
        {"role": "assistant", "content": "Hmm, maybe refactor everything instead. SCRATCH_MARKER"},            # 8
        {"role": "user", "content": "No. Apply the fix now."},                                                  # 9
        {"role": "assistant", "content": "Applying:\n" + _patch(final_step)},                                   # 10
        {"role": "user", "content": "Verify and finish."},                                                      # 11
    ]
    return msgs


def _fences(text: str) -> list[str]:
    return re.findall(r"```python\n(.*?)```", text, re.S)


def _assert_accordion(fw: dict, msgs: list[dict]) -> None:
    convo = [m for m in msgs if m["role"] != "system"]
    sent = [m for m in fw["sent_messages"] if m["role"] != "system"]
    recent_expected = [convo[i] for i in (6, 8, 9, 10)]  # messages 7, 9, 10, 11
    assert sent[-4:] == recent_expected  # recent band byte-identical

    middle = sent[:-4]
    assert [m["role"] for m in middle] == ["user", "user", "user", "assistant"]  # 1, 3, 5, 6 survive; 2, 4, 8 pruned
    joined = "\n".join(m["content"] for m in sent)
    assert DEAD_END not in joined and "look at cli too" not in joined and "SCRATCH_MARKER" not in joined

    [audit_sk] = _fences(middle[1]["content"])
    ast.parse(audit_sk)  # a valid module: signatures, decorators, docstrings, bodies elided
    assert "def audit_session(" in audit_sk and "def html_receipt(" in audit_sk
    assert "line = line.strip()" not in audit_sk and len(audit_sk) < len(AUDIT_SRC) / 2

    cli_sk = middle[2]["content"]
    ast.parse(cli_sk)
    assert "def cmd_ci(" in cli_sk and "def main(" in cli_sk and "\t" not in cli_sk
    assert "report = audit.run(paths)" not in cli_sk

    comp = fw["compaction"]
    assert comp["pruned_messages"] == 3 and comp["cache_cliff"] is False and comp["folded_messages"] == 0
    assert comp["bands"]["recent"]["messages"] == 4 and comp["bands"]["middle"]["messages_in"] == 4
    assert comp["tokens_after"] < comp["tokens_before"] and comp["saved_pct"] >= 60, comp
    assert fw["sent_tokens"] < fw["raw_tokens"]


def test_chat_completions_compacts_the_middle_band_and_keeps_the_recent_band(client, project):
    sid = _init(client, project)
    msgs = conversation(KEEP_CHARGE)
    r = client.post("/v1/chat/completions", json={"model": "gpt-x", "messages": msgs},
                    headers={"x-stepcheck-session": sid, "x-stepcheck-node": "billing"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "stepcheck-dry-run"
    fw = body["stepcheck"]
    assert fw["commit"]["accepted"] is True  # the step under verification landed through the gates
    _assert_accordion(fw, msgs)
    assert "def charge" in "\n".join(m["content"] for m in fw["sent_messages"])  # CheckoutPayload still injected


def test_anthropic_messages_compacts_the_same_way(client, project):
    sid = _init(client, project)
    msgs = conversation(KEEP_CHARGE, with_system=False)
    r = client.post("/v1/messages", json={"model": "claude-x", "max_tokens": 64, "system": "You are careful.", "messages": msgs},
                    headers={"x-stepcheck-session": sid, "x-stepcheck-node": "billing"})
    assert r.status_code == 200, r.text
    fw = r.json()["stepcheck"]
    assert fw["commit"]["accepted"] is True
    _assert_accordion(fw, msgs)
    assert fw["sent_messages"][0] == {"role": "system", "content": "You are careful."}


def test_without_a_tier_header_the_request_model_is_used_as_before(client, project):
    sid = _init(client, project)
    r = client.post("/v1/messages", json={"model": "claude-x", "max_tokens": 64, "messages": conversation(KEEP_CHARGE, with_system=False)},
                    headers={"x-stepcheck-session": sid, "x-stepcheck-node": "billing"})
    routing = r.json()["stepcheck"]["routing"]
    assert routing == {"policy": "frontier", "tier": "frontier", "model": "claude-x", "escalated": False, "gate": None,
                       "focused_turn": True}


def test_cache_cliff_folds_the_oldest_band_into_a_session_state_frame(client, project):
    sid = _init(client, project)
    msgs = conversation(KEEP_CHARGE)
    r = client.post("/v1/chat/completions", json={"model": "gpt-x", "messages": msgs},
                    headers={"x-stepcheck-session": sid, "x-stepcheck-node": "billing",
                             "x-stepcheck-last-turn-at": str(time.time() - 400)})
    assert r.status_code == 200, r.text
    fw = r.json()["stepcheck"]
    comp = fw["compaction"]
    assert comp["cache_cliff"] is True and comp["gap_seconds"] > 300 and comp["folded_messages"] == 4
    sent = [m for m in fw["sent_messages"] if m["role"] != "system"]
    convo = [m for m in msgs if m["role"] != "system"]
    assert sent[-4:] == [convo[i] for i in (6, 8, 9, 10)]
    [fold] = sent[:-4]
    assert "StepCheck session state" in fold["content"]
    assert "billing: VERIFIED" in fold["content"] and "attested" in fold["content"]
    assert "def audit_session" not in fold["content"]  # the old reads are gone, not skeletonized
    assert comp["saved_pct"] >= 60


def test_auto_tier_routes_a_focused_single_symbol_turn_to_the_fast_model(client, project):
    sid = _init(client, project)
    r = client.post("/v1/messages", json={"model": "claude-x", "max_tokens": 64, "messages": conversation(KEEP_CHARGE, with_system=False)},
                    headers={"x-stepcheck-session": sid, "x-stepcheck-node": "billing", "x-stepcheck-focus": "charge",
                             "x-stepcheck-tier": "auto"})
    assert r.status_code == 200, r.text
    fw = r.json()["stepcheck"]
    assert fw["commit"]["accepted"] is True
    assert fw["routing"] == {"policy": "auto", "tier": "fast", "model": "claude-haiku-4-5", "escalated": False, "gate": None,
                             "focused_turn": True}
    assert r.json()["model"] == "stepcheck-dry-run"  # dry-run stays dry-run; the tier is reported, not forwarded


def test_auto_tier_escalates_to_the_frontier_model_when_a_gate_rejects_the_draft(client, project):
    sid = _init(client, project)
    r = client.post("/v1/messages", json={"model": "claude-x", "max_tokens": 64, "messages": conversation(DROP_DECORATOR, with_system=False)},
                    headers={"x-stepcheck-session": sid, "x-stepcheck-node": "billing", "x-stepcheck-focus": "charge",
                             "x-stepcheck-tier": "auto"})
    assert r.status_code == 200, r.text
    fw = r.json()["stepcheck"]
    assert fw["commit"]["accepted"] is False and fw["commit"]["gate"] == "B"
    assert fw["routing"]["escalated"] is True and fw["routing"]["gate"] == "B"
    assert fw["routing"]["tier"] == "frontier" and fw["routing"]["model"] == "claude-x"
    # The rejected draft is in the recent band: the frontier model sees what failed and why.
    assert any("DROP" not in m["content"] and "def charge" in m["content"] for m in fw["sent_messages"])
    assert BILLING_SRC.count("@require_auth") == 1  # the fixture is untouched by the rejected step
