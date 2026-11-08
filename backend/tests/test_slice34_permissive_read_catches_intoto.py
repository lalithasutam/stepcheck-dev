"""Slice 34 — permissive Read, the human-visible catch receipt, and a standard in-toto Statement.

1. A PreToolUse Read of a large tracked module is ALLOWED: the module is adopted into the
   session and the answer rides the causal-cone frame (exports, preserved symbols, dependency
   interfaces) and every Gate C invariant the module carries as additionalContext. The old
   skeleton-for-source denial is opt-in: `strict_read` on the event or STEPCHECK_STRICT_READ=1.
2. Every block at Gate A / B / C — a PreToolUse edit, a PostToolUse Bash sync, a Stop — is a
   `[STEPCHECK CATCH — Gate X] <module> (<symbol>): …` banner in the hook's message and one JSON
   line in <repo>/.stepcheck/catches.jsonl (timestamp, module, symbol, gate, code, reason).
3. `stepcheck compliance` leads with a standard in-toto Statement v1 (attestation.intoto.json);
   DUC.json / DUA-E.json stay as the secondary dual-use files.
"""
from __future__ import annotations

import hashlib
import json
import os
import textwrap
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import cli
from conftest import BILLING_SRC

BIG_SRC = "import hashlib\n\n" + "".join(
    f"def fn_{i}(x: int) -> int:\n    if x < 0:\n        raise ValueError({i})\n"
    f"    return int(hashlib.sha256(str(x + {i}).encode()).hexdigest(), 16) % 97\n\n\n"
    for i in range(60)
)
SVC = textwrap.dedent('''\
    LIMIT = 10


    def check(x):
        if x < 0:
            raise ValueError("negative")
        return x


    def compute(a, b):
        total = a + b
        if total > LIMIT:
            total = LIMIT
        return total
    ''')
CLIENT = "from svc import check, compute\n\n\ndef run(v):\n    return compute(check(v), 1)\n"
STUBBED = SVC.replace("    total = a + b\n    if total > LIMIT:\n        total = LIMIT\n    return total\n", "    ...\n")


@pytest.fixture()
def client(project):
    import server

    with TestClient(server.app) as c:
        yield c


def _hook(client, **event) -> dict:
    r = client.post("/v1/step/hook", json=event)
    assert r.status_code == 200, r.text
    return r.json()


def _init(client, project) -> str:
    return client.post("/v1/step/init", json={"project_root": str(project)}).json()["session_id"]


def _catches(root: Path) -> list[dict]:
    path = root / ".stepcheck" / "catches.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# --------------------------------------------------------- 1. permissive Read


def test_a_large_tracked_read_is_allowed_with_its_cone_and_invariants(client, project):
    (project / "big.py").write_text(BIG_SRC, encoding="utf-8", newline="\n")
    sid = _init(client, project)
    read = lambda name, **extra: _hook(  # noqa: E731
        client, hook_event_name="PreToolUse", tool_name="Read", cwd=str(project),
        tool_input={"file_path": str(project / name)}, **extra)

    out = read("big.py")
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse" and hso["permissionDecision"] == "allow"
    assert "permissionDecisionReason" not in hso or "allow" in hso["permissionDecisionReason"].lower()
    ctx = hso["additionalContext"]
    assert "big.py" in ctx and sid in ctx and "node big" in ctx
    assert "def fn_0(" in ctx and "def fn_59(" in ctx  # the causal-cone frame: every signature
    assert "hexdigest()" not in ctx  # bodies ride in the Read itself, not twice
    # every mined Gate C invariant is in front of the agent (these guards mine as executable calls)
    assert "call:fn_0(x=-1) raises ValueError" in ctx and "call:fn_59(x=-1) raises ValueError" in ctx
    assert "Gate C" in ctx
    assert read("billing.py") == {}  # under the threshold: the Read needs no help
    assert read("README.md") == {}  # not a tracked module
    # a strict per-request threshold still allows, with the frame alongside
    small = read("billing.py", threshold=10)["hookSpecificOutput"]
    assert small["permissionDecision"] == "allow" and "def charge(" in small["additionalContext"]
    assert "amount_cents <= 0" in small["additionalContext"]  # the declared okf-invariant and the mined guard
    # the checkout was charged to the session like any frame
    assert client.get(f"/v1/step/telemetry/{sid}").json()["turns"] >= 2


def test_strict_read_denial_is_opt_in(client, project, monkeypatch):
    (project / "big.py").write_text(BIG_SRC, encoding="utf-8", newline="\n")
    sid = _init(client, project)
    event = dict(hook_event_name="PreToolUse", tool_name="Read", cwd=str(project), tool_input={"file_path": str(project / "big.py")})

    strict = _hook(client, **event, strict_read=True)["hookSpecificOutput"]
    assert strict["permissionDecision"] == "deny" and "big.py" in strict["permissionDecisionReason"] and sid in strict["permissionDecisionReason"]
    assert "def fn_0(" in strict["additionalContext"] and "hexdigest()" not in strict["additionalContext"]

    monkeypatch.setenv("STEPCHECK_STRICT_READ", "1")
    assert _hook(client, **event)["hookSpecificOutput"]["permissionDecision"] == "deny"
    monkeypatch.setenv("STEPCHECK_STRICT_READ", "0")
    assert _hook(client, **event)["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert _hook(client, **event, strict_read=False)["hookSpecificOutput"]["permissionDecision"] == "allow"
    # a scoped slice read is never touched, strict or not
    scoped = dict(event, tool_input={**event["tool_input"], "offset": 1, "limit": 40})
    assert _hook(client, **scoped, strict_read=True) == {}
    # a Read never leaves a catch line: nothing was blocked
    assert _catches(project) == []


# ------------------------------------------------------- 2. catch receipt


def test_a_gate_denial_is_a_banner_and_a_catch_line(client, project):
    sid = _init(client, project)
    edit = lambda old, new: _hook(  # noqa: E731
        client, hook_event_name="PreToolUse", tool_name="Edit", cwd=str(project),
        tool_input={"file_path": str(project / "billing.py"), "old_string": old, "new_string": new})

    dropped = edit("@require_auth\ndef charge(", "def charge(")["hookSpecificOutput"]
    assert dropped["permissionDecision"] == "deny"
    assert dropped["permissionDecisionReason"].startswith("[STEPCHECK CATCH — Gate B] billing (charge): ")
    assert "Gate B" in dropped["permissionDecisionReason"] and "require_auth" in dropped["permissionDecisionReason"]
    # the same unchanged refusal reported again is still denied but logged once
    assert edit("@require_auth\ndef charge(", "def charge(")["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert len(_catches(project)) == 1

    guard = edit('    if amount_cents <= 0:\n        raise ValueError("amount must be positive")\n', "")["hookSpecificOutput"]
    assert guard["permissionDecision"] == "deny"
    assert guard["permissionDecisionReason"].startswith("[STEPCHECK CATCH — Gate C] billing (charge): ")

    assert edit('"status": "charged"', '"status": "charged", "v": 2') == {}  # a fine edit leaves no trace

    assert client.post("/v1/step/lock", json={"session_id": sid, "node_id": "auth"}).status_code == 200
    locked = _hook(client, hook_event_name="PreToolUse", tool_name="Write", cwd=str(project),
                   tool_input={"file_path": str(project / "auth.py"), "content": "x = 1\n"})["hookSpecificOutput"]
    assert locked["permissionDecisionReason"].startswith("[STEPCHECK CATCH — Gate A] auth (module): ")
    assert "LOCKED" in locked["permissionDecisionReason"]

    lines = _catches(project)
    assert [(c["gate"], c["module"], c["symbol"]) for c in lines] == [("B", "billing", "charge"), ("C", "billing", "charge"), ("A", "auth", "module")]
    for c in lines:
        assert set(c) >= {"timestamp", "module", "symbol", "gate", "code", "reason"}
        assert c["timestamp"].startswith("20") and c["reason"].startswith("[STEPCHECK CATCH — Gate ")
        assert c["hook"] == "PreToolUse" and c["session_id"] == sid
    assert lines[0]["code"] == "INTRA_NODE_SYMBOL_DROPPED" and lines[0]["tool"] == "Edit"
    # the declared `# okf-invariant:` expression on charge is judged before the mined guard
    assert lines[1]["code"] == "FRAME_INVARIANT" and "amount_cents <= 0" in lines[1]["reason"]
    assert lines[2]["code"] == "LOCKED" and lines[2]["tool"] == "Write"


def test_bash_and_stop_catches_are_recorded_too(tmp_path):
    import server

    root = tmp_path
    for rel, src in (("svc.py", SVC), ("client.py", CLIENT)):
        (root / rel).write_text(src, encoding="utf-8", newline="\n")
    with TestClient(server.app) as client:
        sid = _init(client, root)
        bash = dict(tool_name="Bash", cwd=str(root), tool_input={"command": "sed -i ... svc.py"})
        (root / "svc.py").write_text(STUBBED, encoding="utf-8", newline="\n")
        post = _hook(client, hook_event_name="PostToolUse", **bash)
        ctx = post["hookSpecificOutput"]["additionalContext"]
        assert ctx.startswith("[STEPCHECK CATCH — Gate B] svc.py (compute): ") and sid in ctx
        stop = _hook(client, hook_event_name="Stop", cwd=str(root))
        assert stop["decision"] == "block" and "[STEPCHECK CATCH — Gate B] svc (REJECTED): " in stop["reason"]
        assert "REJECTED" in stop["reason"] and sid in stop["reason"]
        (root / "svc.py").write_text(SVC, encoding="utf-8", newline="\n")
        assert _hook(client, hook_event_name="Stop", cwd=str(root)) == {}

        # a dirty dependent blocks the Stop with the same banner
        v = client.post("/v1/step/commit", json={"session_id": sid, "node_id": "svc",
                                                 "source": SVC.replace("def check(x):", "def check(x, strict):")}).json()
        assert v["accepted"] and v["dirtied"] == ["client"]
        stop = _hook(client, hook_event_name="Stop", cwd=str(root))
        assert "[STEPCHECK CATCH — Gate B] client (DIRTY_OMISSION_RISK): " in stop["reason"]

    lines = _catches(root)
    assert [(c["hook"], c["gate"], c["module"], c["code"]) for c in lines] == [
        ("PostToolUse", "B", "svc.py", "INTRA_NODE_BODY_STUBBED"),
        ("Stop", "B", "svc", "INTRA_NODE_BODY_STUBBED"),
        ("Stop", "B", "client", "INTER_NODE_DIRTY"),
    ]
    assert lines[0]["symbol"] == "compute" and lines[0]["tool"] == "Bash"


# ------------------------------------------------- 3. in-toto Statement v1


def test_compliance_bundle_leads_with_an_in_toto_statement(kernel, project):
    sid = kernel.init_session(project)
    kernel.lock_node(sid, "auth")
    assert kernel.commit(sid, "billing", patch=[{"op": "append", "code": "LIMIT = 1\n"}]).accepted
    assert kernel.commit(sid, "reports", patch=[{"op": "append", "code": "LIMIT = 2\n"}]).accepted

    bundle = kernel.compliance_bundle(sid)
    assert list(bundle)[0] == "Statement" and set(bundle) == {"Statement", "DUC", "DUA-E"}
    st = bundle["Statement"]
    assert st["_type"] == "https://in-toto.io/Statement/v1"
    assert st["predicateType"] == "https://stepcheck.dev/attestation/v1"
    assert list(st) == ["_type", "subject", "predicateType", "predicate"]
    names = [s["name"] for s in st["subject"]]
    assert names == sorted(names) == ["admin.py", "auth.py", "billing.py", "reports.py", "unrelated_sibling.py"]
    for s in st["subject"]:
        assert s["digest"] == {"sha256": hashlib.sha256((project / s["name"]).read_bytes()).hexdigest()}
    p = st["predicate"]
    assert p["builder"]["id"].startswith("https://") and p["session_id"] == sid
    assert p["attestations"]["merkle_root"] == bundle["DUC"]["attestations"]["merkle_root"] and p["attestations"]["count"] == 2
    assert p["gates"]["commits_accepted"] == 2 and p["gates"]["locked_modules"] == 1
    assert p["invariants"]["total"] >= 1 and p["files"] == 5
    mods = {m["path"]: m for m in p["modules"]}
    assert mods["billing.py"]["status"] == "VERIFIED" and mods["billing.py"]["attestation"]["count"] == 1
    assert mods["billing.py"]["attestation"]["sha256"] == mods["billing.py"]["sha256"]  # attests the bytes on disk
    assert mods["auth.py"]["locked"] is True and mods["auth.py"]["attestation"] is None
    envs = {e["node_digest"]: e["envelope"] for e in bundle["DUA-E"]["envelopes"]}
    assert [e["envelope"]["payloadType"] for e in p["dsse_envelopes"]] == ["application/vnd.in-toto+json"] * 2
    assert {e["node_digest"] for e in p["dsse_envelopes"]} == set(envs)
    assert p["public_card_digest"] == bundle["DUA-E"]["duc_digest"]
    assert sorted(p["controls"]) == sorted(bundle["DUC"]["controls"])
    again = kernel.compliance_bundle(project)["Statement"]
    assert json.dumps(again, sort_keys=True) == json.dumps(st, sort_keys=True)  # deterministic


def test_stepcheck_compliance_writes_the_statement_first(kernel, project, tmp_path, capsys):
    sid = kernel.init_session(project)
    assert kernel.commit(sid, "billing", patch=[{"op": "append", "code": "LIMIT = 1\n"}]).accepted
    out_a, out_b = tmp_path / "a", tmp_path / "b"
    assert cli.main(["compliance", str(project), "--out", str(out_a)]) == 0
    printed = capsys.readouterr().out
    wrote = [line for line in printed.splitlines() if line.startswith("wrote ")]
    assert "attestation.intoto.json" in wrote[0] and "in-toto Statement v1" in wrote[0]
    assert len(wrote) == 3 and "DUC.json" in wrote[1] and "DUA-E.json" in wrote[2]
    st = json.loads((out_a / "attestation.intoto.json").read_text(encoding="utf-8"))
    assert st["_type"] == "https://in-toto.io/Statement/v1" and len(st["subject"]) == 5
    assert cli.main(["compliance", str(project), "--out", str(out_b)]) == 0
    for name in ("attestation.intoto.json", "DUC.json", "DUA-E.json"):
        assert (out_a / name).read_bytes() == (out_b / name).read_bytes()
    assert os.environ.get("STEPCHECK_REQUIRE_KEY") is None
