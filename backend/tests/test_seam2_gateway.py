"""Seam 2 — DualDoorGateway HTTP/MCP boundary (backend/server.py).

No kernel internals are touched and nothing is mocked: tests drive the real
ASGI app (Door 1 + REST + WS) and a real uvicorn process for Streamable HTTP
MCP, against the same concrete fixture project as Seam 1.
"""
import socket
import threading
import time

import pytest
from conftest import BILLING_SRC
from fastapi.testclient import TestClient


@pytest.fixture()
def client(project):
    import server

    with TestClient(server.app) as c:
        yield c


def _init(client, project) -> str:
    r = client.post("/v1/step/init", json={"project_root": str(project)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert {n["node_id"] for n in body["nodes"]} >= {"auth", "billing", "reports"}
    return body["session_id"]


# ------------------------------------------------------------------ Door 2 REST


def test_rest_checkout_commit_lock_telemetry_roundtrip(client, project):
    sid = _init(client, project)

    r = client.post("/v1/step/checkout", json={"session_id": sid, "node_id": "billing"})
    assert r.status_code == 200
    payload = r.json()
    assert payload["node_id"] == "billing"
    assert 0 < payload["token_count"] < 4000
    assert "def charge" in payload["frame_markdown"]
    assert "UNRELATED_SIBLING_MARKER" not in payload["rendered"]

    r = client.post(
        "/v1/step/commit",
        json={"session_id": sid, "node_id": "billing", "source": BILLING_SRC},
    )
    assert r.status_code == 200
    verdict = r.json()
    assert verdict["accepted"] is True
    assert verdict["attestation"]["payload"]["node_id"] == "billing"

    r = client.post("/v1/step/lock", json={"session_id": sid, "node_id": "billing"})
    assert r.status_code == 200 and r.json()["status"] == "LOCKED"

    rejected = client.post(
        "/v1/step/commit",
        json={"session_id": sid, "node_id": "billing", "source": BILLING_SRC + "\n"},
    ).json()
    assert rejected["accepted"] is False and rejected["gate"] == "A"

    t = client.get(f"/v1/step/telemetry/{sid}").json()
    assert t["turns"] == 1  # the one checkout: commits are the write path and charge no turn
    assert t["compacted_okf_tokens"] > 0


# ------------------------------------------------- Door 1: TokenFirewall proxy

FILLER_TURN = "Let me look around... " + "irrelevant exploration DEADEND_MARKER " * 40


def _bloated_messages(final_user: str) -> list[dict]:
    msgs = [{"role": "system", "content": "You are a careful coding agent."}]
    for i in range(6):
        msgs.append({"role": "user", "content": f"continue step {i}"})
        msgs.append({"role": "assistant", "content": FILLER_TURN})
    msgs.append({"role": "user", "content": final_user})
    return msgs


def test_door1_chat_completions_prunes_and_injects_compact_payload(client, project):
    sid = _init(client, project)
    r = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-x", "messages": _bloated_messages("Now fix billing.py")},
        headers={"x-stepcheck-session": sid, "x-stepcheck-node": "billing"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "stepcheck-dry-run"  # no BYOK key -> deterministic dry-run
    fw = body["stepcheck"]
    assert fw["raw_tokens"] > fw["sent_tokens"] > 0

    sent = "\n".join(m["content"] for m in fw["sent_messages"])
    assert "def charge" in sent, "compact CheckoutPayload must be injected"
    assert "Now fix billing.py" in sent, "final user ask survives"
    assert "DEADEND_MARKER" not in sent, "dead-end exploration history is pruned"
    assert "UNRELATED_SIBLING_MARKER" not in sent

    # Dead-end turns were parked as drafts in the kernel scratchpad.
    assert client.get(f"/v1/step/drafts/{sid}").json()["count"] == 6


def test_door1_messages_commits_verified_step_and_surfaces_gate_verdict(client, project):
    sid = _init(client, project)
    good = _bloated_messages("ship it")
    good.insert(-1, {"role": "assistant", "content": f"Done:\n```python\n{BILLING_SRC}```"})
    r = client.post(
        "/v1/messages",
        json={"model": "claude-x", "max_tokens": 64, "messages": good},
        headers={"x-stepcheck-session": sid, "x-stepcheck-node": "billing"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "message" and body["model"] == "stepcheck-dry-run"
    assert body["stepcheck"]["commit"]["accepted"] is True

    bad_src = BILLING_SRC.replace("@require_auth\n", "")
    bad = _bloated_messages("ship it")
    bad.insert(-1, {"role": "assistant", "content": f"```python\n{bad_src}```"})
    r2 = client.post(
        "/v1/messages",
        json={"model": "claude-x", "max_tokens": 64, "messages": bad},
        headers={"x-stepcheck-session": sid, "x-stepcheck-node": "billing"},
    )
    verdict = r2.json()["stepcheck"]["commit"]
    assert verdict["accepted"] is False
    assert verdict["gate"] == "B" and verdict["subtype"] == "INTRA_NODE_SYMBOL_DROPPED"
    assert client.get(f"/v1/step/telemetry/{sid}").json()["omissions_blocked"] == 1


# ------------------------------------------------------------------------- WS


def test_ws_streams_snapshot_and_dirty_propagation(client, project):
    sid = _init(client, project)
    with client.websocket_connect(f"/v1/ws/{sid}") as ws:
        snap = ws.receive_json()
        assert snap["type"] == "snapshot"
        statuses = {n["node_id"]: n["status"] for n in snap["graph"]["nodes"]}
        assert statuses["billing"] == "ACTIVE"

        from conftest import AUTH_SRC

        changed = AUTH_SRC.replace(
            "def check_permission(user: str, action: str) -> bool:",
            'def check_permission(user: str, action: str, scope: str = "x") -> bool:',
        )
        r = client.post(
            "/v1/step/commit",
            json={"session_id": sid, "node_id": "auth", "source": changed},
        )
        assert r.json()["accepted"] and r.json()["dirtied"] == ["admin", "billing"]

        got = {}
        for _ in range(3):
            msg = ws.receive_json()
            got[msg["type"]] = msg
        assert "gate_event" in got and got["gate_event"]["accepted"] is True
        graph = {n["node_id"]: n["status"] for n in got["graph"]["graph"]["nodes"]}
        assert graph["admin"] == graph["billing"] == "DIRTY_OMISSION_RISK"
        assert "telemetry" in got


# ------------------------------------------- Door 2: Streamable HTTP MCP server


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_server():
    import uvicorn

    import server

    port = _free_port()
    config = uvicorn.Config(server.app, host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not srv.started:
        if time.time() > deadline:
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    thread.join(timeout=10)


@pytest.mark.asyncio
async def test_mcp_streamable_http_tools(live_server, project):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    async with streamablehttp_client(f"{live_server}/mcp/") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
            assert tools >= {
                "checkout_context_frame",
                "commit_verified_step",
                "lock_module_invariants",
                "check_omission_risks",
                "get_token_savings",
            }

            init = await session.call_tool("init_project_session", {"project_root": str(project)})
            sid = init.structuredContent["session_id"]

            co = await session.call_tool(
                "checkout_context_frame", {"session_id": sid, "node_id": "billing"}
            )
            assert "def charge" in co.structuredContent["rendered"]
            assert co.structuredContent["token_count"] < 4000

            bad = await session.call_tool(
                "commit_verified_step",
                {
                    "session_id": sid,
                    "node_id": "billing",
                    "source": BILLING_SRC.replace("@require_auth\n", ""),
                },
            )
            assert bad.structuredContent["accepted"] is False
            assert bad.structuredContent["gate"] == "B"

            risks = await session.call_tool("check_omission_risks", {"session_id": sid})
            assert risks.structuredContent["can_finalize"] is True

            lock = await session.call_tool(
                "lock_module_invariants", {"session_id": sid, "node_id": "auth"}
            )
            assert lock.structuredContent["status"] == "LOCKED"

            sav = await session.call_tool("get_token_savings", {"session_id": sid})
            assert sav.structuredContent["omissions_blocked"] == 1


# --------------------------------- Door 1: focus slicing + stepcheck-patch folding


def test_door1_focus_header_serves_skeleton_and_folds_patch(client, project):
    sid = _init(client, project)
    patch = [
        {"op": "append", "code": "def _tax(cents: int) -> int:\n    return cents // 10\n"}
    ]
    import json

    msgs = _bloated_messages("add the tax helper")
    msgs.insert(-1, {"role": "assistant", "content": f"```stepcheck-patch\n{json.dumps(patch)}\n```"})
    r = client.post(
        "/v1/messages",
        json={"model": "claude-x", "max_tokens": 64, "messages": msgs},
        headers={
            "x-stepcheck-session": sid,
            "x-stepcheck-node": "billing",
            "x-stepcheck-focus": "charge",
        },
    )
    assert r.status_code == 200, r.text
    fw = r.json()["stepcheck"]
    assert fw["commit"]["accepted"] is True
    sent = "\n".join(m["content"] for m in fw["sent_messages"])
    assert "def charge" in sent and "def _tax" in sent  # folded into canonical state
    assert 'entry["ok"] = True' not in sent  # _audit body skeletonized
    assert "hashlib.sha256" not in sent
    assert fw["sent_tokens"] < 700


# ------------------------------------------------- Studio static mount coexists


def test_studio_static_mount_coexists_with_api_mcp_and_ws(client, project):
    import server

    if not server.STUDIO_DIST.exists():
        pytest.skip(f"frontend not built at {server.STUDIO_DIST}")
    r = client.get("/studio/")
    assert r.status_code == 200 and 'id="root"' in r.text
    assert "/studio/assets/" in r.text, "built assets must resolve under the mount"
    # SPA deep links fall back to index.html.
    assert client.get("/studio/session/abc").status_code == 200
    # Bare /studio redirects into the mount.
    assert client.get("/studio", follow_redirects=False).status_code in (301, 307)

    # Every API surface still answers on the same port.
    sid = _init(client, project)
    assert client.get(f"/v1/step/graph/{sid}").status_code == 200
    with client.websocket_connect(f"/v1/ws/{sid}") as ws:
        assert ws.receive_json()["type"] == "snapshot"
    assert client.get("/v1/step/graph/nope").status_code == 404
    assert client.get("/studio/assets/definitely-missing.js").status_code == 404
