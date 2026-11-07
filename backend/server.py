"""DualDoorGateway — the whole HTTP surface behind Seam 2 (see GLOSSARY.md).

Door 1 (TokenFirewall proxy): POST /v1/chat/completions · POST /v1/messages.
Intercepts bloated `messages[]`, commits the latest verified code step into the
StateKernel, parks dead-end exploration turns as drafts, injects the compact
CheckoutPayload, and forwards upstream with the caller's own BYOK key — or
answers a deterministic local dry-run when no upstream is configured.

Door 2 (explicit surface): REST /v1/step/*, Streamable HTTP MCP at /mcp
(FastMCP, sharing the FastAPI lifespan — no legacy /sse), and
WS /v1/ws/{session_id} for real-time UI state streaming.

Tested only at this boundary (tests/test_seam2_gateway.py); kernel internals
are Seam 1's business.
"""
from __future__ import annotations

import dataclasses
import math
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import json

import httpx
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from kernel import StateKernel

# When this process loaded the kernel code: the SessionStart staleness guard compares
# it with the backend sources' mtimes (see the hook script's _session_start).
STARTED_AT = time.time()

KERNEL = StateKernel()

# Compiled Studio UI (frontend/dist, built with Vite base "/studio/"). Mounted
# at /studio when present so one port serves UI + API + MCP + WS.
STUDIO_DIST = Path(
    os.environ.get("STEPCHECK_STUDIO_DIST", Path(__file__).resolve().parents[1] / "frontend" / "dist")
)

_CODE_RE = re.compile(r"```python\n(.*?)```", re.S)
_PATCH_RE = re.compile(r"```stepcheck-patch\n(.*?)```", re.S)


def _count(text: str) -> int:
    return math.ceil(len(text) / 4)


# --------------------------------------------------------------- WS streaming


class _WsManager:
    def __init__(self) -> None:
        self._conns: dict[str, list[WebSocket]] = {}

    async def connect(self, session_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._conns.setdefault(session_id, []).append(ws)

    def drop(self, session_id: str, ws: WebSocket) -> None:
        conns = self._conns.get(session_id, [])
        if ws in conns:
            conns.remove(ws)

    async def broadcast(self, session_id: str, message: dict) -> None:
        for ws in list(self._conns.get(session_id, [])):
            try:
                await ws.send_json(message)
            except Exception:
                self.drop(session_id, ws)


WS = _WsManager()


def _telemetry_json(session_id: str) -> dict:
    return dataclasses.asdict(KERNEL.get_telemetry(session_id))


def _verdict_json(verdict) -> dict:
    return {
        "accepted": verdict.accepted,
        "gate": verdict.gate,
        "error": str(verdict.error) if verdict.error else None,
        "subtype": getattr(verdict.error, "subtype", None),
        "attestation": verdict.attestation,
        "dirtied": verdict.dirtied,
        "reverified": verdict.reverified,
    }


async def _broadcast_mutation(session_id: str, gate_event: dict | None = None) -> None:
    if gate_event is not None:
        await WS.broadcast(session_id, {"type": "gate_event", **gate_event})
    await WS.broadcast(session_id, {"type": "graph", "graph": KERNEL.graph(session_id)})
    await WS.broadcast(
        session_id, {"type": "telemetry", "telemetry": _telemetry_json(session_id)}
    )


# ---------------------------------------------- Door 2: Streamable HTTP MCP


def _build_mcp() -> FastMCP:
    """Fresh FastMCP per app startup — its StreamableHTTPSessionManager only
    runs once per instance, and the FastAPI lifespan may re-enter (tests,
    reloads)."""
    m = FastMCP(
        "stepcheck-dev",
        stateless_http=True,
        streamable_http_path="/",
        instructions=(
            "Anti-context-rot state engine for coding agents: checkout a compact "
            "OKF frame, commit verified steps through the 3-tier gates, lock "
            "invariants, watch omission risks, and read token savings."
        ),
    )

    @m.tool()
    async def init_project_session(project_root: str) -> dict[str, Any]:
        """Index a Python project into an OKF graph and open a session."""
        session_id = KERNEL.init_session(project_root)
        return {"session_id": session_id, "graph": KERNEL.graph(session_id)}

    @m.tool()
    async def checkout_context_frame(
        session_id: str, node_id: str, focus: list[str] | None = None
    ) -> dict[str, Any]:
        """Bounded stateless checkout: the node's frame + dependency interface
        skeletons. `focus=[names]` slices the target to those defs (verbatim)
        plus a skeleton of the rest; `focus=[]` is a pure skeleton."""
        try:
            payload = KERNEL.checkout(session_id, node_id, focus=focus)
        except KeyError as exc:
            raise ValueError(f"unknown session or node: {exc}")
        return {
            "session_id": session_id,
            "node_id": node_id,
            "rendered": payload.rendered(),
            "dependency_signatures": payload.dependency_signatures,
            "locked_invariants": payload.locked_invariants,
            "token_count": payload.token_count,
        }

    @m.tool()
    async def commit_verified_step(
        session_id: str,
        node_id: str,
        source: str | None = None,
        patch: list[dict[str, Any]] | None = None,
        allow_deletion: bool = False,
    ) -> dict[str, Any]:
        """Run a staged `source` — or a `patch` of ops folded into canonical
        state ({"op":"append"|"replace_symbol"|"delete_symbol", …}) — through
        Gates A/B/C; attest on pass."""
        verdict = KERNEL.commit(
            session_id, node_id, source, patch=patch, allow_deletion=allow_deletion
        )
        out = _verdict_json(verdict)
        await _broadcast_mutation(session_id, gate_event={"node_id": node_id, **out})
        return out

    @m.tool()
    async def lock_module_invariants(session_id: str, node_id: str) -> dict[str, Any]:
        """Pin a verified module: every further mutation is rejected at Gate A."""
        KERNEL.lock_node(session_id, node_id)
        await _broadcast_mutation(session_id)
        return {"node_id": node_id, "status": "LOCKED", "locked": True}

    @m.tool()
    async def check_omission_risks(session_id: str) -> dict[str, Any]:
        """Nodes holding DIRTY_OMISSION_RISK and whether the session can finalize."""
        graph = KERNEL.graph(session_id)
        dirty = [
            n["node_id"] for n in graph["nodes"] if n["status"] == "DIRTY_OMISSION_RISK"
        ]
        return {"dirty": dirty, "can_finalize": not dirty}

    @m.tool()
    async def get_token_savings(session_id: str) -> dict[str, Any]:
        """raw_bloated_tokens vs compacted_okf_tokens and dollars saved."""
        return _telemetry_json(session_id)

    return m


class _McpMountProxy:
    """Stable mount point whose inner ASGI app is swapped on each startup."""

    def __init__(self) -> None:
        self.inner = None

    async def __call__(self, scope, receive, send):
        if self.inner is None:  # pragma: no cover — requests before startup
            raise RuntimeError("MCP app not started")
        await self.inner(scope, receive, send)


_MCP_MOUNT = _McpMountProxy()


# ----------------------------------------------------------------- FastAPI app


@asynccontextmanager
async def lifespan(app: FastAPI):
    # The MCP session manager shares the FastAPI lifespan (streamable-http).
    m = _build_mcp()
    _MCP_MOUNT.inner = m.streamable_http_app()
    async with m.session_manager.run():
        yield


app = FastAPI(title="StepCheck DualDoorGateway", lifespan=lifespan)
app.mount("/mcp", _MCP_MOUNT)


# ------------------------------------------------------------ Door 2: REST


class InitBody(BaseModel):
    project_root: str


class NodeBody(BaseModel):
    session_id: str
    node_id: str


class CheckoutBody(NodeBody):
    focus: list[str] | None = None


class CommitBody(NodeBody):
    source: str | None = None
    patch: list[dict] | None = None
    allow_deletion: bool = False


def _or_404(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"unknown session or node: {exc}")


@app.post("/v1/step/init")
async def step_init(body: InitBody) -> dict:
    session_id = KERNEL.init_session(body.project_root)
    return {"session_id": session_id, **KERNEL.graph(session_id)}


@app.post("/v1/step/checkout")
async def step_checkout(body: CheckoutBody) -> dict:
    payload = _or_404(KERNEL.checkout, body.session_id, body.node_id, focus=body.focus)
    return {
        "session_id": body.session_id,
        "node_id": body.node_id,
        "frame_markdown": payload.frame_markdown,
        "dependency_signatures": payload.dependency_signatures,
        "locked_invariants": payload.locked_invariants,
        "token_count": payload.token_count,
        "rendered": payload.rendered(),
    }


@app.post("/v1/step/commit")
async def step_commit(body: CommitBody) -> dict:
    verdict = _or_404(
        KERNEL.commit,
        body.session_id,
        body.node_id,
        body.source,
        patch=body.patch,
        allow_deletion=body.allow_deletion,
    )
    out = _verdict_json(verdict)
    await _broadcast_mutation(body.session_id, gate_event={"node_id": body.node_id, **out})
    return out


@app.post("/v1/step/lock")
async def step_lock(body: NodeBody) -> dict:
    _or_404(KERNEL.lock_node, body.session_id, body.node_id)
    await _broadcast_mutation(body.session_id)
    return {"node_id": body.node_id, "status": "LOCKED", "locked": True}


@app.get("/v1/step/graph/{session_id}")
async def step_graph(session_id: str) -> dict:
    return _or_404(KERNEL.graph, session_id)


@app.get("/v1/step/telemetry/{session_id}")
async def step_telemetry(session_id: str) -> dict:
    return _or_404(_telemetry_json, session_id)


@app.get("/v1/step/drafts/{session_id}")
async def step_drafts(session_id: str) -> dict:
    drafts = _or_404(KERNEL.drafts, session_id)
    return {"count": len(drafts), "drafts": drafts}


@app.post("/v1/step/finalize")
async def step_finalize(body: InitBody | None = None, session_id: str | None = None) -> dict:
    sid = session_id or (body and body.project_root)
    raise HTTPException(status_code=400, detail="use POST /v1/step/finalize/{session_id}")


@app.post("/v1/step/finalize/{session_id}")
async def step_finalize_sid(session_id: str) -> dict:
    from kernel import OmissionError

    try:
        _or_404(KERNEL.finalize_session, session_id)
    except OmissionError as exc:
        return {"finalized": False, "error": str(exc), "subtype": exc.subtype}
    return {"finalized": True}


# ------------------------------------------------------------------------- WS


@app.websocket("/v1/ws/{session_id}")
async def ws_session(ws: WebSocket, session_id: str) -> None:
    await WS.connect(session_id, ws)
    try:
        await ws.send_json(
            {
                "type": "snapshot",
                "graph": KERNEL.graph(session_id),
                "telemetry": _telemetry_json(session_id),
            }
        )
        while True:
            await ws.receive_text()  # keepalive / client pings
    except (WebSocketDisconnect, KeyError):
        pass
    finally:
        WS.drop(session_id, ws)


# ------------------------------------------- Door 1: TokenFirewall proxy


def _msg_text(message: dict) -> str:
    """Text of a message in either API shape, tool_result blocks and `role: "tool"`
    messages included (the accordion's reader), so raw / sent token counts and
    step detection see what the model would see."""
    from kernel import _accordion

    return _accordion.message_text(message)


def _extract_step(text: str) -> tuple[str, object] | None:
    """Latest verified step in an assistant turn: ("patch", ops) folds AST-level
    ops into canonical state; ("source", code) stages a whole module."""
    patches = _PATCH_RE.findall(text)
    if patches:
        try:
            return ("patch", json.loads(patches[-1]))
        except json.JSONDecodeError:
            return None
    matches = _CODE_RE.findall(text)
    return ("source", matches[-1]) if matches else None


async def _run_firewall(
    body: dict,
    session_id: str,
    node_id: str | None,
    api: str,
    focus: list[str] | None = None,
    headers: dict | None = None,
) -> dict:
    """Door 1 firewall for one proxied turn. The latest assistant step is folded
    through the gates; every other assistant turn is parked as a draft. What is
    forwarded is: the caller's system prompts, the compact CheckoutPayload of the
    active node, and the conversation after three-band accordion compaction
    (recent band verbatim, middle band with large source blocks skeletonized,
    oldest band folded into a session-state frame after a cache cliff). The
    `x-stepcheck-tier` header (or STEPCHECK_TIER_POLICY) selects the model tier;
    without it the request's own model is used, as before."""
    from kernel import _accordion

    hdrs = {str(k).lower(): v for k, v in (headers or {}).items()}
    messages: list[dict] = body.get("messages", [])
    systems = [
        _msg_text(m) for m in messages if m.get("role") == "system"
    ]
    if api == "anthropic" and isinstance(body.get("system"), str):
        systems.insert(0, body["system"])

    # The latest assistant ```python block is the step output; everything else
    # by the agent is dead-end scratch to park.
    last_step, last_idx = None, -1
    for i, m in enumerate(messages):
        if m.get("role") == "assistant":
            step = _extract_step(_msg_text(m))
            if step:
                last_step, last_idx = step, i

    commit_info = None
    for i, m in enumerate(messages):
        if m.get("role") not in ("assistant", "tool"):
            continue
        if i == last_idx and last_step is not None and node_id:
            kind, value = last_step
            if kind == "patch":
                verdict = KERNEL.commit(session_id, node_id, patch=value)
            else:
                verdict = KERNEL.commit(session_id, node_id, value)
            commit_info = _verdict_json(verdict)
            await _broadcast_mutation(
                session_id, gate_event={"node_id": node_id, **commit_info}
            )
        else:
            KERNEL.record_draft(session_id, node_id or "__chat__", _msg_text(m))

    sent: list[dict] = [{"role": "system", "content": s} for s in systems]
    if node_id:
        payload = _or_404(KERNEL.checkout, session_id, node_id, focus=focus)
        sent.append(
            {
                "role": "system",
                "content": "## StepCheck CheckoutPayload\n\n" + payload.rendered(),
            }
        )
    last_turn_at = _accordion.parse_timestamp(hdrs.get("x-stepcheck-last-turn-at"))
    if last_turn_at is None:
        last_turn_at = _accordion.latest_message_timestamp(messages)
    compaction = _accordion.ContextCompactor().compact(
        messages,
        is_step=lambda m: m.get("role") == "assistant" and _extract_step(_msg_text(m)) is not None,
        last_turn_at=last_turn_at,
        summary=lambda: _session_summary(session_id, node_id),
    )
    sent.extend(compaction.messages)

    routing = _route(hdrs, body, node_id, focus, last_step, commit_info)
    raw_tokens = sum(_count(_msg_text(m)) for m in messages) + sum(
        _count(s) for s in systems if api == "anthropic"
    )
    sent_tokens = sum(_count(_msg_text(m)) for m in sent)
    _record_door1(session_id, compaction.report(), routing, sent_tokens, body.get("model"))
    return {
        "session_id": session_id,
        "node_id": node_id,
        "raw_tokens": raw_tokens,
        "sent_tokens": sent_tokens,
        "tokens_pruned": raw_tokens - sent_tokens,
        "sent_messages": sent,
        "compaction": compaction.report(),
        "routing": routing,
        "commit": commit_info,
        "telemetry": _telemetry_json(session_id),
    }


def _session_from(request: Request, body: dict) -> tuple[str, str | None, list[str] | None]:
    sc = body.get("stepcheck", {}) if isinstance(body.get("stepcheck"), dict) else {}
    session_id = request.headers.get("x-stepcheck-session") or sc.get("session_id")
    node_id = request.headers.get("x-stepcheck-node") or sc.get("node_id")
    # focus: header "a,b" or "" (pure skeleton); body.stepcheck.focus as a list.
    focus: list[str] | None = None
    if "x-stepcheck-focus" in request.headers:
        raw = request.headers["x-stepcheck-focus"].strip()
        focus = [f.strip() for f in raw.split(",") if f.strip()] if raw else []
    elif isinstance(sc.get("focus"), list):
        focus = [str(f) for f in sc["focus"]]
    if not session_id:
        raise HTTPException(
            status_code=400,
            detail="x-stepcheck-session header (or body.stepcheck.session_id) required",
        )
    return session_id, node_id, focus


async def _maybe_forward(
    request: Request, body: dict, fw: dict, api: str
) -> dict | None:
    """BYOK upstream routing: only when the caller supplies key AND base URL.
    The model forwarded is the one the tier router chose (`fw["routing"]`)."""
    upstream = request.headers.get("x-stepcheck-upstream") or os.environ.get(
        "STEPCHECK_UPSTREAM_BASE"
    )
    key = request.headers.get("authorization") or request.headers.get("x-api-key")
    if not upstream or not key:
        return None
    path = "/v1/messages" if api == "anthropic" else "/v1/chat/completions"
    out_body = dict(body)
    out_body["messages"] = [
        m for m in fw["sent_messages"] if not (api == "anthropic" and m["role"] == "system")
    ]
    routed_model = (fw.get("routing") or {}).get("model")
    if routed_model:
        out_body["model"] = routed_model
    headers = {"content-type": "application/json"}
    if api == "anthropic":
        out_body["system"] = "\n\n".join(
            m["content"] for m in fw["sent_messages"] if m["role"] == "system"
        )
        headers["x-api-key"] = request.headers.get("x-api-key", "")
        headers["anthropic-version"] = request.headers.get(
            "anthropic-version", "2023-06-01"
        )
    else:
        headers["authorization"] = request.headers.get("authorization", "")
    out_body.pop("stepcheck", None)
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(upstream.rstrip("/") + path, json=out_body, headers=headers)
    data = resp.json()
    data["stepcheck"] = fw
    return data


_DRY_NOTICE = (
    "StepCheck dry-run: no BYOK upstream configured. The compacted request this "
    "firewall would have forwarded is in `stepcheck.sent_messages`."
)


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> dict:
    body = await request.json()
    session_id, node_id, focus = _session_from(request, body)
    fw = await _run_firewall(body, session_id, node_id, api="openai", focus=focus, headers=dict(request.headers))
    forwarded = await _maybe_forward(request, body, fw, api="openai")
    if forwarded is not None:
        return forwarded
    return {
        "id": f"sc-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": 0,
        "model": "stepcheck-dry-run",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": _DRY_NOTICE},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": fw["sent_tokens"],
            "completion_tokens": 0,
            "total_tokens": fw["sent_tokens"],
        },
        "stepcheck": fw,
    }


@app.post("/v1/messages")
async def anthropic_messages(request: Request) -> dict:
    body = await request.json()
    session_id, node_id, focus = _session_from(request, body)
    fw = await _run_firewall(body, session_id, node_id, api="anthropic", focus=focus, headers=dict(request.headers))
    forwarded = await _maybe_forward(request, body, fw, api="anthropic")
    if forwarded is not None:
        return forwarded
    return {
        "id": f"msg-sc-{uuid.uuid4().hex[:12]}",
        "type": "message",
        "role": "assistant",
        "model": "stepcheck-dry-run",
        "content": [{"type": "text", "text": _DRY_NOTICE}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": fw["sent_tokens"], "output_tokens": 0},
        "stepcheck": fw,
    }


# ----------------------------------------------------- Studio static mount


@app.get("/studio", include_in_schema=False)
async def studio_root() -> RedirectResponse:
    return RedirectResponse(url="/studio/", status_code=307)


class _SpaStaticFiles(StaticFiles):
    """Serve real files; fall back to index.html for SPA deep links, but keep a
    genuine 404 for missing hashed assets so broken builds surface."""

    async def get_response(self, path: str, scope):
        from starlette.exceptions import HTTPException as StarletteHTTPException

        # Starlette builds `path` with os.path.join, so Windows yields backslashes.
        path = path.replace("\\", "/")
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404 and not path.startswith("assets/"):
                return await super().get_response("index.html", scope)
            raise


if STUDIO_DIST.exists():
    app.mount("/studio", _SpaStaticFiles(directory=str(STUDIO_DIST), html=True), name="studio")


@app.post("/v1/step/hook")
async def step_hook(request: Request) -> dict:
    """Warm fast path for Claude Code lifecycle hooks. The installed hook script
    (`stepcheck hooks`) relays its stdin JSON here and prints the answer, so a
    `PreToolUse` Read of a big tracked module comes back as the `focus=[]`
    skeleton, an Edit of a LOCKED module is denied with the Gate A diagnostic,
    and `Stop` is blocked while DIRTY_OMISSION_RISK nodes remain — all against
    the in-memory kernel, no interpreter start-up. Policy: hooks.decide."""
    import hooks

    try:
        event = await request.json()
    except ValueError:
        event = {}
    event = event if isinstance(event, dict) else {}
    out = hooks.decide(event, KERNEL)
    if event.get("hook_event_name") == "SessionStart":
        # Identity for the relay's staleness guard; the relay strips this key.
        out = dict(out, stepcheck_gateway={"pid": os.getpid(), "started": STARTED_AT,
                                           "daemon": os.environ.get("STEPCHECK_DAEMON") == "1"})
    return out


def _session_summary(session_id: str, node_id: str | None) -> str:
    """The oldest band after a cache cliff: one compact OKF session-state frame —
    every node's status and latest attestation digest. The active node's own
    compact frame is already injected as the CheckoutPayload system message."""
    graph = _or_404(KERNEL.graph, session_id)
    lines = ["## StepCheck session state (older turns folded after a cache cliff)", ""]
    for n in graph["nodes"]:
        att = n.get("attestation")
        digest = f", attested {att['payload']['sha256'][:12]}" if att else ""
        active = " (active; compact frame above)" if n["node_id"] == node_id else ""
        lines.append(f"- {n['node_id']}: {n['status']}{digest}{active}")
    return "\n".join(lines)


def _route(headers: dict, body: dict, node_id: str | None, focus: list[str] | None,
           last_step: tuple[str, object] | None, commit_info: dict | None) -> dict:
    """Gate-backed model tiering. Policy from `x-stepcheck-tier` or
    STEPCHECK_TIER_POLICY (default `frontier`: the request's model, unchanged).
    `auto` sends a focused single-symbol turn to STEPCHECK_FAST_MODEL and, when
    the draft that turn produced was rejected at a gate, escalates this turn
    back to the frontier model named in the request."""
    policy = str(headers.get("x-stepcheck-tier") or os.environ.get("STEPCHECK_TIER_POLICY", "frontier")).strip().lower()
    frontier = body.get("model") or ""
    fast = os.environ.get("STEPCHECK_FAST_MODEL", "claude-haiku-4-5")
    single_patch = (
        last_step is not None and last_step[0] == "patch" and isinstance(last_step[1], list)
        and len(last_step[1]) == 1 and isinstance(last_step[1][0], dict) and last_step[1][0].get("op") == "replace_symbol"
    )
    focused = bool(node_id) and ((focus is not None and len(focus) == 1) or single_patch)
    if policy == "fast" or (policy == "auto" and focused):
        tier, model = "fast", fast
    else:
        tier, model = "frontier", frontier
    escalated, gate = False, None
    if tier == "fast" and commit_info and not commit_info.get("accepted"):
        escalated, gate, tier, model = True, commit_info.get("gate"), "frontier", frontier
    return {"policy": policy, "tier": tier, "model": model, "escalated": escalated, "gate": gate, "focused_turn": focused}


def _record_door1(session_id: str, report: dict, routing: dict, sent_tokens: int, frontier_model: str | None) -> None:
    """Persist one Door 1 turn as a `door1` session event (band token counts,
    cache-cliff fold, pruned/folded messages, routing decision with the frontier
    and fast model names) so the team ledger can aggregate compaction, shield
    and arbitrage figures across sessions."""
    try:
        KERNEL.record_event(session_id, {
            "kind": "door1",
            "tokens_before": int(report.get("tokens_before") or 0),
            "tokens_after": int(report.get("tokens_after") or 0),
            "pruned_messages": int(report.get("pruned_messages") or 0),
            "folded_messages": int(report.get("folded_messages") or 0),
            "cache_cliff": bool(report.get("cache_cliff")),
            "sent_tokens": int(sent_tokens),
            "routing": {**routing, "frontier_model": frontier_model,
                        "fast_model": os.environ.get("STEPCHECK_FAST_MODEL", "claude-haiku-4-5")},
        })
    except KeyError:
        pass


_LICENSED_PATHS = {
    "/v1/messages": "door1_accordion",
    "/v1/chat/completions": "door1_accordion",
    "/v1/team/summary": "team_summary",
}


@app.middleware("http")
async def _license_gate(request: Request, call_next):
    """Opt-in tier enforcement (STEPCHECK_REQUIRE_KEY=1): Door 1 needs `pro`,
    the team ledger needs `team`, verified from `X-StepCheck-Key`; without
    enforcement every path is open and nothing here runs. Policy: licensing."""
    import licensing
    from fastapi.responses import JSONResponse

    capability = _LICENSED_PATHS.get(request.url.path)
    if capability is not None:
        denial = licensing.gate_headers(dict(request.headers), capability)
        if denial is not None:
            return JSONResponse(status_code=402, content=denial)
    return await call_next(request)


@app.middleware("http")
async def _session_freshness(request: Request, call_next):
    """Before any session-backed request (REST, the hook relay, MCP, Door 1):
    evict sessions whose `.stepcheck/sessions/<id>.json` was archived or
    deleted, and reload any another process rewrote (StateKernel.refresh_sessions),
    so a long-lived gateway never answers from a stale in-memory copy."""
    path = request.url.path
    if path.startswith(("/v1/", "/mcp")):
        KERNEL.refresh_sessions()
    return await call_next(request)


@app.get("/v1/team/summary")
async def team_summary(request: Request, project_root: str | None = None) -> dict:
    """Team FinOps & governance ledger across every registered session (or the
    sessions of `project_root`): checkout telemetry, Door 1 compaction and
    cache-cliff shield, model-arbitrage dollars, regressions caught per gate,
    DIRTY_OMISSION_RISK flags raised and re-verified, and the tier in force."""
    import ledger
    import licensing

    roots = [Path(project_root)] if project_root else None
    tier = licensing.held_tier(request.headers.get(licensing.HEADER))
    return ledger.summarize(KERNEL, roots, tier=tier, enforcement=licensing.enforcement_enabled())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8420")))
