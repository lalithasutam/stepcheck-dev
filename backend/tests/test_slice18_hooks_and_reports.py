"""Slice 18 — warm daemon hooks and team artifacts: `POST /v1/step/hook` on the
DualDoorGateway evaluating Claude Code lifecycle events against the in-memory
StateKernel, `stepcheck hooks` (idempotent installer with an offline-safe hook
script), `stepcheck ci --report` (deterministic PR blast-radius + provenance
checklist) and `stepcheck audit --card` (zero-code-leak SVG/Markdown badge).
Seam 2 through the real ASGI app, CLI seam through `cli.main`."""
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

import pytest
from conftest import BILLING_SRC
from fastapi.testclient import TestClient

import cli
from kernel import StateKernel

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "benchmarks" / "fixtures" / "sample_session.jsonl"

BIG_SRC = "import hashlib\n\n\n" + "".join(
    f'def handler_{i}(payload: dict, retries: int = {i}) -> dict:\n'
    f'    """Handler number {i} of the big module."""\n'
    f'    if not payload:\n        raise ValueError("empty payload {i}")\n'
    f'    digest = hashlib.sha256(repr(sorted(payload.items())).encode()).hexdigest()\n'
    f'    return {{"id": {i}, "digest": digest, "retries": retries, "size": len(payload)}}\n\n\n'
    for i in range(40)
)


@pytest.fixture()
def client(project):
    import server

    with TestClient(server.app) as c:
        yield c


def _init(client, project) -> str:
    r = client.post("/v1/step/init", json={"project_root": str(project)})
    assert r.status_code == 200, r.text
    return r.json()["session_id"]


def _hook(client, **event) -> dict:
    r = client.post("/v1/step/hook", json=event)
    assert r.status_code == 200, r.text
    return r.json()


def _p95(xs):
    s = sorted(xs)
    return s[round(0.95 * (len(s) - 1))]


# ------------------------------------------- 1. POST /v1/step/hook (Seam 2)


def test_hook_read_of_a_big_tracked_module_returns_its_skeleton(client, project):
    (project / "big.py").write_text(BIG_SRC, encoding="utf-8", newline="\n")
    sid = _init(client, project)
    read = lambda name: _hook(  # noqa: E731
        client, hook_event_name="PreToolUse", tool_name="Read", cwd=str(project),
        tool_input={"file_path": str(project / name)},
    )

    out = read("big.py")
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse" and hso["permissionDecision"] == "deny"
    assert "big.py" in hso["permissionDecisionReason"] and sid in hso["permissionDecisionReason"]
    ctx = hso["additionalContext"]
    assert "def handler_0(" in ctx and "def handler_39(" in ctx  # every signature survives
    assert "hexdigest()" not in ctx  # bodies do not
    assert read("billing.py") == {}  # tracked but under the threshold
    assert read("README.md") == {}  # not a tracked module
    # The threshold is per request: a strict one turns billing.py into a skeleton too.
    strict = _hook(client, hook_event_name="PreToolUse", tool_name="Read", cwd=str(project),
                   tool_input={"file_path": str(project / "billing.py")}, threshold=10)
    assert strict["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "def charge(" in strict["hookSpecificOutput"]["additionalContext"]


def test_hook_denies_edits_of_locked_modules_with_the_gate_a_diagnostic(client, project):
    sid = _init(client, project)
    assert client.post("/v1/step/lock", json={"session_id": sid, "node_id": "auth"}).status_code == 200
    edit = lambda tool, name: _hook(  # noqa: E731
        client, hook_event_name="PreToolUse", tool_name=tool, cwd=str(project),
        tool_input={"file_path": str(project / name), "old_string": "x", "new_string": "y"},
    )
    denied = edit("Edit", "auth.py")["hookSpecificOutput"]
    assert denied["permissionDecision"] == "deny" and "LOCKED" in denied["permissionDecisionReason"]
    assert "Gate A" in denied["permissionDecisionReason"]
    assert edit("Write", "auth.py")["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert edit("Edit", "billing.py") == {}  # unlocked: no opinion
    assert edit("Edit", "nothing.py") == {}


def test_hook_stop_blocks_until_dirty_dependents_are_reverified(client, project):
    sid = _init(client, project)
    stop = lambda **extra: _hook(client, hook_event_name="Stop", cwd=str(project), **extra)  # noqa: E731
    assert stop() == {}

    changed = BILLING_SRC.replace(
        "def charge(user: str, amount_cents: int) -> dict:",
        'def charge(user: str, amount_cents: int, currency: str = "usd") -> dict:',
    )
    v = client.post("/v1/step/commit", json={"session_id": sid, "node_id": "billing", "source": changed}).json()
    assert v["accepted"] and v["dirtied"] == ["reports"]

    blocked = stop()
    assert blocked["decision"] == "block" and "reports" in blocked["reason"] and sid in blocked["reason"]
    assert stop(stop_hook_active=True) == {}  # never loop on the agent
    assert stop(stepcheck_session_id=sid)["decision"] == "block"

    reports_src = (project / "reports.py").read_text(encoding="utf-8")
    ok = client.post("/v1/step/commit", json={"session_id": sid, "node_id": "reports", "source": reports_src}).json()
    assert ok["accepted"]
    assert stop() == {}


def test_hook_endpoint_p95_under_25ms(client, project):
    """The governance decisions (Stop, Edit of a tracked module, Read under the
    threshold) answer from the warm kernel in well under the 25 ms p95 budget,
    where the subprocess prototype needed a few hundred milliseconds per call.
    A denied Read is the one path that does kernel work — a real
    `checkout(focus=[])` that is charged to telemetry and persisted — so it is
    bounded separately rather than hidden in the mix."""
    (project / "big.py").write_text(BIG_SRC, encoding="utf-8", newline="\n")
    _init(client, project)
    decisions = [
        dict(hook_event_name="Stop", cwd=str(project)),
        dict(hook_event_name="PreToolUse", tool_name="Edit", cwd=str(project), tool_input={"file_path": str(project / "auth.py")}),
        dict(hook_event_name="PreToolUse", tool_name="Read", cwd=str(project), tool_input={"file_path": str(project / "billing.py")}),
    ]
    deny = dict(hook_event_name="PreToolUse", tool_name="Read", cwd=str(project), tool_input={"file_path": str(project / "big.py")})
    _hook(client, **deny)  # warm-up

    def timed(event) -> float:
        started = time.perf_counter()
        _hook(client, **event)
        return (time.perf_counter() - started) * 1000

    samples = [timed(decisions[i % 3]) for i in range(50)]
    assert _p95(samples) < 25, (statistics.median(samples), _p95(samples))
    skeleton = [timed(deny) for _ in range(20)]
    assert statistics.median(skeleton) < 150, skeleton  # measured 45 ms p50 on a 10-module project


# ------------------------------------------------ 2. stepcheck hooks (CLI)


def test_hooks_installer_is_idempotent_and_the_script_allows_when_offline(tmp_path, capsys):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"permissions": {"allow": ["Bash(git status)"]}, "hooks": {
        "PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "echo edited"}]}]}}, indent=2),
        encoding="utf-8")

    assert cli.main(["hooks", str(tmp_path)]) == 0
    first_settings, first_script = settings.read_bytes(), (tmp_path / ".claude" / "hooks" / "stepcheck_hook.py").read_bytes()
    assert cli.main(["hooks", str(tmp_path)]) == 0
    assert settings.read_bytes() == first_settings and (tmp_path / ".claude" / "hooks" / "stepcheck_hook.py").read_bytes() == first_script

    data = json.loads(first_settings)
    assert data["permissions"] == {"allow": ["Bash(git status)"]}  # untouched
    assert data["hooks"]["PostToolUse"][0]["hooks"][0]["command"] == "echo edited"  # untouched
    pre = [h for m in data["hooks"]["PreToolUse"] for h in m["hooks"] if "stepcheck_hook.py" in h["command"]]
    stop = [h for m in data["hooks"]["Stop"] for h in m["hooks"] if "stepcheck_hook.py" in h["command"]]
    assert len(pre) == 1 and len(stop) == 1
    assert any("Read" in m["matcher"] and "Edit" in m["matcher"] for m in data["hooks"]["PreToolUse"])
    out = capsys.readouterr().out
    assert "stepcheck_hook.py" in out and "settings.json" in out

    # The relay never blocks the agent when the gateway is down: allow + one stderr line.
    env = {**os.environ, "STEPCHECK_HOOK_URL": "http://127.0.0.1:8459/v1/step/hook", "STEPCHECK_HOOK_TIMEOUT": "1"}
    done = subprocess.run(
        [sys.executable, str(tmp_path / ".claude" / "hooks" / "stepcheck_hook.py")],
        input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "x.py"}}),
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert done.returncode == 0 and done.stdout.strip() == ""
    assert "offline" in done.stderr and done.stderr.count("\n") == 1


# -------------------------------------------- 3. stepcheck ci --report (CLI)


def test_ci_report_is_deterministic_and_carries_provenance(kernel, project, tmp_path, capsys):
    sid = kernel.init_session(project)
    assert kernel.commit(sid, "billing", patch=[{"op": "append", "code": "def _h() -> int:\n    return 1\n"}]).accepted
    v = kernel.commit(sid, "billing", patch=[{"op": "replace_symbol", "name": "refund", "code":
        "def refund(user: str, amount_cents: int, reason: str = \"\") -> dict:\n"
        "    return {\"user\": user, \"amount_cents\": -amount_cents, \"status\": \"refunded\", \"reason\": reason}\n"}])
    assert v.accepted and v.dirtied == ["reports"]
    assert kernel.commit(sid, "reports", source=(project / "reports.py").read_text(encoding="utf-8")).accepted
    envelope = kernel.provenance(sid, "billing")

    out_a, out_b = tmp_path / "a.md", tmp_path / "b.md"
    assert cli.main(["ci", str(project), "--report", "--report-out", str(out_a)]) == 0
    stdout = capsys.readouterr().out
    assert cli.main(["ci", str(project), "--report", "--report-out", str(out_b)]) == 0
    capsys.readouterr()
    assert out_a.read_bytes() == out_b.read_bytes()

    report = out_a.read_text(encoding="utf-8")
    assert "stepcheck ci: PASS" in stdout and report in stdout
    assert "## Touched modules" in report and "`billing`" in report and "`reports`" in report
    assert "re-verified" in report and "still DIRTY_OMISSION_RISK" not in report
    assert "`@require_auth`" in report and "`call:check_permission`" in report  # Gate B conserved
    assert 'call:charge(' in report and "auto-mined" in report  # Gate C executed
    assert v.attestation["payload"]["sha256"] in report
    assert "application/vnd.in-toto+json" in report and envelope["signatures"][0]["sig"] in report
    assert "can_finalize: **true**" in report


def test_ci_without_report_is_unchanged_and_report_needs_a_session(project, tmp_path, capsys):
    assert cli.main(["ci", str(project)]) == 0
    out = capsys.readouterr().out
    assert "stepcheck ci: PASS" in out and "## Touched modules" not in out
    assert cli.main(["ci", str(project), "--report"]) == 1  # no session registered for this root
    assert "no StepCheck session" in capsys.readouterr().out


# -------------------------------------------- 4. stepcheck audit --card (CLI)


def _transcript(path: Path, file_path: str, session_id: str) -> None:
    rows = [
        {"type": "user", "uuid": "u1", "sessionId": session_id, "cwd": "/x", "timestamp": "2026-10-30T09:00:00Z",
         "message": {"role": "user", "content": [{"type": "text", "text": "fix it"}]}},
        {"type": "assistant", "uuid": "u2", "sessionId": session_id, "cwd": "/x", "timestamp": "2026-10-30T09:00:40Z",
         "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": file_path}}],
                     "usage": {"input_tokens": 20, "cache_creation_input_tokens": 14200, "cache_read_input_tokens": 0, "output_tokens": 220}}},
        {"type": "user", "uuid": "u3", "sessionId": session_id, "cwd": "/x", "timestamp": "2026-10-30T09:00:43Z",
         "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
                                                    "content": "     1→def secret_fn(a: int) -> int:\n     2→    return a\n"}]}},
        {"type": "assistant", "uuid": "u4", "sessionId": session_id, "cwd": "/x", "timestamp": "2026-10-30T09:10:00Z",
         "message": {"role": "assistant", "content": [{"type": "text", "text": "done"}],
                     "usage": {"input_tokens": 15000, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 10}}},
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def test_audit_card_is_written_and_leaks_no_paths_or_ids(tmp_path, capsys):
    svg = tmp_path / "card.svg"
    assert cli.main(["audit", str(FIXTURE), "--out", str(tmp_path / "r.html"), "--card", "--card-out", str(svg)]) == 0
    out = capsys.readouterr().out
    text = svg.read_text(encoding="utf-8")
    assert text.startswith("<svg") and "cache-cliff tax" in text and "read-to-skeleton" in text
    assert "**stepcheck audit**" in out and "cache-cliff tax" in out

    secret_path = "/Users/secret-person/proj/hidden_module.py"
    secret_sid = "7c1d3b9e-aaaa-4bbb-8ccc-123456789abc"
    log = tmp_path / "t.jsonl"
    _transcript(log, secret_path, secret_sid)
    svg2 = tmp_path / "card2.svg"
    assert cli.main(["audit", str(log), "--out", str(tmp_path / "r2.html"), "--card", "--card-out", str(svg2)]) == 0
    md = capsys.readouterr().out
    card = svg2.read_text(encoding="utf-8")
    for leak in ("secret-person", "hidden_module", secret_sid, "secret_fn", str(log)):
        assert leak not in card and leak not in md.split("**stepcheck audit**", 1)[1]
    assert "1 sessions" in card or "1 session" in card
