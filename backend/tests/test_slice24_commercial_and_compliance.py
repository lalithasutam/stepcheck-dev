"""Slice 24 — the commercial surface: a 1-click GitHub Action (`action.yml`),
opt-in four-tier licensing on the DualDoorGateway and the team-grade CLI
commands, the multi-session team FinOps & governance ledger
(`GET /v1/team/summary`), and the dual-use compliance exporter
(`StateKernel.compliance_bundle`, `stepcheck compliance`). Seam 1, Seam 2
through the real ASGI app, and `cli.main`; zero mocks."""
import base64
import hashlib
import json
import shutil
import statistics
import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

import cli
from conftest import BILLING_SRC  # noqa: F401  (fixture module; keeps the project fixture importable)
from kernel import StateKernel  # noqa: F401

try:  # the modules this slice adds; absent on the unpatched tree, so every test below fails Red
    import licensing
    import pricing
except ImportError:  # pragma: no cover - Red state only
    licensing = pricing = None

REPO = Path(__file__).resolve().parents[2]
SECRET = "slice24-test-secret"


@pytest.fixture()
def client(project):
    import server

    with TestClient(server.app) as c:
        yield c


def _init(client, project) -> str:
    r = client.post("/v1/step/init", json={"project_root": str(project)})
    assert r.status_code == 200, r.text
    return r.json()["session_id"]


def _replace(name: str, code: str) -> list[dict]:
    return [{"op": "replace_symbol", "name": name, "code": code}]


SIGNATURE_CHANGE = _replace(
    "charge",
    "@require_auth\ndef charge(user: str, amount_cents: int, currency: str = \"usd\") -> dict:\n"
    '    # okf-invariant: "amount_cents <= 0" in src and "raise ValueError" in src\n'
    "    if amount_cents <= 0:\n        raise ValueError(\"amount must be positive\")\n"
    "    if not check_permission(user, \"charge\"):\n        raise PermissionError(user)\n"
    '    return {"user": user, "amount_cents": amount_cents, "status": "charged", "currency": currency}\n',
)
DROP_DECORATOR = _replace(
    "charge",
    "def charge(user: str, amount_cents: int) -> dict:\n"
    "    if amount_cents <= 0:\n        raise ValueError(\"amount must be positive\")\n"
    "    if not check_permission(user, \"charge\"):\n        raise PermissionError(user)\n"
    '    return {"user": user, "amount_cents": amount_cents, "status": "charged"}\n',
)


def _door1(client, sid: str, step: list[dict] | None = None, **headers) -> dict:
    msgs = [{"role": "user", "content": "Harden charge()."}]
    if step is not None:
        msgs.append({"role": "assistant", "content": "Applying:\n```stepcheck-patch\n" + json.dumps(step) + "\n```"})
    msgs.append({"role": "user", "content": "Verify."})
    r = client.post("/v1/messages", json={"model": "claude-sonnet-4-5", "max_tokens": 64, "messages": msgs},
                    headers={"x-stepcheck-session": sid, "x-stepcheck-node": "billing", **headers})
    return r


# ------------------------------------------------------------- 1. action.yml


def test_action_yml_is_a_composite_action_running_the_gate_with_a_report():
    spec = yaml.safe_load((REPO / "action.yml").read_text(encoding="utf-8"))
    assert spec["runs"]["using"] == "composite"
    inputs = spec["inputs"]
    assert inputs["path"]["default"] == "." and inputs["python-version"]["default"] == "3.12"
    assert inputs["report-path"]["default"] == "stepcheck-report.md" and inputs["fail-on-dirty"]["default"] == "true"
    steps = spec["runs"]["steps"]
    uses = [s.get("uses", "") for s in steps]
    assert any(u.startswith("actions/setup-python@") for u in uses)
    assert any(u.startswith("actions/upload-artifact@") for u in uses)
    runs = "\n".join(s.get("run", "") for s in steps)
    assert 'pip install --quiet "stepcheck-dev${{ inputs.version }}"' in runs and inputs["version"]["default"] == ">=0.2.0"
    assert 'stepcheck ci "$STEPCHECK_PATH" --report --report-out "$STEPCHECK_REPORT"' in runs
    assert '>> "$GITHUB_STEP_SUMMARY"' in runs and 'exit "$status"' in runs
    assert spec["outputs"]["verdict"]["value"] == "${{ steps.gate.outputs.verdict }}"


def test_the_action_command_sequence_works_locally_and_fails_closed_on_dirty(kernel, project, tmp_path, capsys):
    sid = kernel.init_session(project)
    assert kernel.commit(sid, "billing", patch=[{"op": "append", "code": "LIMIT = 1\n"}]).accepted
    report = tmp_path / "stepcheck-report.md"

    rc = cli.main(["ci", str(project), "--report", "--report-out", str(report)])
    out = capsys.readouterr().out
    assert rc == 0 and "stepcheck ci: PASS" in out
    text = report.read_text(encoding="utf-8")
    assert text.startswith("# StepCheck decision-provenance report") and "can_finalize: **true**" in text

    v = kernel.commit(sid, "billing", patch=SIGNATURE_CHANGE)
    assert v.accepted and v.dirtied == ["reports"]
    rc = cli.main(["ci", str(project), "--report", "--report-out", str(report)])
    out = capsys.readouterr().out
    assert rc == 1 and "DIRTY_OMISSION_RISK" in out  # fail closed ...
    assert "can_finalize: **false**" in report.read_text(encoding="utf-8")  # ... and the PR still gets the report


# ---------------------------------------------------- 2. four-tier licensing


def test_tier_table_matches_the_product_architecture():
    assert pricing.TIER_ORDER == ["free", "pro", "team", "enterprise"]
    assert pricing.TIERS["free"]["usd_per_month"] == 0 and pricing.TIERS["free"]["license"] == "Apache-2.0"
    assert pricing.TIERS["pro"]["usd_per_month"] == 19 and pricing.TIERS["pro"]["savings_share"] == 0.15
    assert pricing.TIERS["team"]["usd_per_seat_month"] == 39
    assert pricing.TIERS["enterprise"]["usd_per_seat_month"] == 79 and pricing.TIERS["enterprise"]["usd_per_year_self_hosted"] == 25000
    assert pricing.tier_for_capability("door1_accordion") == "pro"
    assert pricing.tier_for_capability("team_summary") == "team" and pricing.tier_for_capability("ci_report") == "team"
    assert pricing.tier_for_capability("compliance_bundle") == "enterprise"
    assert pricing.tier_for_capability("hooks") == "free"


def test_without_enforcement_every_door_is_open(client, project, monkeypatch):
    monkeypatch.delenv("STEPCHECK_REQUIRE_KEY", raising=False)
    sid = _init(client, project)
    assert _door1(client, sid).status_code == 200
    assert client.get("/v1/team/summary").status_code == 200
    assert licensing.check("compliance_bundle", None) is None


def test_enforcement_gates_each_tier_with_402_and_prices(client, project, monkeypatch):
    monkeypatch.setenv("STEPCHECK_REQUIRE_KEY", "1")
    monkeypatch.setenv("STEPCHECK_LICENSE_SECRET", SECRET)
    sid = _init(client, project)  # Door 2 stays free
    pro = licensing.issue_key("pro", SECRET, seed="alice")
    team = licensing.issue_key("team", SECRET, seed="acme")
    forged = pro[:-1] + ("0" if pro[-1] != "0" else "1")
    assert licensing.verify_key(pro, SECRET) == "pro" and licensing.verify_key(forged, SECRET) is None
    assert pro.startswith("sk-pro-") and licensing.issue_key("pro", SECRET, seed="alice") == pro

    denied = _door1(client, sid)
    assert denied.status_code == 402
    body = denied.json()
    assert body["required_tier"] == "pro" and body["price"]["usd_per_month"] == pricing.TIERS["pro"]["usd_per_month"]
    assert body["held_tier"] == "free" and body["capability"] == "door1_accordion"
    assert _door1(client, sid, **{"x-stepcheck-key": forged}).status_code == 402
    assert _door1(client, sid, **{"x-stepcheck-key": pro}).status_code == 200

    summary = client.get("/v1/team/summary", headers={"x-stepcheck-key": pro})
    assert summary.status_code == 402 and summary.json()["required_tier"] == "team"
    assert summary.json()["price"]["usd_per_seat_month"] == pricing.TIERS["team"]["usd_per_seat_month"]
    ok = client.get("/v1/team/summary", headers={"x-stepcheck-key": team})
    assert ok.status_code == 200 and ok.json()["tier"]["tier"] == "team" and ok.json()["tier"]["enforcement"] is True

    # hooks stay free even under enforcement
    hook = client.post("/v1/step/hook", json={"hook_event_name": "Stop", "cwd": str(project)})
    assert hook.status_code == 200


def test_cli_report_and_compliance_honour_enforcement_from_the_environment(kernel, project, tmp_path, monkeypatch, capsys):
    sid = kernel.init_session(project)
    assert kernel.commit(sid, "billing", patch=[{"op": "append", "code": "LIMIT = 1\n"}]).accepted
    monkeypatch.setenv("STEPCHECK_REQUIRE_KEY", "1")
    monkeypatch.setenv("STEPCHECK_LICENSE_SECRET", SECRET)
    monkeypatch.setenv("STEPCHECK_LICENSE_KEY", licensing.issue_key("pro", SECRET))

    assert cli.main(["ci", str(project), "--report"]) == 3
    assert "team" in capsys.readouterr().err
    assert cli.main(["compliance", str(project), "--out", str(tmp_path / "c")]) == 3
    assert "enterprise" in capsys.readouterr().err
    assert cli.main(["ci", str(project)]) == 0  # the plain gate is free

    monkeypatch.setenv("STEPCHECK_LICENSE_KEY", licensing.issue_key("enterprise", SECRET))
    assert cli.main(["ci", str(project), "--report"]) == 0
    assert cli.main(["compliance", str(project), "--out", str(tmp_path / "c")]) == 0
    assert (tmp_path / "c" / "DUC.json").exists() and (tmp_path / "c" / "DUA-E.json").exists()


# ------------------------------------------------- 3. GET /v1/team/summary


def test_team_summary_aggregates_sessions_events_and_arbitrage(client, project, tmp_path_factory):
    second = tmp_path_factory.mktemp("second") / "proj"  # a sibling project, not a subtree of the first
    shutil.copytree(project, second, ignore=shutil.ignore_patterns(".stepcheck"))
    sid1, sid2 = _init(client, project), _init(client, second)

    # session 1: a Gate B rejection, a signature change that dirties `reports`, then its re-verification
    r = client.post("/v1/step/commit", json={"session_id": sid1, "node_id": "billing", "patch": DROP_DECORATOR})
    assert r.status_code == 200 and r.json()["accepted"] is False and r.json()["gate"] == "B"
    r = client.post("/v1/step/commit", json={"session_id": sid1, "node_id": "billing", "patch": SIGNATURE_CHANGE})
    assert r.json()["accepted"] is True and r.json()["dirtied"] == ["reports"]
    r = client.post("/v1/step/commit", json={"session_id": sid1, "node_id": "reports",
                                             "patch": [{"op": "append", "code": "LIMIT = 1\n"}]})
    assert r.json()["accepted"] is True
    # session 2: a focused single-symbol turn routed to the fast tier through Door 1
    fast = _door1(client, sid2, step=_replace("refund", "def refund(user: str, amount_cents: int) -> dict:\n"
                                                        '    return {"user": user, "amount_cents": -amount_cents, "status": "refunded", "v": 2}\n'),
                  **{"x-stepcheck-tier": "auto"})
    assert fast.status_code == 200
    fw = fast.json()["stepcheck"]
    assert fw["routing"]["tier"] == "fast" and fw["commit"]["accepted"] is True

    s = client.get("/v1/team/summary").json()
    assert s["sessions"] == 2 and sorted(s["session_ids"]) == sorted([sid1, sid2])
    assert s["gates"]["regressions_caught"]["B"] == 1 and s["gates"]["commits_accepted"] == 3
    assert s["gates"]["omissions_blocked"] == 1
    assert s["omission_risk"] == {"flags_raised": 1, "re_verified": 1, "still_dirty": 0}
    assert s["door1"]["turns"] == 1 and s["door1"]["tokens_before"] > 0  # a 3-message turn has nothing to compact
    assert s["arbitrage"]["fast_turns"] == 1 and s["arbitrage"]["escalations"] == 0
    expected = (pricing.price_for_model("claude-sonnet-4-5") - pricing.price_for_model("claude-haiku-4-5")) * fw["sent_tokens"] / 1e6
    assert s["arbitrage"]["usd_saved"] == pytest.approx(expected, abs=1e-6) and expected > 0
    assert s["tokens"]["compacted"] > 0 and s["tokens"]["turns"] > 0  # a 5-module fixture payload can exceed its raw read
    assert s["tier"] == {"enforcement": False, "tier": "free", "label": pricing.TIERS["free"]["label"],
                         "capabilities": pricing.TIERS["free"]["capabilities"], "price": pricing.tier_price("free")}
    assert client.get("/v1/team/summary").json() == s  # deterministic for a given state
    only_second = client.get("/v1/team/summary", params={"project_root": str(second)}).json()
    assert only_second["sessions"] == 1 and only_second["session_ids"] == [sid2]


# ----------------------------------------------- 4. compliance bundles


def _merkle(leaves: list[str]) -> str:
    level = sorted(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256((level[i] + level[i + 1]).encode()).hexdigest() for i in range(0, len(level), 2)]
    return level[0]


def test_compliance_bundle_is_a_public_card_plus_an_escrowed_ledger(kernel, project):
    sid = kernel.init_session(project)
    kernel.lock_node(sid, "auth")
    assert kernel.commit(sid, "billing", patch=[{"op": "append", "code": "LIMIT = 1\n"}]).accepted
    assert not kernel.commit(sid, "billing", patch=DROP_DECORATOR).accepted
    assert kernel.commit(sid, "reports", patch=[{"op": "append", "code": "LIMIT = 2\n"}]).accepted

    bundle = kernel.compliance_bundle(sid)
    duc, dua = bundle["DUC"], bundle["DUA-E"]
    assert duc["_type"].startswith("https://") and dua["_type"].startswith("https://")
    assert duc["files"] == 5 and duc["languages"] == {"python": 5}
    assert duc["gates"] == {"commits_accepted": 2, "rejections": {"A": 0, "B": 1, "C": 0}, "locked_modules": 1, "dirty_omission_risk": 0}
    assert duc["invariants"]["total"] >= 1 and duc["attestations"]["count"] == 2
    assert duc["leak_check"]["paths"] == 0 and duc["leak_check"]["code"] == 0
    card = json.dumps(duc)
    for forbidden in ("billing", "auth.py", "reports", "def ", "class ", str(project)):
        assert forbidden not in card
    assert duc["session_digest"] == hashlib.sha256(sid.encode()).hexdigest()
    assert "OWASP_AISVS_1.0:C9.3" in duc["controls"] and "PCI_DSS_4.0:6.3.2" in duc["controls"]

    envelopes = [e["envelope"] for e in dua["envelopes"]]
    assert len(envelopes) == 2 and all(e["payloadType"] == "application/vnd.in-toto+json" for e in envelopes)
    leaves = []
    for env in envelopes:
        statement = json.loads(base64.b64decode(env["payload"]))
        assert statement["_type"] == "https://in-toto.io/Statement/v1"
        [subject] = statement["subject"]
        on_disk = hashlib.sha256((project / subject["name"]).read_bytes()).hexdigest()
        assert subject["digest"]["sha256"] == on_disk
        leaves.append(on_disk)
    assert dua["merkle"]["root"] == duc["attestations"]["merkle_root"] == _merkle(leaves)
    assert dua["duc_digest"] == hashlib.sha256(json.dumps(duc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    controls = dua["controls"]
    assert set(controls) == {"OWASP_AISVS_1.0:C9.3", "SOC2_TypeII:CC8.1", "PCI_DSS_4.0:6.3.2", "EU_AI_Act:Art.12"}
    assert controls["OWASP_AISVS_1.0:C9.3"]["control_text"] and controls["PCI_DSS_4.0:6.3.2"]["control_text"] is None
    assert controls["OWASP_AISVS_1.0:C9.3"]["evidence_present"]["gate_a_locked_modules"] is True
    assert kernel.compliance_bundle(project) == bundle  # a project root resolves to its newest session
    with pytest.raises(KeyError):
        kernel.compliance_bundle("sk-000000000000")


def test_stepcheck_compliance_writes_both_files_deterministically(kernel, project, tmp_path, capsys):
    sid = kernel.init_session(project)
    assert kernel.commit(sid, "billing", patch=[{"op": "append", "code": "LIMIT = 1\n"}]).accepted
    out_a, out_b = tmp_path / "a", tmp_path / "b"
    assert cli.main(["compliance", str(project), "--out", str(out_a)]) == 0
    printed = capsys.readouterr().out
    assert "DUC.json" in printed and "DUA-E.json" in printed and "merkle" in printed.lower()
    assert cli.main(["compliance", str(project), "--out", str(out_b)]) == 0
    for name in ("DUC.json", "DUA-E.json"):
        assert (out_a / name).read_bytes() == (out_b / name).read_bytes()
    duc = json.loads((out_a / "DUC.json").read_text(encoding="utf-8"))
    assert duc["leak_check"] == {"paths": 0, "code": 0, "method": duc["leak_check"]["method"]}
    assert cli.main(["compliance", str(tmp_path / "nowhere"), "--out", str(tmp_path / "c")]) == 1


def test_leak_check_matches_whole_names_and_ignores_the_cards_own_labels(kernel, project):
    """Regression: a repo with `types.ts` tripped the public card's leak check because the
    stem `types` is a substring of the card's own `typescript` language label. Tracked
    names are matched as whole tokens, and a file whose stem equals a schema key or a
    language label the card always emits is not a leak."""
    (project / "types.ts").write_text("export interface User { id: string }\n", encoding="utf-8", newline="\n")
    (project / "python.py").write_text("LIMIT = 1\n", encoding="utf-8", newline="\n")
    sid = kernel.init_session(project)
    assert kernel.commit(sid, "billing", patch=[{"op": "append", "code": "LIMIT = 1\n"}]).accepted

    duc = kernel.compliance_bundle(sid)["DUC"]
    assert duc["languages"] == {"python": 6, "typescript": 1}
    assert duc["leak_check"]["paths"] == 0 and duc["leak_check"]["code"] == 0
    card = json.dumps(duc)
    for forbidden in ("types.ts", "python.py", "billing", str(project)):
        assert forbidden not in card


# ------------------------------------------------- 5. latency of the ledger


def test_team_summary_and_hook_stay_fast_under_enforcement(client, project, monkeypatch):
    monkeypatch.setenv("STEPCHECK_REQUIRE_KEY", "1")
    monkeypatch.setenv("STEPCHECK_LICENSE_SECRET", SECRET)
    sid = _init(client, project)
    key = licensing.issue_key("team", SECRET)
    client.get("/v1/team/summary", headers={"x-stepcheck-key": key})
    summary_ms, hook_ms = [], []
    for _ in range(50):
        t0 = time.perf_counter()
        assert client.get("/v1/team/summary", headers={"x-stepcheck-key": key}).status_code == 200
        summary_ms.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter()
        assert client.post("/v1/step/hook", json={"hook_event_name": "Stop", "cwd": str(project)}).status_code == 200
        hook_ms.append((time.perf_counter() - t0) * 1000)
    assert statistics.median(summary_ms) < 150 and statistics.median(hook_ms) < 50, (summary_ms, hook_ms)
    assert sid in client.get("/v1/team/summary", headers={"x-stepcheck-key": key}).json()["session_ids"]
