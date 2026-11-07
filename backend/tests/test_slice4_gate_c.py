"""Slice 4 — Gate C: logical micro-invariants, DSSE attestation, telemetry (Seam 1)."""
import hashlib

import pytest
import yaml
from conftest import BILLING_SRC

from kernel import LogicalError

# ------------------------------------------------------------ (a) invariants

# Removes the positive-amount guard AND its okf-invariant comment. Statement
# count is unchanged (if+raise -> if+assign), every preserved symbol survives,
# so Gates A and B pass — only the standing frame invariant catches it.
GUARD_REMOVED = BILLING_SRC.replace(
    '    # okf-invariant: "amount_cents <= 0" in src and "raise ValueError" in src\n'
    "    if amount_cents <= 0:\n"
    '        raise ValueError("amount must be positive")\n',
    "    if amount_cents == 0:\n"
    "        amount_cents = 1\n",
)


def _meta(project, node_id):
    text = (project / ".stepcheck" / "okf" / f"{node_id}.md").read_text(encoding="utf-8")
    return yaml.safe_load(text.split("---\n")[1])


def test_gate_c_rejects_diff_violating_frame_invariant(kernel, project):
    assert "raise ValueError" not in GUARD_REMOVED  # fixture sanity, not a mock
    sid = kernel.init_session(project)
    verdict = kernel.commit(sid, "billing", GUARD_REMOVED)

    assert not verdict.accepted
    assert verdict.gate == "C"
    assert isinstance(verdict.error, LogicalError)
    assert "amount_cents <= 0" in str(verdict.error)

    meta = _meta(project, "billing")
    assert meta["status"] == "REJECTED"
    assert meta["verified"] == [], "verified[] must stay untouched on rejection"
    assert "raise ValueError" in (
        project / ".stepcheck" / "okf" / "billing.md"
    ).read_text(encoding="utf-8"), "frame source must be the last good version, not the rejected diff"


# --------------------------------------------- (b) DSSE envelope + draft GC


def test_passing_commit_appends_deterministic_dsse_envelope(kernel, project):
    sid = kernel.init_session(project)
    kernel.record_draft(sid, "billing", "turn 1: let me explore billing.py ...")
    kernel.record_draft(sid, "billing", "turn 2: dead-end attempt, rewriting ...")
    kernel.record_draft(sid, "admin", "turn 3: unrelated admin scratch")

    verdict = kernel.commit(sid, "billing", BILLING_SRC)
    assert verdict.accepted, f"baseline source must pass all gates: {verdict.error}"

    env = verdict.attestation
    assert env["payloadType"] == "application/vnd.stepcheck.okf-commit+json"
    assert env["payload"]["node_id"] == "billing"
    assert env["payload"]["sha256"] == hashlib.sha256(BILLING_SRC.encode()).hexdigest()
    sig = env["signatures"][0]
    assert sig["keyid"] == "stepcheck-deterministic-v1"
    assert len(sig["sig"]) == 64 and int(sig["sig"], 16) >= 0  # hex SHA-256

    # Envelope lands in the frame's verified[].
    assert _meta(project, "billing")["verified"] == [env]

    # Accepted commit garbage-collects that node's dead-end drafts only.
    remaining = kernel.drafts(sid)
    assert [d["node_id"] for d in remaining] == ["admin"]


def test_attestation_is_deterministic_across_sessions(kernel, project, tmp_path_factory):
    sid1 = kernel.init_session(project)
    env1 = kernel.commit(sid1, "billing", BILLING_SRC).attestation

    other_root = tmp_path_factory.mktemp("replay")
    for f in ("auth.py", "admin.py", "billing.py", "reports.py", "unrelated_sibling.py"):
        (other_root / f).write_bytes((project / f).read_bytes())
    from kernel import StateKernel

    sid2 = StateKernel().init_session(other_root)
    env2 = kernel.__class__().init_session  # noqa: B018 — guard against accidental reuse
    env2 = StateKernel()
    s2 = env2.init_session(other_root)
    assert env2.commit(s2, "billing", BILLING_SRC).attestation == env1


# --------------------------------------------------------- (c) telemetry math


def _padded_module(fn_name: str, total_len: int) -> str:
    base = f"def {fn_name}() -> int:\n    return 1\n"
    pad = total_len - len(base)
    assert pad >= 4
    return base + "# " + "x" * (pad - 3) + "\n"


def test_get_telemetry_matches_hand_calculated_literal_example(kernel, tmp_path):
    # a.py is exactly 800 chars -> ceil(800/4) = 200 full-read tokens.
    # b.py is exactly 400 chars -> 100 full-read tokens.
    a_src = _padded_module("fa", 800)
    b_src = _padded_module("fb", 400)
    assert len(a_src) == 800 and len(b_src) == 400
    (tmp_path / "a.py").write_text(a_src, encoding="utf-8")
    (tmp_path / "b.py").write_text(b_src, encoding="utf-8")

    sid = kernel.init_session(tmp_path)
    p_a = kernel.checkout(sid, "a", at=0.0)          # turn 1
    assert kernel.commit(sid, "a", a_src, at=100.0).accepted   # write path: no turn
    p_b = kernel.checkout(sid, "b", at=200.0)        # turn 2
    p_a2 = kernel.checkout(sid, "a", at=600.0)       # turn 3
    assert kernel.commit(sid, "b", b_src, at=650.0).accepted   # write path: no turn

    t = kernel.get_telemetry(sid)

    # Only the read path is context (Slice 28): a turn is a checkout. The raw
    # (unfirewalled) agent re-reads every file read so far on each turn; a
    # re-read more than 300s after the last one bills full rate, else 10%:
    #   turn 1 (t=0):   a never read                              = 200
    #   turn 2 (t=200): a gap 200 <= 300 -> 20;  b never -> 100   = 120
    #   turn 3 (t=600): a gap 400 > 300 -> 200;  b gap 400 -> 100 = 300
    assert t.turns == 3
    assert t.raw_bloated_tokens == 200 + 120 + 300 == 620

    compacted = p_a.token_count + p_b.token_count + p_a2.token_count  # frames returned, nothing else
    assert t.compacted_okf_tokens == compacted
    assert t.tokens_saved == 620 - compacted
    # $3.00 per million input tokens (kernel/_telemetry.py owns the constant).
    assert t.dollars_saved == pytest.approx((620 - compacted) * 3.00 / 1_000_000)
    assert t.turns == 3
    assert t.omissions_blocked == 0


def test_telemetry_counts_blocked_omissions(kernel, project):
    sid = kernel.init_session(project)
    bad = BILLING_SRC.replace("@require_auth\n", "")
    assert not kernel.commit(sid, "billing", bad).accepted
    assert kernel.get_telemetry(sid).omissions_blocked == 1
