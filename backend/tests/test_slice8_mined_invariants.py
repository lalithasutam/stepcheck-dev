"""Slice 8 — zero-config guard invariants mined from leading `if …: raise …` clauses (Seam 1)."""
import textwrap

import yaml

from kernel import LogicalError

# No `# okf-invariant:` anywhere. The guards themselves are the spec.
LEDGER_SRC = textwrap.dedent('''\
    def post(account: str, amount_cents: int, memo: str = "") -> dict:
        """Post a signed amount to an account."""
        if amount_cents <= 0:
            raise ValueError("amount must be positive")
        if not account:
            raise KeyError("account required")
        return {"account": account, "amount_cents": amount_cents, "memo": memo}


    def close(account: str) -> bool:
        if account is None:
            raise TypeError("account must be a str")
        return True


    def reconcile(entries: list) -> int:
        total = 0
        if len(entries) == 0:
            raise ValueError("nothing to reconcile")  # not leading: after an assignment
        return total
    ''')

GUARD_REMOVED = LEDGER_SRC.replace(
    '    if amount_cents <= 0:\n        raise ValueError("amount must be positive")\n',
    "    if amount_cents == 0:\n        amount_cents = 1\n",
)


def _meta(project, node_id):
    text = (project / ".stepcheck" / "okf" / f"{node_id}.md").read_text(encoding="utf-8")
    return yaml.safe_load(text.split("---\n")[1])


def test_init_session_mines_guard_invariants_without_annotations(kernel, tmp_path):
    (tmp_path / "ledger.py").write_text(LEDGER_SRC, encoding="utf-8")
    sid = kernel.init_session(tmp_path)
    meta = _meta(tmp_path, "ledger")

    mined = meta["invariants_auto_mined"]
    assert 'call:post(account="x", amount_cents=0) raises ValueError' in mined
    assert 'call:post(account="", amount_cents=1) raises KeyError' in mined
    assert "call:close(account=None) raises TypeError" in mined
    # Only *leading* guards are mined; reconcile's check follows an assignment.
    assert not any(inv.startswith("call:reconcile") for inv in mined)
    # Mined invariants are live invariants, and they ride along in the payload.
    assert set(mined) <= set(meta["invariants"])
    payload = kernel.checkout(sid, "ledger", focus=[])
    assert 'call:post(account="x", amount_cents=0) raises ValueError' in payload.rendered()


def test_gate_c_rejects_patch_that_removes_a_mined_guard(kernel, tmp_path):
    (tmp_path / "ledger.py").write_text(LEDGER_SRC, encoding="utf-8")
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(sid, "ledger", GUARD_REMOVED)
    assert not v.accepted and v.gate == "C"
    assert isinstance(v.error, LogicalError)
    assert 'call:post(account="x", amount_cents=0) raises ValueError' in str(v.error)
    assert "auto-mined" in str(v.error)

    # A declared deletion waives mined guards (never hand-written ones).
    waived = kernel.commit(sid, "ledger", GUARD_REMOVED, allow_deletion=True)
    assert waived.accepted, waived.error
    # And the guard set is re-mined from the new canonical source.
    assert not any(
        "amount_cents=0" in inv for inv in _meta(tmp_path, "ledger")["invariants_auto_mined"]
    )


def test_manual_annotations_dedupe_and_outrank_mined(kernel, tmp_path):
    annotated = LEDGER_SRC.replace(
        '    """Post a signed amount to an account."""\n',
        '    """Post a signed amount to an account."""\n'
        '    # okf-invariant: call:post(account="x", amount_cents=0) raises ValueError\n',
    )
    (tmp_path / "ledger.py").write_text(annotated, encoding="utf-8")
    kernel.init_session(tmp_path)
    meta = _meta(tmp_path, "ledger")
    assert meta["invariants"].count('call:post(account="x", amount_cents=0) raises ValueError') == 1
    assert meta["invariants"][0] == 'call:post(account="x", amount_cents=0) raises ValueError'
