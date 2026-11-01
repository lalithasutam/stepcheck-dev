"""Slice 2 — Gate A: mechanical & locked-module invariant protection (Seam 1)."""
import textwrap

import yaml
from conftest import AUTH_SRC

from kernel import MechanicalError


def _meta(project, node_id):
    text = (project / ".stepcheck" / "okf" / f"{node_id}.md").read_text(encoding="utf-8")
    return yaml.safe_load(text.split("---\n")[1])


def test_gate_a_rejects_invalid_ast_syntax(kernel, project):
    sid = kernel.init_session(project)
    verdict = kernel.commit(sid, "billing", "def charge(user, amount_cents:\n    return {")
    assert not verdict.accepted
    assert verdict.gate == "A"
    assert isinstance(verdict.error, MechanicalError)
    assert verdict.attestation is None
    assert verdict.dirtied == []
    # Frame content unchanged, verified[] untouched.
    meta = _meta(project, "billing")
    assert meta["status"] == "REJECTED"
    assert meta["verified"] == []
    assert "def refund" in (project / ".stepcheck" / "okf" / "billing.md").read_text(encoding="utf-8")


def test_gate_a_rejects_dropping_export_required_by_dependents(kernel, project):
    sid = kernel.init_session(project)
    # reports.py imports and calls billing.charge; this source deletes charge outright.
    source = textwrap.dedent('''\
        def refund(user: str, amount_cents: int) -> dict:
            return {"user": user, "amount_cents": -amount_cents, "status": "refunded"}
        ''')
    verdict = kernel.commit(sid, "billing", source, allow_deletion=True)
    assert not verdict.accepted
    assert verdict.gate == "A"
    assert isinstance(verdict.error, MechanicalError)
    assert "charge" in str(verdict.error)
    assert "reports" in str(verdict.error)


def test_gate_a_rejects_any_mutation_of_locked_module(kernel, project):
    sid = kernel.init_session(project)
    baseline = kernel.commit(sid, "auth", AUTH_SRC)
    assert baseline.accepted, f"baseline commit must pass all gates: {baseline.error}"
    kernel.lock_node(sid, "auth")
    assert _meta(project, "auth")["locked"] is True
    assert len(_meta(project, "auth")["verified"]) == 1

    verdict = kernel.commit(sid, "auth", AUTH_SRC.replace('"forbidden"', '"banned"'))
    assert not verdict.accepted
    assert verdict.gate == "A"
    assert isinstance(verdict.error, MechanicalError)
    assert "LOCKED" in str(verdict.error)

    meta = _meta(project, "auth")
    assert meta["locked"] is True
    assert meta["status"] == "LOCKED"
    assert len(meta["verified"]) == 1, "verified[] must stay untouched on rejection"
    assert '"banned"' not in (project / ".stepcheck" / "okf" / "auth.md").read_text(encoding="utf-8")
