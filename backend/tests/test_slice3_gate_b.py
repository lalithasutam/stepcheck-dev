"""Slice 3 — Gate B: intra-node & inter-node omission error detection (Seam 1)."""
import pytest
import yaml
from conftest import ADMIN_SRC, AUTH_SRC, BILLING_SRC

from kernel import OmissionError


def _status(project, node_id):
    text = (project / ".stepcheck" / "okf" / f"{node_id}.md").read_text(encoding="utf-8")
    return yaml.safe_load(text.split("---\n")[1])["status"]


# ---------------------------------------------------------------- intra-node

SILENT_DECORATOR_DROP = BILLING_SRC.replace("@require_auth\n", "")

MASS_DELETION = BILLING_SRC.replace(
    '_FEES = {"standard": 30, "intl": 50}\n\n\n'
    "def _audit(user: str, action: str) -> None:\n"
    '    entry = {"user": user, "action": action}\n'
    '    entry["ok"] = True\n'
    "    print(entry)\n",
    "",
)


def test_intra_node_rejects_silently_dropped_preserved_decorator(kernel, project):
    sid = kernel.init_session(project)
    verdict = kernel.commit(sid, "billing", SILENT_DECORATOR_DROP)
    assert not verdict.accepted
    assert verdict.gate == "B"
    assert isinstance(verdict.error, OmissionError)
    assert verdict.error.subtype == "INTRA_NODE_SYMBOL_DROPPED"
    assert "@require_auth" in str(verdict.error)
    assert _status(project, "billing") == "REJECTED"


def test_intra_node_rejects_mass_statement_deletion_without_flag(kernel, project):
    sid = kernel.init_session(project)
    verdict = kernel.commit(sid, "billing", MASS_DELETION)
    assert not verdict.accepted
    assert verdict.gate == "B"
    assert isinstance(verdict.error, OmissionError)
    assert verdict.error.subtype == "INTRA_NODE_MASS_DELETION"

    # The identical deletion is legal when declared.
    allowed = kernel.commit(sid, "billing", MASS_DELETION, allow_deletion=True)
    assert allowed.accepted, f"declared deletion must pass: {allowed.error}"


# ---------------------------------------------------------------- inter-node

SIGNATURE_CHANGE = AUTH_SRC.replace(
    "def check_permission(user: str, action: str) -> bool:",
    'def check_permission(user: str, action: str, scope: str = "any") -> bool:',
)


def test_inter_node_dirty_propagation_blocks_finalization(kernel, project):
    sid = kernel.init_session(project)

    verdict = kernel.commit(sid, "auth", SIGNATURE_CHANGE)
    assert verdict.accepted, f"name is intact, Gate A must pass: {verdict.error}"
    assert verdict.dirtied == ["admin", "billing"], "both direct dependents dirty"

    assert _status(project, "admin") == "DIRTY_OMISSION_RISK"
    assert _status(project, "billing") == "DIRTY_OMISSION_RISK"
    assert _status(project, "reports") == "ACTIVE", "non-dependent must stay clean"

    with pytest.raises(OmissionError) as exc:
        kernel.finalize_session(sid)
    assert exc.value.subtype == "INTER_NODE_DIRTY"

    # Re-verify billing only — finalization must still be blocked by admin.
    kernel.checkout(sid, "billing")
    assert kernel.commit(sid, "billing", BILLING_SRC).accepted
    with pytest.raises(OmissionError):
        kernel.finalize_session(sid)

    # Re-verify admin — finalization unblocks.
    kernel.checkout(sid, "admin")
    assert kernel.commit(sid, "admin", ADMIN_SRC).accepted
    assert kernel.finalize_session(sid) is True
    assert _status(project, "billing") == "VERIFIED"
    assert _status(project, "admin") == "VERIFIED"
