"""Slice 6 — Diff folding & AST skeleton slicing (Seam 1 + benchmark)."""
import sys
from pathlib import Path

import yaml
from conftest import ADMIN_SRC, AUTH_SRC, BILLING_SRC

BENCH = Path(__file__).resolve().parents[2] / "benchmarks"


def _meta(project, node_id):
    text = (project / ".stepcheck" / "okf" / f"{node_id}.md").read_text(encoding="utf-8")
    return yaml.safe_load(text.split("---\n")[1])


def test_focused_checkout_serves_ast_skeleton_of_target_and_deps(kernel, project):
    sid = kernel.init_session(project)
    full = kernel.checkout(sid, "billing")
    focused = kernel.checkout(sid, "billing", focus=["charge"])
    rendered = focused.rendered()

    # Focused def travels whole, comments included (the agent must see its invariant).
    assert "def charge" in rendered
    assert "# okf-invariant:" in rendered
    assert 'raise ValueError("amount must be positive")' in rendered
    # Non-focused internals are skeletonized: signature kept, body stripped.
    assert "def _audit(user: str, action: str) -> None" in rendered
    assert 'entry["ok"] = True' not in rendered
    assert "def refund" in rendered and '"status": "refunded"' not in rendered
    # Imports survive so the agent can reference dependencies.
    assert "from auth import require_auth, check_permission" in rendered
    # Dependencies arrive as interface skeletons: decorators/signatures, no bodies.
    assert "require_auth(fn)" in rendered
    assert "hashlib.sha256" not in rendered
    assert focused.token_count < full.token_count

    pure = kernel.checkout(sid, "billing", focus=[])
    assert "def charge" in pure.rendered() and "raise PermissionError" not in pure.rendered()
    assert pure.token_count < focused.token_count


BALLAST_SRC = (
    "from auth import hash_token\n\n\n"
    "def lookup(key: str) -> str:\n"
    '    """Resolve a config key."""\n'
    "    return hash_token(key)\n\n\n"
    + "".join(f"CONFIG_ROW_{i} = '{'c' * 48}'\n" for i in range(60))
)


def test_skeleton_folds_data_ballast(kernel, project):
    (project / "config.py").write_text(BALLAST_SRC, encoding="utf-8")
    sid = kernel.init_session(project)
    full = kernel.checkout(sid, "config")
    sliced = kernel.checkout(sid, "config", focus=["lookup"])
    r = sliced.rendered()
    assert "def lookup" in r and "return hash_token(key)" in r
    assert "CONFIG_ROW_0 … CONFIG_ROW_59" in r and "cccc" not in r
    assert sliced.token_count < 0.3 * full.token_count, (sliced.token_count, full.token_count)


def test_patch_commit_folds_into_canonical_state(kernel, project):
    sid = kernel.init_session(project)
    kernel.checkout(sid, "billing", focus=[])
    v = kernel.commit(
        sid,
        "billing",
        patch=[
            {"op": "append", "code": "def _helper(x: int) -> int:\n    return x + 1\n"},
        ],
    )
    assert v.accepted, v.error
    meta = _meta(project, "billing")
    assert "def _helper" in (project / ".stepcheck" / "okf" / "billing.md").read_text(encoding="utf-8")
    assert "def charge" in (project / ".stepcheck" / "okf" / "billing.md").read_text(encoding="utf-8")
    assert meta["status"] == "VERIFIED"

    # replace_symbol swaps one top-level def (decorators included) and runs every gate:
    dropped = kernel.commit(
        sid,
        "billing",
        patch=[
            {
                "op": "replace_symbol",
                "name": "charge",
                "code": (
                    "def charge(user: str, amount_cents: int) -> dict:\n"
                    "    if amount_cents <= 0:\n"
                    '        raise ValueError("amount must be positive")\n'
                    '    if not check_permission(user, "charge"):\n'
                    "        raise PermissionError(user)\n"
                    '    return {"user": user, "amount_cents": amount_cents, "status": "charged"}\n'
                ),
            }
        ],
    )
    assert not dropped.accepted and dropped.gate == "B"  # @require_auth silently gone

    # Telemetry charges the folded patch, not the whole module.
    t = kernel.get_telemetry(sid)
    from kernel import _tokens

    assert t.compacted_okf_tokens < kernel.checkout(sid, "billing").token_count + _tokens.count(BILLING_SRC)


def test_checkout_payload_does_not_grow_with_superseded_turn_history(kernel, project):
    sid = kernel.init_session(project)
    assert kernel.commit(sid, "billing", BILLING_SRC).accepted
    before = kernel.checkout(sid, "billing", focus=[]).token_count
    for _ in range(5):
        assert kernel.commit(sid, "billing", BILLING_SRC).accepted
    after = kernel.checkout(sid, "billing", focus=[]).token_count
    assert after == before, "attestation history must fold, not accumulate, in the payload"
    assert len(_meta(project, "billing")["verified"]) == 6, "but the on-disk frame keeps the full chain"


def test_fifty_turn_benchmark_saves_at_least_85_percent():
    sys.path.insert(0, str(BENCH))
    import coding_rot_benchmark as bench

    r = bench.run()
    assert all(r["caught"].values()), r["caught"]
    assert r["final"]["savings_pct"] >= 85.0, r["final"]
