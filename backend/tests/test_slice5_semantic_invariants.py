"""Slice 5 — Gate C semantic micro-invariants: normalized `src`, `tree`, `ns` (Seam 1)."""
import textwrap

from conftest import AUTH_SRC

from kernel import LogicalError

# billing.py v2: semantic invariants on the guard — AST over `tree`, callable
# over the loaded `ns`. (The legacy string flavour lives in conftest's billing.)
BILLING_V2 = textwrap.dedent('''\
    from auth import require_auth, check_permission


    @require_auth
    def charge(user: str, amount_cents: int) -> dict:
        # okf-invariant: any(isinstance(n, ast.Raise) for n in ast.walk(tree))
        # okf-invariant: call:charge("u", 0) raises ValueError
        if amount_cents <= 0:
            raise ValueError("amount must be positive")
        if not check_permission(user, "charge"):
            raise PermissionError(user)
        return {"user": user, "amount_cents": amount_cents, "status": "charged"}
    ''')

GUARD = (
    "    if amount_cents <= 0:\n"
    '        raise ValueError("amount must be positive")\n'
)

# Same semantics, different surface — must all pass.
TIGHT_WHITESPACE = BILLING_V2.replace(GUARD, "    if amount_cents<=0:\n        raise ValueError('amount must be positive')\n")
NEGATED_FORM = BILLING_V2.replace(GUARD, "    if not (amount_cents > 0):\n        raise ValueError(\"amount must be positive\")\n")

# Still has `raise ValueError` text and a Raise node, but charge(…, 0) now returns 0.
RETURNS_ZERO = BILLING_V2.replace(
    GUARD,
    "    if amount_cents <= 0:\n"
    "        return 0\n"
    "    if amount_cents > 10_000_000:\n"
    '        raise ValueError("amount too large")\n',
)


def _project(tmp_path):
    (tmp_path / "auth.py").write_text(AUTH_SRC, encoding="utf-8")
    (tmp_path / "billing.py").write_text(BILLING_V2, encoding="utf-8")
    return tmp_path


def test_normalized_src_accepts_whitespace_variants(kernel, project):
    # conftest billing carries the legacy string invariant "amount_cents <= 0" in src;
    # before normalization, tight whitespace in the agent's edit was a false rejection.
    from conftest import BILLING_SRC

    sid = kernel.init_session(project)
    tight = BILLING_SRC.replace(GUARD, "    if amount_cents<=0:\n        raise ValueError('amount must be positive')\n")
    assert "amount_cents<=0" in tight
    v = kernel.commit(sid, "billing", tight)
    assert v.accepted, f"whitespace must never fail a string invariant: {v.error}"


def test_semantic_invariants_accept_equivalent_forms(kernel, tmp_path):
    sid = kernel.init_session(_project(tmp_path))
    for variant in (TIGHT_WHITESPACE, NEGATED_FORM):
        v = kernel.commit(sid, "billing", variant)
        assert v.accepted, f"semantically intact guard must pass Gate C: {v.error}"
        # The commit was folded into canonical state; the next payload shows it.
        assert "ValueError" in kernel.checkout(sid, "billing").frame_markdown


def test_callable_invariant_rejects_guard_that_no_longer_raises(kernel, tmp_path):
    sid = kernel.init_session(_project(tmp_path))
    assert 'raise ValueError' in RETURNS_ZERO  # string + AST checks are satisfied...
    v = kernel.commit(sid, "billing", RETURNS_ZERO)
    assert not v.accepted and v.gate == "C"
    assert isinstance(v.error, LogicalError)
    assert 'call:charge("u", 0) raises ValueError' in str(v.error)


def test_string_invariants_stay_backward_compatible(kernel, project):
    # conftest's billing.py carries only the legacy string invariant.
    sid = kernel.init_session(project)
    from conftest import BILLING_SRC

    assert kernel.commit(sid, "billing", BILLING_SRC).accepted
    broken = BILLING_SRC.replace(
        '    # okf-invariant: "amount_cents <= 0" in src and "raise ValueError" in src\n'
        "    if amount_cents <= 0:\n"
        '        raise ValueError("amount must be positive")\n',
        "    if amount_cents == 0:\n        amount_cents = 1\n",
    )
    v = kernel.commit(sid, "billing", broken)
    assert not v.accepted and isinstance(v.error, LogicalError)
