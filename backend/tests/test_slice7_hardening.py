"""Slice 7 — kernel hardening: auto-skeleton budget fallback & Gate C execution guard (Seam 1)."""
import time

from conftest import AUTH_SRC

from kernel import LogicalError


def _large_module(n_funcs: int = 60) -> str:
    """>4,000 raw tokens: many real functions with bodies worth skeletonizing."""
    parts = ["import hashlib\n\n\n"]
    for i in range(n_funcs):
        parts.append(
            f"def handler_{i}(payload: dict, retries: int = 3) -> dict:\n"
            f'    """Handle event kind {i} with bounded retries."""\n'
            f"    digest = hashlib.sha256(str(payload).encode()).hexdigest()\n"
            f"    for attempt in range(retries):\n"
            f"        if digest.startswith('{i:02x}'):\n"
            f"            return {{'kind': {i}, 'attempt': attempt, 'digest': digest}}\n"
            f"    return {{'kind': {i}, 'attempt': -1, 'digest': digest}}\n\n\n"
        )
    return "".join(parts)


# ------------------------------------------------ Caveat A: unfocused budget


def test_unfocused_checkout_of_large_module_auto_skeletonizes_under_budget(kernel, tmp_path):
    big = _large_module()
    from kernel import _tokens

    assert _tokens.count(big) > 4000, "fixture must exceed the budget on its own"
    (tmp_path / "big.py").write_text(big, encoding="utf-8")
    (tmp_path / "auth.py").write_text(AUTH_SRC, encoding="utf-8")

    sid = kernel.init_session(tmp_path)
    payload = kernel.checkout(sid, "big")  # focus=None — the agent asked for everything

    assert payload.auto_skeletonized is True
    assert payload.token_count < 4000
    rendered = payload.rendered()
    # Symbol index: every top-level def is discoverable by name...
    assert "handler_0(" in rendered and "handler_59(" in rendered
    # ...bodies are stripped, docstrings kept, and the agent is told how to go deeper.
    assert "hashlib.sha256(str(payload).encode())" not in rendered
    assert "Handle event kind 7 with bounded retries." in rendered
    assert "focus=" in rendered

    # A small module is untouched by the fallback.
    small = kernel.checkout(sid, "auth")
    assert small.auto_skeletonized is False
    assert "hashlib.sha256(token.encode())" in small.frame_markdown


# ------------------------------------------- Caveat B: Gate C execution guard

RUNAWAY = '''\
from auth import require_auth


@require_auth
def charge(user: str, amount_cents: int) -> dict:
    # okf-invariant: call:charge("u", 0) raises ValueError
    if amount_cents <= 0:
        raise ValueError("amount must be positive")
    return {"user": user, "amount_cents": amount_cents}
'''

INFINITE_LOOP = RUNAWAY.replace(
    "    if amount_cents <= 0:\n        raise ValueError(\"amount must be positive\")\n",
    "    while amount_cents <= 0:\n        amount_cents = amount_cents  # never advances\n",
)

INFINITE_RECURSION = RUNAWAY.replace(
    "    if amount_cents <= 0:\n        raise ValueError(\"amount must be positive\")\n",
    "    if amount_cents <= 0:\n        return charge(user, amount_cents - 0)\n",
)


def _project(tmp_path):
    (tmp_path / "auth.py").write_text(AUTH_SRC, encoding="utf-8")
    (tmp_path / "billing.py").write_text(RUNAWAY, encoding="utf-8")
    return tmp_path


def test_gate_c_guard_stops_runaway_loop_deterministically(kernel, tmp_path):
    sid = kernel.init_session(_project(tmp_path))
    t0 = time.perf_counter()
    v = kernel.commit(sid, "billing", INFINITE_LOOP)
    elapsed = time.perf_counter() - t0

    assert elapsed < 1.0, f"Gate C must not hang: {elapsed:.2f}s"
    assert not v.accepted and v.gate == "C"
    assert isinstance(v.error, LogicalError)
    assert "execution budget" in str(v.error)
    assert 'call:charge("u", 0) raises ValueError' in str(v.error)

    # Deterministic: the same staged diff yields the same verdict text.
    again = kernel.commit(sid, "billing", INFINITE_LOOP)
    assert str(again.error) == str(v.error)


def test_gate_c_guard_catches_infinite_recursion(kernel, tmp_path):
    sid = kernel.init_session(_project(tmp_path))
    t0 = time.perf_counter()
    v = kernel.commit(sid, "billing", INFINITE_RECURSION)
    assert time.perf_counter() - t0 < 1.0
    assert not v.accepted and v.gate == "C" and isinstance(v.error, LogicalError)
    # The kernel is still healthy afterwards: a correct diff passes.
    assert kernel.commit(sid, "billing", RUNAWAY).accepted
