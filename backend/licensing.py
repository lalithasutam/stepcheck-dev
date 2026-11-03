"""Opt-in four-tier licensing for the DualDoorGateway and the team-grade CLI commands.

This is a LOCAL VERIFICATION STUB, not a billing system: a key is an HMAC token
`sk-<tier>-<nonce16><mac32>` minted with `issue_key()` from a shared secret
(`STEPCHECK_LICENSE_SECRET`) and verified offline. Nothing is enforced unless
`STEPCHECK_REQUIRE_KEY=1`; the default local experience is unchanged.

Tiers and capabilities live in `pricing.TIERS`:
  free        audit, audit --card, hooks, up, mcp, ci
  pro         Door 1 accordion compaction, cache-cliff shield, model arbitrage
  team        ci --report, GET /v1/team/summary, org-wide Pin & Lock
  enterprise  polyglot verification beyond Python/TS, compliance bundles
"""
from __future__ import annotations

import hashlib
import hmac
import os

import pricing

KEY_PREFIX = "sk-"
HEADER = "x-stepcheck-key"
ENV_KEY = "STEPCHECK_LICENSE_KEY"
ENV_SECRET = "STEPCHECK_LICENSE_SECRET"
ENV_REQUIRE = "STEPCHECK_REQUIRE_KEY"


def enforcement_enabled() -> bool:
    return os.environ.get(ENV_REQUIRE, "").strip() == "1"


def secret() -> str:
    return os.environ.get(ENV_SECRET, "")


def issue_key(tier: str, secret_value: str, seed: str = "") -> str:
    """Deterministic key for `tier`: the nonce is derived from `seed`, the MAC
    binds tier and nonce to the secret."""
    if tier not in pricing.TIERS:
        raise ValueError(f"unknown tier {tier!r}")
    nonce = hashlib.sha256(f"{tier}:{seed}".encode("utf-8")).hexdigest()[:16]
    mac = hmac.new(secret_value.encode("utf-8"), f"{tier}:{nonce}".encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    return f"{KEY_PREFIX}{tier}-{nonce}{mac}"


def verify_key(key: str | None, secret_value: str) -> str | None:
    """The tier a key proves, or None for a missing, malformed or forged key."""
    if not key or not key.startswith(KEY_PREFIX):
        return None
    rest = key[len(KEY_PREFIX):]
    tier, _, hexpart = rest.partition("-")
    if tier not in pricing.TIERS or len(hexpart) != 48:
        return None
    nonce, mac = hexpart[:16], hexpart[16:]
    expected = hmac.new(secret_value.encode("utf-8"), f"{tier}:{nonce}".encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    return tier if hmac.compare_digest(mac, expected) else None


def check(capability: str, key: str | None) -> dict | None:
    """None when the capability may be used; otherwise the 402 body naming the
    tier and price it needs. Without enforcement everything is allowed."""
    if not enforcement_enabled():
        return None
    required = pricing.tier_for_capability(capability)
    held = verify_key(key, secret()) or "free"
    if pricing.TIERS[held]["rank"] >= pricing.TIERS[required]["rank"]:
        return None
    price = pricing.tier_price(required)
    return {
        "error": "license_required",
        "status": 402,
        "capability": capability,
        "required_tier": required,
        "held_tier": held,
        "price": price,
        "label": pricing.TIERS[required]["label"],
        "message": (f"{capability} needs the {required} tier ({pricing.TIERS[required]['label']}, "
                    + ", ".join(f"{k}={v}" for k, v in price.items()) + f"); this key holds {held}"),
    }


def gate_headers(headers: dict, capability: str) -> dict | None:
    lowered = {str(k).lower(): v for k, v in headers.items()}
    return check(capability, lowered.get(HEADER))


def gate_env(capability: str) -> dict | None:
    return check(capability, os.environ.get(ENV_KEY))


def held_tier(key: str | None) -> str:
    return verify_key(key, secret()) or "free"
