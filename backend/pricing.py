"""Price and tier parameters: product constants, not measurements.

Every dollar figure the gateway reports (model arbitrage, cache-cliff shield,
team summary) is derived from this table so a test can read the parameter it
checks instead of retyping it. Prices are USD per million input tokens.
"""
from __future__ import annotations

USD_PER_MTOK_INPUT: dict[str, float] = {
    "haiku_4_5": 0.80,
    "sonnet": 3.00,
    "opus": 15.00,
    "local": 0.00,  # Ollama / vLLM on the developer's own hardware
}
CACHE_READ_FRACTION = 0.10  # a cache-read token costs this fraction of an input token

TIERS: dict[str, dict] = {
    "free": {
        "rank": 0,
        "label": "Open Core CLI & Local Hooks",
        "usd_per_month": 0.0,
        "license": "Apache-2.0",
        "capabilities": ["audit", "audit_card", "hooks", "up", "mcp", "ci"],
    },
    "pro": {
        "rank": 1,
        "label": "Pro FinOps Proxy",
        "usd_per_month": 19.0,
        "alternative": "15% of verified savings",
        "savings_share": 0.15,
        "capabilities": ["door1_accordion", "cache_cliff_shield", "model_arbitrage"],
    },
    "team": {
        "rank": 2,
        "label": "Team PR Blast-Radius & FinOps",
        "usd_per_seat_month": 39.0,
        "seats": "10-100",
        "capabilities": ["ci_report", "team_summary", "org_pin_lock"],
    },
    "enterprise": {
        "rank": 3,
        "label": "Enterprise Trust & Compliance Ledger",
        "usd_per_seat_month": 79.0,
        "alternative": "$25k/yr self-hosted",
        "usd_per_year_self_hosted": 25000.0,
        "capabilities": ["polyglot_verification", "compliance_bundle"],
    },
}
TIER_ORDER = ["free", "pro", "team", "enterprise"]


def price_for_model(model: str | None) -> float | None:
    """USD per million input tokens for a model name, by family keyword; None
    when the family is unknown (the caller then counts no saving)."""
    name = (model or "").lower()
    if not name:
        return None
    for key in ("haiku", "sonnet", "opus"):
        if key in name:
            return USD_PER_MTOK_INPUT["haiku_4_5" if key == "haiku" else key]
    if any(k in name for k in ("ollama", "vllm", "local", "llama", "qwen", "mistral")):
        return USD_PER_MTOK_INPUT["local"]
    return None


def tier_for_capability(capability: str) -> str:
    """The lowest tier whose capability list contains `capability` (free when
    nobody lists it: an unlisted capability is never gated)."""
    for tier in TIER_ORDER:
        if capability in TIERS[tier]["capabilities"]:
            return tier
    return "free"


def tier_price(tier: str) -> dict:
    t = TIERS[tier]
    return {k: t[k] for k in ("usd_per_month", "usd_per_seat_month", "alternative", "usd_per_year_self_hosted") if k in t}
