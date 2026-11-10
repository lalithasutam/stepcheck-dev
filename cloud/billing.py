"""Entitlements, the free trial, checkout links and billing webhooks.

Policy
  public repositories   always evaluated, free
  private repositories  the first FREE_PRIVATE_PRS pull requests of an installation are
                        evaluated free (a pull request counts once, however often it is
                        pushed); after that an active subscription is required:
                        solo for a personal account, team for an Organization

The merchant of record is Dodo Payments or Polar. Both sign webhooks with the Standard
Webhooks scheme: HMAC-SHA256 over "<webhook-id>.<webhook-timestamp>.<raw body>", sent
base64-encoded as `webhook-signature: v1,<signature>` (several, space separated, during
a secret rotation). A `whsec_` secret is base64 after the prefix; Polar secrets created
before its move to Standard Webhooks use the UTF-8 bytes of the whole secret as the key,
so both keys are tried.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import Settings
from .store import Store

FREE_PRIVATE_PRS = 15
REPLAY_WINDOW_SECONDS = 300
PLANS: dict[str, dict] = {
    "solo": {"label": "Solo", "usd_per_month": 29},
    "team": {"label": "Team", "usd_per_month": 149},
}

_ACTIVATING = {"subscription.active", "subscription.renewed", "subscription.uncanceled", "subscription.resumed",
               "subscription.unpaused", "subscription.cycled"}
_REVOKING = {"subscription.revoked", "subscription.expired", "subscription.failed", "subscription.on_hold",
             "subscription.paused"}
_LIVE_STATUSES = {"active", "trialing"}
_DEAD_STATUSES = {"cancelled", "canceled", "expired", "failed", "on_hold", "paused", "revoked", "unpaid",
                  "incomplete_expired"}


class CheckoutNotConfigured(RuntimeError):
    """No checkout link is configured for the plan."""


# --------------------------------------------------------------------- entitlements


def required_plan(account_type: str) -> str:
    return "team" if account_type == "Organization" else "solo"


def entitled(installation: dict) -> bool:
    """Whether the installation's subscription covers private repositories."""
    if installation.get("status") != "active":
        return False
    tier = installation.get("tier")
    return tier == "team" or (tier == "solo" and installation.get("account_type") != "Organization")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str  # "public" | "subscribed" | "trial" | "trial_exhausted" | "no_source" (private, nothing to judge)
    trial_used: int = 0
    plan: str | None = None
    checkout_url: str | None = None


def checkout_link(settings: Settings, installation_id: int, plan: str) -> str:
    """The service's own one-click link; it redirects to the merchant of record."""
    return f"{settings.cloud_url.rstrip('/')}/checkout?installation_id={installation_id}&plan={plan}"


def decide(store: Store, settings: Settings, installation: dict, repo: str, pr_number: int, private: bool, *,
           consume: bool = True) -> Decision:
    """Whether this pull request may be evaluated, and on what grounds. With
    `consume=False` the answer is a preview: no trial slot is taken, so a pull request
    that turns out to change no source file costs nothing."""
    if not private:
        return Decision(True, "public")
    if entitled(installation):
        return Decision(True, "subscribed")
    installation_id = installation["installation_id"]
    claim = store.claim_trial_pr if consume else store.trial_status
    allowed, used = claim(installation_id, repo, pr_number, FREE_PRIVATE_PRS)
    if allowed:
        return Decision(True, "trial", trial_used=used)
    plan = required_plan(installation["account_type"])
    return Decision(False, "trial_exhausted", trial_used=used, plan=plan,
                    checkout_url=checkout_link(settings, installation_id, plan))


def merchant_checkout_url(settings: Settings, installation: dict, plan: str) -> str:
    """The merchant's checkout link for `plan`, carrying the installation as metadata.

    Dodo Payments passes every `metadata_<key>` query parameter of a payment link into
    the payment's and subscription's metadata. Polar stores a link's `reference_id` in
    the checkout metadata, which it copies to the subscription; the plan rides in it as
    `<installation id>:<plan>`. An Organization is always sent to the team plan."""
    if plan not in PLANS:
        raise ValueError(f"unknown plan {plan!r}")
    if installation["account_type"] == "Organization":
        plan = "team"
    base = settings.checkout_url_team if plan == "team" else settings.checkout_url_solo
    if not base:
        raise CheckoutNotConfigured(f"no checkout link is configured for the {plan} plan")
    installation_id = str(installation["installation_id"])
    if settings.billing_provider == "polar":
        extra = {"reference_id": f"{installation_id}:{plan}"}
    else:
        extra = {"metadata_installation_id": installation_id,
                 "metadata_account_login": installation["account_login"], "metadata_plan": plan}
    parts = urlsplit(base)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(extra)
    return urlunsplit(parts._replace(query=urlencode(query)))


# ------------------------------------------------------------------------- webhooks


def _keys(secret: str) -> list[bytes]:
    keys = [secret.encode("utf-8")]
    encoded = secret[len("whsec_"):] if secret.startswith("whsec_") else secret
    try:
        keys.insert(0, base64.b64decode(encoded, validate=True))
    except ValueError:
        pass
    return keys


def sign_webhook(secret: str, webhook_id: str, timestamp: int, body: bytes) -> str:
    """The `webhook-signature` value a Standard Webhooks sender computes (used by tests
    and for local replays)."""
    signed = f"{webhook_id}.{timestamp}.".encode("utf-8") + body
    digest = hmac.new(_keys(secret)[0], signed, hashlib.sha256).digest()
    return "v1," + base64.b64encode(digest).decode("ascii")


def verify_webhook(secrets: dict[str, str], headers, body: bytes, now: float) -> str | None:
    """The provider whose secret signed this delivery, or None when the headers are
    missing, the timestamp is outside the replay window or no signature matches."""
    webhook_id = headers.get("webhook-id")
    timestamp = headers.get("webhook-timestamp")
    signature = headers.get("webhook-signature")
    if not webhook_id or not timestamp or not signature:
        return None
    try:
        sent_at = int(timestamp)
    except ValueError:
        return None
    if abs(now - sent_at) > REPLAY_WINDOW_SECONDS:
        return None
    signed = f"{webhook_id}.{timestamp}.".encode("utf-8") + body
    offered = [value.encode("ascii", "ignore") for version, _, value in (part.partition(",") for part in signature.split())
               if version == "v1" and value]
    matched = None
    for provider, secret in secrets.items():
        for key in _keys(secret):
            expected = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest())
            for value in offered:
                if hmac.compare_digest(expected, value):
                    matched = matched or provider
    return matched


@dataclass(frozen=True)
class SubscriptionChange:
    installation_id: int | None
    tier: str | None
    status: str | None  # "active" | "cancelled" | None when the event changes no entitlement
    subscription_id: str | None
    account_login: str


def _installation_and_plan(metadata: dict) -> tuple[int | None, str | None]:
    """Dodo: `metadata.installation_id` and `metadata.plan` (from the link's `metadata_*`
    parameters). Polar: the link's `reference_id`, found under `referenceId` or
    `reference_id`, holding `<installation id>` or `<installation id>:<plan>`."""
    raw = metadata.get("installation_id")
    plan = metadata.get("plan")
    reference = metadata.get("referenceId") or metadata.get("reference_id")
    if raw is None and reference:
        raw, _, ref_plan = str(reference).partition(":")
        plan = plan or ref_plan or None
    try:
        return int(raw), plan
    except (TypeError, ValueError):
        return None, plan


def interpret(event: dict, settings: Settings) -> SubscriptionChange:
    """What a subscription webhook means for an installation's entitlement.

    The event type decides when it is unambiguous (`subscription.active`,
    `subscription.revoked`, …); otherwise the subscription's own `status` does, so a
    cancellation that keeps access until the period ends (Polar's `subscription.canceled`
    with status `active`) revokes nothing."""
    kind = str(event.get("type") or "")
    data = event.get("data") or {}
    metadata = data.get("metadata") or {}
    installation_id, plan = _installation_and_plan(metadata)
    if plan not in PLANS:
        product = data.get("product_id") or (data.get("product") or {}).get("id")
        plan = {settings.product_id_solo: "solo", settings.product_id_team: "team"}.get(product) if product else None
    live = str(data.get("status") or "").lower()
    if not kind.startswith("subscription."):
        status = None
    elif kind in _ACTIVATING:
        status = "active"
    elif kind in _REVOKING:
        status = "cancelled"
    elif live in _LIVE_STATUSES:
        status = "active"
    elif live in _DEAD_STATUSES or kind in ("subscription.cancelled", "subscription.canceled"):
        status = "cancelled"
    else:
        status = None
    if status == "active" and plan is None:
        status = None  # an activation that names no plan cannot grant one
    # the subscription's id: Dodo `data.subscription_id`, Polar `data.id`
    return SubscriptionChange(installation_id, plan, status, data.get("subscription_id") or data.get("id"),
                              str(metadata.get("account_login") or ""))


def apply_webhook(store: Store, settings: Settings, provider: str, webhook_id: str, timestamp: int, event: dict) -> dict:
    """Apply one verified billing webhook idempotently."""
    change = interpret(event, settings)
    outcome = store.apply_subscription_event(
        webhook_id, provider, str(event.get("type") or ""), installation_id=change.installation_id, tier=change.tier,
        status=change.status, subscription_id=change.subscription_id, event_ts=timestamp,
        account_login=change.account_login)
    return {"outcome": outcome, "installation_id": change.installation_id, "status": change.status, "tier": change.tier,
            "activated": outcome == "applied" and change.status == "active"}
