"""StepCheck Cloud — the hosted GitHub App and billing service (Stage 2 MVP).

Isolated from the `stepcheck-dev` package: nothing here is shipped in the wheel and
nothing under `backend/` imports it. The service uses the published engine
(`StateKernel.judge_transition` through `retro.judge`) exactly as `stepcheck diff` does.

Modules
  app         FastAPI application factory and the HTTP routes
  github_app  webhook verification, GitHub App auth, PR evaluation, Check Runs, overrides
  signing     Ed25519 DSSE envelopes over in-toto Statement v1 receipts
  billing     entitlements, the free trial, checkout links and billing webhooks
  store       SQLite (WAL) persistence
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields

__all__ = ["Settings"]


def _pem(value: str) -> str:
    """A PEM pasted into a single-line environment variable keeps its newlines as `\\n`."""
    return value.replace("\\n", "\n").strip()


@dataclass
class Settings:
    """Service configuration. Every field is read from `STEPCHECK_<FIELD NAME IN CAPS>`,
    except the database path, which is `STEPCHECK_CLOUD_DB`, and the public base URL,
    which is `STEPCHECK_CLOUD_URL`."""

    github_app_id: str = ""
    github_private_key_pem: str = field(default="", repr=False)
    github_webhook_secret: str = field(default="", repr=False)
    github_api_url: str = "https://api.github.com"
    cloud_db: str = "stepcheck-cloud.db"
    cloud_url: str = "http://localhost:8080"
    signing_key_pem: str = field(default="", repr=False)
    require_signing_key: bool = False
    billing_provider: str = "dodo"  # "dodo" or "polar": how the checkout link carries metadata
    dodo_webhook_secret: str = field(default="", repr=False)
    polar_webhook_secret: str = field(default="", repr=False)
    checkout_url_solo: str = ""
    checkout_url_team: str = ""
    product_id_solo: str = ""
    product_id_team: str = ""
    judge_workers: int = 1

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Settings":
        env = os.environ if env is None else env
        values: dict = {}
        for f in fields(cls):
            raw = env.get(f"STEPCHECK_{f.name.upper()}")
            if raw is None:
                continue
            if f.name.endswith("_pem"):
                values[f.name] = _pem(raw)
            elif f.type in ("int", int):
                values[f.name] = int(raw)
            elif f.type in ("bool", bool):
                values[f.name] = raw.strip().lower() in ("1", "true", "yes")
            else:
                values[f.name] = raw.strip()
        return cls(**values)

    def webhook_secrets(self) -> dict[str, str]:
        """Configured billing webhook secrets by provider name."""
        return {k: v for k, v in (("dodo", self.dodo_webhook_secret), ("polar", self.polar_webhook_secret)) if v}
