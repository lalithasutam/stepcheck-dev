"""The StepCheck Cloud HTTP service.

Routes
  POST /webhooks/github                      GitHub App webhooks (signature verified)
  POST /webhooks/billing                     Dodo Payments / Polar webhooks (Standard Webhooks)
  GET  /checkout?installation_id=&plan=      one-click redirect to the merchant's checkout
  GET  /.well-known/stepcheck-pubkey.pem     the Ed25519 public key receipts verify against
  GET  /v1/receipts/{receipt_id}.intoto.json a signed DSSE receipt
  GET  /health

Run with `uvicorn cloud.app:create_app --factory`. A verified webhook is answered at once
and its work (GitHub calls, judging, the Check Run) runs after the response.
"""
from __future__ import annotations

import json
import logging
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response

from . import Settings, billing, signing
from .github_app import Firewall, GitHubApp, Judge, verify_github_signature
from .store import Store

log = logging.getLogger("stepcheck.cloud")


def create_app(settings: Settings | None = None, *, github_transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if settings.require_signing_key and not settings.signing_key_pem:
        raise RuntimeError("STEPCHECK_SIGNING_KEY_PEM is required (STEPCHECK_REQUIRE_SIGNING_KEY is set)")
    signer = signing.Signer.from_pem(settings.signing_key_pem)
    if signer.ephemeral:
        log.warning("no STEPCHECK_SIGNING_KEY_PEM: signing with a key generated for this process only")
    store = Store(settings.cloud_db)
    judge = Judge(workers=settings.judge_workers)
    firewall = Firewall(settings, store, signer, GitHubApp(settings, github_transport), judge)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        judge.close()
        store.close()

    app = FastAPI(title="StepCheck Cloud", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.settings, app.state.store, app.state.signer, app.state.firewall = settings, store, signer, firewall

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "keyid": signer.keyid}

    @app.post("/webhooks/github")
    async def github_webhook(request: Request, background: BackgroundTasks):
        body = await request.body()
        if not verify_github_signature(settings.github_webhook_secret, body, request.headers.get("x-hub-signature-256")):
            return JSONResponse({"error": "invalid signature"}, status_code=401)
        event = request.headers.get("x-github-event", "")
        try:
            payload = json.loads(body)
        except ValueError:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)
        if not isinstance(payload, dict) or "installation" not in payload or not firewall.wants(event, payload):
            return {"accepted": False}
        background.add_task(firewall.handle, event, payload)
        return JSONResponse({"accepted": True}, status_code=202)

    @app.post("/webhooks/billing")
    async def billing_webhook(request: Request, background: BackgroundTasks):
        body = await request.body()
        provider = billing.verify_webhook(settings.webhook_secrets(), request.headers, body, time.time())
        if provider is None:
            return JSONResponse({"error": "invalid signature"}, status_code=401)
        try:
            event = json.loads(body)
        except ValueError:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)
        result = billing.apply_webhook(store, settings, provider, request.headers["webhook-id"],
                                       int(request.headers["webhook-timestamp"]), event if isinstance(event, dict) else {})
        if result["activated"]:
            background.add_task(firewall.reevaluate_gated, result["installation_id"])
        return {k: result[k] for k in ("outcome", "installation_id", "status", "tier")}

    @app.get("/checkout")
    def checkout(installation_id: int, plan: str):
        if plan not in billing.PLANS:
            return JSONResponse({"error": "plan must be solo or team"}, status_code=400)
        installation = store.installation(installation_id)
        if installation is None:
            return JSONResponse({"error": "unknown installation"}, status_code=404)
        try:
            return RedirectResponse(billing.merchant_checkout_url(settings, installation, plan), status_code=303)
        except billing.CheckoutNotConfigured as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)

    @app.get("/.well-known/stepcheck-pubkey.pem")
    def public_key() -> Response:
        return PlainTextResponse(signer.public_pem(), media_type="application/x-pem-file")

    @app.get("/v1/receipts/{receipt_id}.intoto.json")
    def receipt(receipt_id: str):
        envelope = store.receipt(receipt_id)
        if envelope is None:
            return JSONResponse({"error": "unknown receipt"}, status_code=404)
        return JSONResponse(envelope, media_type="application/vnd.dsse.envelope.v1+json")

    return app
