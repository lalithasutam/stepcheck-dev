"""StepCheck Cloud MVP, end to end and offline.

Every test drives the real service through its HTTP routes (Starlette's TestClient) with
the real engine, a real SQLite file, real Ed25519 / RS256 / HMAC cryptography and no
network: GitHub's REST API is a fake behind `httpx.MockTransport` that verifies the App
JWT it is sent and records the Check Runs and comments the service publishes.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import hmac
import json
import re
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from cloud import Settings, billing, signing
from cloud.app import create_app
from cloud.github_app import CHECK_NAME, FOOTER, Judge, parse_allow, AllowSyntaxError
from cloud.store import Store

APP_ID = "424242"
WEBHOOK_SECRET = "gh-webhook-secret"
DODO_SECRET = "whsec_" + base64.b64encode(b"dodo-signing-key-0123456789abcdef").decode()
POLAR_SECRET = "polar-legacy-secret!"  # not base64: the key is its UTF-8 bytes
CLOUD_URL = "https://cloud.stepcheck.test"
INSTALL = 9001

BEFORE = '''\
def charge(user, amount):
    if amount <= 0:
        raise ValueError("amount must be positive")
    return {"user": user, "amount": amount}


def refund(user, amount):
    if not user:
        raise PermissionError("no user")
    return {"user": user, "amount": -amount}
'''
GUARD_DROP = BEFORE.replace("if amount <= 0:", "if amount < 0:")
TWO_DROPS = GUARD_DROP.replace('    if not user:\n        raise PermissionError("no user")\n', "")
CLEAN = BEFORE + "\n\ndef describe(user):\n    return f\"account {user}\"\n"


def _sha(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()


def _blob_sha(raw: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()


class FakeGitHub:
    """GitHub's REST API for the calls the service makes, with its state in memory."""

    def __init__(self, app_public_key) -> None:
        self._app_key = app_public_key
        self.pulls: dict[tuple[str, int], dict] = {}
        self.pull_files: dict[tuple[str, int], list[dict]] = {}
        self.at_ref: dict[tuple[str, str, str], bytes] = {}
        self.blobs: dict[tuple[str, str], bytes] = {}
        self.permissions: dict[tuple[str, str], str] = {}
        self.checks: dict[int, dict] = {}
        self.comments: list[dict] = []
        self.token_requests = 0
        self.requests: list[tuple[str, str]] = []
        self._next_id = 5000
        self.transport = httpx.MockTransport(self.handle)

    # ------------------------------------------------------------------ state

    def add_pr(self, repo: str, number: int, files: dict[str, tuple[str, str]], *, private: bool = False,
               owner_type: str = "User", head: str | None = None) -> dict:
        base_sha = _sha(f"{repo}#{number}:base")
        head_sha = head or _sha(f"{repo}#{number}:head:{json.dumps(files, sort_keys=True)}")
        listing = []
        for path, (before, after) in files.items():
            raw = after.encode()
            self.at_ref[(repo, base_sha, path)] = before.encode()
            self.blobs[(repo, _blob_sha(raw))] = raw
            listing.append({"filename": path, "status": "modified", "sha": _blob_sha(raw)})
        self.pull_files[(repo, number)] = listing
        pr = {"number": number, "head": {"sha": head_sha},
              "base": {"sha": base_sha, "ref": "main",
                       "repo": {"full_name": repo, "private": private,
                                "owner": {"login": repo.split("/")[0], "type": owner_type}}}}
        self.pulls[(repo, number)] = pr
        return pr

    def check_for(self, repo: str, number: int) -> dict:
        """The latest state of the Check Run on a pull request's current head."""
        head = self.pulls[(repo, number)]["head"]["sha"]
        runs = [c for c in self.checks.values() if c["repo"] == repo and c["head_sha"] == head]
        assert len(runs) == 1, f"expected one Check Run on {repo}#{number}, found {len(runs)}"
        return runs[0]

    # --------------------------------------------------------------- transport

    def _jwt_ok(self, header: str) -> bool:
        try:
            head, claims, sig = header.removeprefix("Bearer ").split(".")
            pad = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
            self._app_key.verify(pad(sig), f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
            body = json.loads(pad(claims))
            return (json.loads(pad(head))["alg"] == "RS256" and body["iss"] == APP_ID
                    and body["iat"] < time.time() < body["exp"] <= body["iat"] + 600)
        except Exception:  # noqa: BLE001
            return False

    def handle(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.requests.append((method, path))
        m = re.fullmatch(r"/app/installations/(\d+)/access_tokens", path)
        if m and method == "POST":
            if not self._jwt_ok(request.headers.get("authorization", "")):
                return httpx.Response(401, json={"message": "bad JWT"})
            self.token_requests += 1
            expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            return httpx.Response(201, json={"token": f"ghs_{m.group(1)}", "expires_at": expires})
        if not request.headers.get("authorization", "").startswith("Bearer ghs_"):
            return httpx.Response(401, json={"message": "no installation token"})
        m = re.fullmatch(r"/repos/([^/]+/[^/]+)/(.+)", path)
        if not m:
            return httpx.Response(404, json={"message": "not found"})
        repo, rest = m.group(1), m.group(2)
        if (m := re.fullmatch(r"pulls/(\d+)", rest)) and method == "GET":
            return httpx.Response(200, json=self.pulls[(repo, int(m.group(1)))])
        if (m := re.fullmatch(r"pulls/(\d+)/files", rest)) and method == "GET":
            page = int(request.url.params.get("page", "1"))
            return httpx.Response(200, json=self.pull_files[(repo, int(m.group(1)))] if page == 1 else [])
        if (m := re.fullmatch(r"compare/([0-9a-f]+)\.\.\.([0-9a-f]+)", rest)) and method == "GET":
            return httpx.Response(200, json={"merge_base_commit": {"sha": m.group(1)}})
        if (m := re.fullmatch(r"contents/(.+)", rest)) and method == "GET":
            assert "raw" in request.headers["accept"]
            raw = self.at_ref.get((repo, request.url.params["ref"], m.group(1)))
            return httpx.Response(200, content=raw) if raw is not None else httpx.Response(404, json={})
        if (m := re.fullmatch(r"git/blobs/([0-9a-f]+)", rest)) and method == "GET":
            assert "raw" in request.headers["accept"]
            raw = self.blobs.get((repo, m.group(1)))
            return httpx.Response(200, content=raw) if raw is not None else httpx.Response(404, json={})
        if rest == "check-runs" and method == "POST":
            payload = json.loads(request.content)
            self._next_id += 1
            self.checks[self._next_id] = {"id": self._next_id, "repo": repo, "head_sha": payload["head_sha"],
                                          "updates": 0, **payload}
            return httpx.Response(201, json={"id": self._next_id})
        if (m := re.fullmatch(r"check-runs/(\d+)", rest)) and method == "PATCH":
            run = self.checks[int(m.group(1))]
            run.pop("details_url", None)
            run.update(json.loads(request.content))
            run["updates"] += 1
            return httpx.Response(200, json={"id": run["id"]})
        if (m := re.fullmatch(r"collaborators/([^/]+)/permission", rest)) and method == "GET":
            return httpx.Response(200, json={"permission": self.permissions.get((repo, m.group(1)), "none")})
        if (m := re.fullmatch(r"issues/(\d+)/comments", rest)) and method == "POST":
            self.comments.append({"repo": repo, "number": int(m.group(1)), "body": json.loads(request.content)["body"]})
            return httpx.Response(201, json={"id": len(self.comments)})
        return httpx.Response(404, json={"message": f"unhandled {method} {path}"})


# ----------------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def app_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    return SimpleNamespace(pem=pem, public=key.public_key())


@pytest.fixture()
def cloud(tmp_path, app_key):
    settings = Settings(
        github_app_id=APP_ID, github_private_key_pem=app_key.pem, github_webhook_secret=WEBHOOK_SECRET,
        cloud_db=str(tmp_path / "cloud.db"), cloud_url=CLOUD_URL,
        dodo_webhook_secret=DODO_SECRET, polar_webhook_secret=POLAR_SECRET,
        checkout_url_solo="https://checkout.dodopayments.com/buy/pdt_solo?quantity=1",
        checkout_url_team="https://checkout.dodopayments.com/buy/pdt_team?quantity=1")
    github = FakeGitHub(app_key.public)
    app = create_app(settings, github_transport=github.transport)
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, github=github, store=app.state.store, settings=settings, app=app)


def github_post(client, event: str, payload: dict, *, secret: str = WEBHOOK_SECRET, signature: str | None = None):
    body = json.dumps(payload).encode()
    headers = {"X-GitHub-Event": event, "Content-Type": "application/json"}
    sig = signature if signature is not None else "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if sig:
        headers["X-Hub-Signature-256"] = sig
    return client.post("/webhooks/github", content=body, headers=headers)


def pr_event(github: FakeGitHub, repo: str, number: int, action: str = "opened", installation: int = INSTALL) -> dict:
    return {"action": action, "installation": {"id": installation}, "repository": {"full_name": repo},
            "pull_request": github.pulls[(repo, number)]}


def comment_event(repo: str, number: int, user: str, body: str, comment_id: int, installation: int = INSTALL) -> dict:
    return {"action": "created", "installation": {"id": installation}, "repository": {"full_name": repo},
            "issue": {"number": number, "pull_request": {"url": f"https://api.github.com/repos/{repo}/pulls/{number}"}},
            "comment": {"id": comment_id, "body": body, "user": {"login": user, "type": "User"}}}


def open_pr(cloud, repo: str, number: int, files: dict, **kwargs) -> dict:
    cloud.github.add_pr(repo, number, files, **kwargs)
    r = github_post(cloud.client, "pull_request", pr_event(cloud.github, repo, number))
    assert r.status_code == 202, r.text
    return cloud.github.check_for(repo, number)


def billing_post(client, event: dict, *, secret: str = DODO_SECRET, key: bytes | None = None, webhook_id: str = "evt_1",
                 timestamp: int | None = None, signature: str | None = None):
    body = json.dumps(event).encode()
    ts = int(time.time()) if timestamp is None else timestamp
    if signature is None:
        key = key if key is not None else base64.b64decode(secret.removeprefix("whsec_"))
        digest = hmac.new(key, f"{webhook_id}.{ts}.".encode() + body, hashlib.sha256).digest()
        signature = "v1," + base64.b64encode(digest).decode()
    return client.post("/webhooks/billing", content=body, headers={
        "webhook-id": webhook_id, "webhook-timestamp": str(ts), "webhook-signature": signature,
        "Content-Type": "application/json"})


def subscription_event(kind: str, installation: int, plan: str, status: str) -> dict:
    return {"business_id": "bus_test", "type": kind, "timestamp": "2026-11-10T10:00:00Z",
            "data": {"payload_type": "Subscription", "subscription_id": "sub_123", "status": status,
                     "product_id": f"pdt_{plan}",
                     "metadata": {"installation_id": str(installation), "account_login": "acme", "plan": plan}}}


def verify_receipt_independently(envelope: dict, public_pem: str) -> dict:
    """DSSE verification written out here, without the service's own verifier."""
    key = serialization.load_pem_public_key(public_pem.encode())
    payload = base64.b64decode(envelope["payload"])
    kind = envelope["payloadType"].encode()
    message = b"DSSEv1 " + str(len(kind)).encode() + b" " + kind + b" " + str(len(payload)).encode() + b" " + payload
    key.verify(base64.b64decode(envelope["signatures"][0]["sig"]), message)  # raises InvalidSignature
    return json.loads(payload)


# ------------------------------------------------- 1. forged webhooks are rejected


def test_a_forged_or_unsigned_github_webhook_is_rejected_and_starts_no_work(cloud):
    cloud.github.add_pr("acme/shop", 1, {"billing.py": (BEFORE, GUARD_DROP)})
    payload = pr_event(cloud.github, "acme/shop", 1)
    assert github_post(cloud.client, "pull_request", payload, secret="wrong-secret").status_code == 401
    assert github_post(cloud.client, "pull_request", payload, signature="").status_code == 401
    assert github_post(cloud.client, "pull_request", payload, signature="sha1=" + "0" * 40).status_code == 401
    assert github_post(cloud.client, "pull_request", payload, signature="sha256=" + "0" * 64).status_code == 401
    assert cloud.github.requests == [] and cloud.github.checks == {}
    assert cloud.store.installation(INSTALL) is None


def test_a_service_without_a_webhook_secret_verifies_nothing(tmp_path, app_key):
    settings = Settings(github_app_id=APP_ID, github_private_key_pem=app_key.pem, cloud_db=str(tmp_path / "c.db"))
    github = FakeGitHub(app_key.public)
    github.add_pr("acme/shop", 1, {"billing.py": (BEFORE, GUARD_DROP)})
    with TestClient(create_app(settings, github_transport=github.transport)) as client:
        assert github_post(client, "pull_request", pr_event(github, "acme/shop", 1), secret="").status_code == 401
        assert billing_post(client, subscription_event("subscription.active", INSTALL, "solo", "active")).status_code == 401
    assert github.requests == []


def test_a_forged_stale_or_unsigned_billing_webhook_is_rejected(cloud):
    cloud.store.upsert_installation(INSTALL, "acme", "User")
    event = subscription_event("subscription.active", INSTALL, "solo", "active")
    forged = billing_post(cloud.client, event, key=b"not-the-signing-key")
    stale = billing_post(cloud.client, event, timestamp=int(time.time()) - 6 * 60)
    future = billing_post(cloud.client, event, timestamp=int(time.time()) + 6 * 60)
    wrong_version = billing_post(cloud.client, event, signature="v2," + base64.b64encode(b"x" * 32).decode())
    unsigned = cloud.client.post("/webhooks/billing", content=json.dumps(event))
    assert [r.status_code for r in (forged, stale, future, wrong_version, unsigned)] == [401] * 5
    assert cloud.store.installation(INSTALL)["status"] == "none"

    # the signature covers the id and the timestamp too: replaying a body under another id fails
    ts = int(time.time())
    body = json.dumps(event).encode()
    good = "v1," + base64.b64encode(hmac.new(base64.b64decode(DODO_SECRET[6:]), f"evt_a.{ts}.".encode() + body,
                                              hashlib.sha256).digest()).decode()
    assert billing_post(cloud.client, event, webhook_id="evt_b", timestamp=ts, signature=good).status_code == 401
    assert billing_post(cloud.client, event, webhook_id="evt_a", timestamp=ts, signature=good).status_code == 200
    assert cloud.store.installation(INSTALL)["status"] == "active"


# -------------------------------------- 2. a silent guard drop fails the Check Run


def test_a_pull_request_that_weakens_a_guard_gets_a_failure_check_naming_gate_c_and_the_guard(cloud):
    check = open_pr(cloud, "acme/shop", 7, {"billing.py": (BEFORE, GUARD_DROP), "README.md": ("a", "b")})
    assert check["name"] == CHECK_NAME == "StepCheck Contract Firewall"
    assert check["status"] == "completed" and check["conclusion"] == "failure"
    assert check["head_sha"] == cloud.github.pulls[("acme/shop", 7)]["head"]["sha"]
    assert check["output"]["title"] == "1 silent regression blocked"
    summary = check["output"]["summary"]
    assert "Gate C" in summary and "`billing.py`" in summary and "`charge`" in summary
    assert "amount <= 0" in summary and "raises ValueError" in summary  # the exact guard that was on record
    assert re.search(r"\*\*2 guards audited\*\* across 1 file in \*\*[\d,]+ ms\*\*", summary)
    assert "/stepcheck allow" in summary
    assert "dollars" not in summary.lower() and "$" not in summary and "saved" not in summary.lower()
    assert FOOTER in summary  # a public repository
    # nothing was cloned or fetched beyond the API: one token, the PR's files, one base and one head blob
    methods = [p for _, p in cloud.github.requests]
    assert sum("/contents/" in p for p in methods) == 1 and sum("/git/blobs/" in p for p in methods) == 1
    inst = cloud.store.installation(INSTALL)
    assert (inst["regressions_blocked"], inst["guards_audited"], inst["prs_evaluated"]) == (1, 2, 1)
    assert inst["account_login"] == "acme" and inst["account_type"] == "User"
    assert cloud.store.check_run("acme/shop", 7, check["head_sha"])["receipt_id"] is None  # nothing signed for a failure


def test_a_clean_pull_request_passes_and_a_redelivery_updates_the_same_check_run(cloud):
    check = open_pr(cloud, "acme/shop", 8, {"billing.py": (BEFORE, CLEAN)})
    assert check["conclusion"] == "success" and check["output"]["title"] == "No contract regressions"
    assert "blocked" not in check["output"]["summary"]
    github_post(cloud.client, "pull_request", pr_event(cloud.github, "acme/shop", 8, "synchronize"))
    again = cloud.github.check_for("acme/shop", 8)  # still exactly one Check Run on the head
    assert again["id"] == check["id"] and again["updates"] == 1
    assert cloud.github.token_requests == 1  # the installation token is cached
    inst = cloud.store.installation(INSTALL)
    assert (inst["prs_evaluated"], inst["regressions_blocked"]) == (1, 0)  # a re-run is not counted twice


def test_webhooks_that_need_no_work_are_acknowledged_without_calling_github(cloud):
    cloud.github.add_pr("acme/shop", 9, {"billing.py": (BEFORE, GUARD_DROP)})
    closed = github_post(cloud.client, "pull_request", pr_event(cloud.github, "acme/shop", 9, "closed"))
    chatter = github_post(cloud.client, "issue_comment", comment_event("acme/shop", 9, "dev", "looks good to me", 1))
    ping = github_post(cloud.client, "ping", {"zen": "Keep it logically awesome."})
    assert [r.status_code for r in (closed, chatter, ping)] == [200, 200, 200]
    assert all(r.json() == {"accepted": False} for r in (closed, chatter, ping))
    assert cloud.github.requests == []


# ------------------------------- 3. the human override and the Ed25519 receipt


def test_only_a_write_collaborator_can_allow_a_regression_and_the_sign_off_mints_a_verifiable_receipt(cloud):
    repo = "acme/shop"
    failing = open_pr(cloud, repo, 11, {"billing.py": (BEFORE, GUARD_DROP)})
    assert failing["conclusion"] == "failure"
    cloud.github.permissions.update({(repo, "drive-by"): "read", (repo, "maintainer"): "write"})
    command = '/stepcheck allow billing.py charge --reason "zero-amount trial"'

    # a user with read permission is refused: nothing recorded, the check stays red, and they are told why
    r = github_post(cloud.client, "issue_comment", comment_event(repo, 11, "drive-by", command, 501))
    assert r.status_code == 202
    head = failing["head_sha"]
    assert cloud.store.allowances(repo, 11, head) == []
    assert cloud.github.check_for(repo, 11)["conclusion"] == "failure"
    assert len(cloud.github.comments) == 1 and "@drive-by" in cloud.github.comments[0]["body"]
    assert "`read`" in cloud.github.comments[0]["body"]

    # an outsider GitHub reports no permission for is refused the same way
    github_post(cloud.client, "issue_comment", comment_event(repo, 11, "stranger", command, 502))
    assert cloud.store.allowances(repo, 11, head) == [] and len(cloud.github.comments) == 2

    # a write collaborator's sign-off flips the same Check Run to success
    r = github_post(cloud.client, "issue_comment", comment_event(repo, 11, "maintainer", "thanks!\n" + command, 503))
    assert r.status_code == 202
    passing = cloud.github.check_for(repo, 11)
    assert passing["id"] == failing["id"] and passing["conclusion"] == "success"
    assert passing["output"]["title"] == "Passed with 1 human sign-off"
    summary = passing["output"]["summary"]
    assert "signed off by @maintainer" in summary and "@maintainer (write)" in summary and "zero-amount trial" in summary
    assert "Gate C" in summary and "amount <= 0" in summary  # the regression stays on the record
    assert len(cloud.github.comments) == 2  # no reply needed for an accepted sign-off
    [allowance] = cloud.store.allowances(repo, 11, head)
    assert (allowance["actor"], allowance["permission"], allowance["path"], allowance["symbol"]) == \
        ("maintainer", "write", "billing.py", "charge")

    # the receipt: fetched over HTTP and verified against the published public key
    receipt_id = cloud.store.check_run(repo, 11, head)["receipt_id"]
    url = f"{CLOUD_URL}/v1/receipts/{receipt_id}.intoto.json"
    assert url in summary
    got = cloud.client.get(f"/v1/receipts/{receipt_id}.intoto.json")
    assert got.status_code == 200
    envelope = got.json()
    key_response = cloud.client.get("/.well-known/stepcheck-pubkey.pem")
    assert key_response.status_code == 200 and key_response.text.startswith("-----BEGIN PUBLIC KEY-----")
    public_pem = key_response.text
    statement = verify_receipt_independently(envelope, public_pem)
    assert statement == signing.verify_envelope(envelope, public_pem)
    assert envelope["payloadType"] == "application/vnd.in-toto+json"
    assert envelope["signatures"][0]["keyid"] == cloud.client.get("/health").json()["keyid"]
    assert len(base64.b64decode(envelope["signatures"][0]["sig"])) == 64  # an Ed25519 signature, not a digest
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"] == "https://stepcheck.dev/attestation/v1"
    assert {"name": f"git+https://github.com/{repo}", "digest": {"gitCommit": head}} in statement["subject"]
    file_subject = next(s for s in statement["subject"] if s["name"] == "billing.py")
    assert file_subject["digest"]["sha256"] == hashlib.sha256(GUARD_DROP.encode()).hexdigest()
    predicate = statement["predicate"]
    assert (predicate["verdict"], predicate["pullRequest"], predicate["headSha"]) == ("approved", 11, head)
    [approved] = predicate["regressions"]
    assert approved["symbol"] == "charge" and approved["gate"] == "C"
    assert approved["approvedBy"]["login"] == "maintainer" and approved["approvedBy"]["reason"] == "zero-amount trial"
    assert any("amount <= 0" in g for g in approved["guardsRemoved"])

    # a tampered payload, or another key, does not verify
    forged = dict(envelope, payload=base64.b64encode(
        base64.b64decode(envelope["payload"]).replace(b'"approved"', b'"pass"')).decode())
    with pytest.raises(signing.InvalidEnvelope):
        signing.verify_envelope(forged, public_pem)
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with pytest.raises(signing.InvalidEnvelope):
        signing.verify_envelope(envelope, other)
    assert cloud.client.get("/v1/receipts/" + "0" * 32 + ".intoto.json").status_code == 404

    # the sign-off is scoped to that head: a new commit with the same drop is blocked again
    cloud.github.add_pr(repo, 11, {"billing.py": (BEFORE, GUARD_DROP + "\n# rebased\n")})
    github_post(cloud.client, "pull_request", pr_event(cloud.github, repo, 11, "synchronize"))
    assert cloud.github.check_for(repo, 11)["conclusion"] == "failure"


def test_a_sign_off_for_one_symbol_does_not_wave_through_a_second_drop_in_the_same_file(cloud):
    repo = "acme/shop"
    check = open_pr(cloud, repo, 12, {"billing.py": (BEFORE, TWO_DROPS)})
    assert check["conclusion"] == "failure" and check["output"]["title"] == "2 silent regressions blocked"
    cloud.github.permissions[(repo, "owner")] = "admin"
    github_post(cloud.client, "issue_comment", comment_event(
        repo, 12, "owner", '/stepcheck allow billing.py charge --reason "trial amounts"', 601))
    half = cloud.github.check_for(repo, 12)
    assert half["conclusion"] == "failure" and half["output"]["title"] == "1 silent regression blocked"
    assert "signed off by @owner" in half["output"]["summary"] and "`refund`" in half["output"]["summary"]
    # a file-level sign-off (no symbol) covers the rest
    github_post(cloud.client, "issue_comment", comment_event(
        repo, 12, "owner", '/stepcheck allow billing.py --reason "refunds are checked upstream now"', 602))
    assert cloud.github.check_for(repo, 12)["conclusion"] == "success"
    # a malformed command records nothing and is answered with the usage
    github_post(cloud.client, "issue_comment", comment_event(repo, 12, "owner", "/stepcheck allow billing.py charge", 603))
    assert len(cloud.store.allowances(repo, 12, check["head_sha"])) == 2
    assert "--reason" in cloud.github.comments[-1]["body"]


def test_the_allow_command_grammar():
    assert parse_allow("nice work") is None
    cmd = parse_allow('cc @team\n  /stepcheck allow ./src/pay.ts Cart.total --reason "rounding moved to the API"\n')
    assert (cmd.path, cmd.symbol, cmd.reason) == ("src/pay.ts", "Cart.total", "rounding moved to the API")
    assert parse_allow("/stepcheck allow a.py --reason one two").reason == "one two"
    assert parse_allow("/stepcheck allow a.py f --reason “smart quotes”").reason == "smart quotes"
    for bad in ("/stepcheck", "/stepcheck deny a.py --reason x", "/stepcheck allow --reason x",
                "/stepcheck allow a.py f g --reason x", '/stepcheck allow a.py --reason ""', '/stepcheck allow a.py --reason "x'):
        with pytest.raises(AllowSyntaxError):
            parse_allow(bad)


# ------------------------------------------- 4. free public repos, trial, billing


def test_public_repositories_are_free_forever_with_the_footer(cloud):
    for n in range(1, 21):
        check = open_pr(cloud, "acme/oss", n, {"billing.py": (BEFORE, CLEAN + f"# {n}\n")})
        assert check["conclusion"] == "success" and check["output"]["summary"].endswith(FOOTER)
    inst = cloud.store.installation(INSTALL)
    assert inst["private_prs_used"] == 0 and inst["prs_evaluated"] == 20 and inst["tier"] == "free"


def test_private_pr_16_hits_the_trial_gate_and_a_signed_subscription_webhook_unlocks_it(cloud):
    repo = "acme/vault"
    for n in range(1, 16):
        check = open_pr(cloud, repo, n, {"billing.py": (BEFORE, CLEAN + f"# {n}\n")}, private=True)
        assert check["conclusion"] == "success"
        assert f"Free trial: {n} of 15 private pull requests used." in check["output"]["summary"]
        assert FOOTER not in check["output"]["summary"]
    assert cloud.store.installation(INSTALL)["private_prs_used"] == 15

    # a pull request already in the trial keeps being evaluated; the 16th is gated
    cloud.github.add_pr(repo, 3, {"billing.py": (BEFORE, GUARD_DROP)}, private=True)
    github_post(cloud.client, "pull_request", pr_event(cloud.github, repo, 3, "synchronize"))
    assert cloud.github.check_for(repo, 3)["conclusion"] == "failure"
    fetched_before = sum("/contents/" in p or "/git/blobs/" in p for _, p in cloud.github.requests)
    gated = open_pr(cloud, repo, 16, {"billing.py": (BEFORE, GUARD_DROP)}, private=True)
    assert gated["conclusion"] == "action_required"
    # gated on the file list alone: no source text of the pull request was fetched or judged
    assert sum("/contents/" in p or "/git/blobs/" in p for _, p in cloud.github.requests) == fetched_before
    checkout = f"{CLOUD_URL}/checkout?installation_id={INSTALL}&plan=solo"
    assert checkout in gated["output"]["summary"] and gated["details_url"] == checkout
    assert "$29/month" in gated["output"]["summary"]
    assert cloud.store.installation(INSTALL)["private_prs_used"] == 15  # the gated PR used nothing
    # a public repository of the same installation is still free
    assert open_pr(cloud, "acme/oss", 1, {"billing.py": (BEFORE, CLEAN)})["conclusion"] == "success"

    # the one-click link redirects to the merchant's checkout with the installation in the metadata
    r = cloud.client.get(f"/checkout?installation_id={INSTALL}&plan=solo", follow_redirects=False)
    assert r.status_code == 303
    target = urlsplit(r.headers["location"])
    assert (target.netloc, target.path) == ("checkout.dodopayments.com", "/buy/pdt_solo")
    assert parse_qs(target.query) == {"quantity": ["1"], "metadata_installation_id": [str(INSTALL)],
                                      "metadata_account_login": ["acme"], "metadata_plan": ["solo"]}
    assert cloud.client.get("/checkout?installation_id=1&plan=solo", follow_redirects=False).status_code == 404
    assert cloud.client.get(f"/checkout?installation_id={INSTALL}&plan=gold", follow_redirects=False).status_code == 400

    # the signed subscription webhook activates the entitlement and the gated check is re-run at once
    active = subscription_event("subscription.active", INSTALL, "solo", "active")
    r = billing_post(cloud.client, active, webhook_id="evt_active")
    assert r.status_code == 200 and r.json() == {"outcome": "applied", "installation_id": INSTALL, "status": "active", "tier": "solo"}
    inst = cloud.store.installation(INSTALL)
    assert (inst["tier"], inst["status"], inst["provider"], inst["subscription_id"]) == ("solo", "active", "dodo", "sub_123")
    unlocked = cloud.github.check_for(repo, 16)
    assert unlocked["id"] == gated["id"] and unlocked["conclusion"] == "failure"  # evaluated now: it drops a guard
    assert "Gate C" in unlocked["output"]["summary"] and "details_url" not in unlocked
    assert "Free trial" not in unlocked["output"]["summary"]

    # a re-run requested from the Checks tab works too, and later PRs are simply evaluated
    rerun = {"action": "rerequested", "installation": {"id": INSTALL}, "repository": {"full_name": repo},
             "check_run": {"id": gated["id"], "head_sha": gated["head_sha"], "pull_requests": []}}
    assert github_post(cloud.client, "check_run", rerun).status_code == 202
    assert cloud.github.check_for(repo, 16)["updates"] == 2
    assert open_pr(cloud, repo, 17, {"billing.py": (BEFORE, CLEAN)}, private=True)["conclusion"] == "success"
    assert cloud.store.installation(INSTALL)["private_prs_used"] == 15

    # the same delivery again changes nothing (idempotent), and neither does a late older event
    again = billing_post(cloud.client, active, webhook_id="evt_active")
    assert again.status_code == 200 and again.json()["outcome"] == "duplicate"
    cancelled = subscription_event("subscription.cancelled", INSTALL, "solo", "cancelled")
    r = billing_post(cloud.client, cancelled, webhook_id="evt_cancel", timestamp=int(time.time()) + 5)
    assert r.json()["outcome"] == "applied" and cloud.store.installation(INSTALL)["status"] == "cancelled"
    late = billing_post(cloud.client, active, webhook_id="evt_late", timestamp=int(time.time()) - 60)
    assert late.json()["outcome"] == "stale" and cloud.store.installation(INSTALL)["status"] == "cancelled"
    assert open_pr(cloud, repo, 18, {"billing.py": (BEFORE, CLEAN)}, private=True)["conclusion"] == "action_required"


def test_a_private_docs_or_config_pull_request_passes_without_using_a_trial_credit(cloud):
    repo = "acme/vault"
    docs_only = {"README.md": ("# Vault\n", "# Vault\n\nNow with docs.\n"), "deploy/values.yaml": ("replicas: 1\n", "replicas: 2\n"),
                 "tests/test_billing.py": ("def test_a():\n    assert True\n", "def test_a():\n    assert 1\n")}
    check = open_pr(cloud, repo, 1, docs_only, private=True)
    assert check["conclusion"] == "success" and check["output"]["title"] == "No supported source files modified"
    summary = check["output"]["summary"]
    assert summary.startswith("No supported source files modified — 0 trial credits used.")
    assert "Free trial:" not in summary and FOOTER not in summary and "guards audited" not in summary
    assert "3 changed files not judged" in summary
    assert cloud.store.installation(INSTALL)["private_prs_used"] == 0
    assert not any("/contents/" in p or "/git/blobs/" in p or "/compare/" in p for _, p in cloud.github.requests)
    receipt_id = cloud.store.check_run(repo, 1, check["head_sha"])["receipt_id"]  # still a signed pass, over the commit
    statement = signing.verify_envelope(cloud.client.get(f"/v1/receipts/{receipt_id}.intoto.json").json(),
                                        cloud.client.get("/.well-known/stepcheck-pubkey.pem").text)
    assert statement["predicate"]["filesJudged"] == 0 and len(statement["subject"]) == 1

    # the slot is taken only when the pull request gains a source file, and then only once
    cloud.github.add_pr(repo, 1, {**docs_only, "billing.py": (BEFORE, CLEAN)}, private=True)
    github_post(cloud.client, "pull_request", pr_event(cloud.github, repo, 1, "synchronize"))
    assert "Free trial: 1 of 15 private pull requests used." in cloud.github.check_for(repo, 1)["output"]["summary"]
    assert cloud.store.installation(INSTALL)["private_prs_used"] == 1

    # with the trial used up, a docs-only pull request still passes free while a source change is gated
    for n in range(100, 114):
        assert cloud.store.claim_trial_pr(INSTALL, repo, n, billing.FREE_PRIVATE_PRS)[0]
    assert cloud.store.installation(INSTALL)["private_prs_used"] == 15
    free = open_pr(cloud, repo, 2, {"README.md": ("a\n", "b\n")}, private=True)
    assert free["conclusion"] == "success" and "0 trial credits used" in free["output"]["summary"]
    assert open_pr(cloud, repo, 3, {"billing.py": (BEFORE, CLEAN)}, private=True)["conclusion"] == "action_required"
    assert cloud.store.installation(INSTALL)["private_prs_used"] == 15
    # a public docs-only pull request says the same without the trial wording
    public = open_pr(cloud, "acme/oss", 1, {"README.md": ("a\n", "b\n")})
    assert public["output"]["summary"].startswith("No supported source files modified.") and FOOTER in public["output"]["summary"]


# Payloads in the shape each merchant documents for a subscription webhook (identifiers are made up).
DODO_SUBSCRIPTION = {
    "business_id": "bus_P3mRkT9wQxL2",
    "type": "subscription.active",
    "timestamp": "2026-11-10T10:15:42.118Z",
    "data": {
        "payload_type": "Subscription",
        "subscription_id": "sub_8fKq2ZbN4mVx",
        "product_id": "pdt_solo_monthly",
        "status": "active",
        "quantity": 1,
        "currency": "USD",
        "recurring_pre_tax_amount": 2900,
        "tax_inclusive": False,
        "trial_period_days": 0,
        "payment_frequency_count": 1,
        "payment_frequency_interval": "Month",
        "subscription_period_count": 10,
        "subscription_period_interval": "Year",
        "created_at": "2026-11-10T10:15:40.004Z",
        "previous_billing_date": "2026-11-10T10:15:40.004Z",
        "next_billing_date": "2026-12-10T10:15:40.004Z",
        "cancel_at_next_billing_date": False,
        "cancelled_at": None,
        "on_demand": False,
        "addons": [],
        "customer": {"customer_id": "cus_Lm7Yt2", "name": "Ada Example", "email": "ada@example.com"},
        "billing": {"country": "US", "state": "CA", "city": "San Francisco", "street": "1 Example St", "zipcode": "94105"},
        "metadata": {"installation_id": "9001", "account_login": "acme", "plan": "solo"},
    },
}
POLAR_SUBSCRIPTION = {
    "type": "subscription.active",
    "timestamp": "2026-11-10T10:15:42.118Z",
    "data": {
        "id": "1dbfc517-0bbf-4301-9ba8-555ca42b9737",
        "created_at": "2026-11-10T10:15:40.004Z",
        "modified_at": "2026-11-10T10:15:42.000Z",
        "amount": 2900,
        "currency": "usd",
        "recurring_interval": "month",
        "status": "active",
        "current_period_start": "2026-11-10T10:15:40.004Z",
        "current_period_end": "2026-12-10T10:15:40.004Z",
        "cancel_at_period_end": False,
        "canceled_at": None,
        "started_at": "2026-11-10T10:15:40.004Z",
        "ends_at": None,
        "ended_at": None,
        "customer_id": "992fae2a-2a17-4b7a-8d9e-e287cf90131b",
        "product_id": "d8dd2de1-21b7-4a41-8bc3-ce909c0cfe23",
        "discount_id": None,
        "checkout_id": "e4b478fa-cd25-4253-9f1f-8a41e6370ede",
        "customer_cancellation_reason": None,
        "metadata": {"referenceId": "9001"},
        "customer": {"id": "992fae2a-2a17-4b7a-8d9e-e287cf90131b", "email": "ada@example.com", "name": "Ada Example"},
        "product": {"id": "d8dd2de1-21b7-4a41-8bc3-ce909c0cfe23", "name": "StepCheck Solo", "is_recurring": True},
    },
}


def _variant(event: dict, kind: str, **data) -> dict:
    return {**event, "type": kind, "data": {**event["data"], **data}}


def test_dodo_subscription_payloads_are_read_field_for_field():
    settings = Settings()
    change = billing.interpret(DODO_SUBSCRIPTION, settings)
    assert change == billing.SubscriptionChange(9001, "solo", "active", "sub_8fKq2ZbN4mVx", "acme")
    # the plan can also come from the product when the link carried only the installation
    by_product = _variant(DODO_SUBSCRIPTION, "subscription.active", metadata={"installation_id": "9001"}, product_id="pdt_team_monthly")
    assert billing.interpret(by_product, Settings(product_id_team="pdt_team_monthly")).tier == "team"
    assert billing.interpret(by_product, settings).status is None  # an activation that names no plan grants nothing
    # a cancellation scheduled for the next billing date keeps access; the terminal states end it
    scheduled = _variant(DODO_SUBSCRIPTION, "subscription.plan_changed", cancel_at_next_billing_date=True)
    assert billing.interpret(scheduled, settings).status == "active"
    assert billing.interpret(_variant(DODO_SUBSCRIPTION, "subscription.renewed"), settings).status == "active"
    for kind, status in (("subscription.cancelled", "cancelled"), ("subscription.expired", "expired"),
                         ("subscription.failed", "failed"), ("subscription.on_hold", "on_hold")):
        ended = billing.interpret(_variant(DODO_SUBSCRIPTION, kind, status=status, cancelled_at="2026-12-01T00:00:00Z"), settings)
        assert (ended.installation_id, ended.status, ended.subscription_id) == (9001, "cancelled", "sub_8fKq2ZbN4mVx"), kind
    # other Dodo events share the envelope and change no entitlement
    payment = {**DODO_SUBSCRIPTION, "type": "payment.succeeded", "data": {**DODO_SUBSCRIPTION["data"], "payload_type": "Payment"}}
    assert billing.interpret(payment, settings).status is None


def test_polar_subscription_payloads_are_read_field_for_field():
    solo_product = POLAR_SUBSCRIPTION["data"]["product_id"]
    settings = Settings(product_id_solo=solo_product)
    change = billing.interpret(POLAR_SUBSCRIPTION, settings)  # metadata.referenceId (camelCase), data.id, plan from the product
    assert change == billing.SubscriptionChange(9001, "solo", "active", "1dbfc517-0bbf-4301-9ba8-555ca42b9737", "")
    # the reference this service puts on its own links carries the plan, in either spelling of the key
    for metadata in ({"referenceId": "9001:team"}, {"reference_id": "9001:team"}, {"installation_id": "9001", "plan": "team"}):
        got = billing.interpret(_variant(POLAR_SUBSCRIPTION, "subscription.active", metadata=metadata), Settings())
        assert (got.installation_id, got.tier, got.status) == (9001, "team", "active"), metadata
    # cancelled at period end: still active, so access stays until Polar revokes it
    pending = _variant(POLAR_SUBSCRIPTION, "subscription.canceled", cancel_at_period_end=True, canceled_at="2026-11-20T00:00:00Z")
    assert billing.interpret(pending, settings).status == "active"
    assert billing.interpret(_variant(POLAR_SUBSCRIPTION, "subscription.uncanceled"), settings).status == "active"
    revoked = billing.interpret(_variant(POLAR_SUBSCRIPTION, "subscription.revoked", status="canceled"), settings)
    assert (revoked.installation_id, revoked.status) == (9001, "cancelled")
    for terminal in ("canceled", "unpaid", "incomplete_expired"):
        assert billing.interpret(_variant(POLAR_SUBSCRIPTION, "subscription.updated", status=terminal), settings).status == "cancelled"
    # a status that is neither live nor terminal changes nothing
    assert billing.interpret(_variant(POLAR_SUBSCRIPTION, "subscription.updated", status="past_due"), settings).status is None
    assert billing.interpret(_variant(POLAR_SUBSCRIPTION, "subscription.created", status="incomplete"), settings).status is None


def test_realistic_dodo_and_polar_deliveries_drive_the_entitlement_end_to_end(cloud):
    cloud.store.upsert_installation(INSTALL, "acme", "User")
    now = int(time.time())
    r = billing_post(cloud.client, DODO_SUBSCRIPTION, webhook_id="msg_dodo_1", timestamp=now)
    assert r.json() == {"outcome": "applied", "installation_id": INSTALL, "status": "active", "tier": "solo"}
    inst = cloud.store.installation(INSTALL)
    assert (inst["provider"], inst["subscription_id"], inst["tier"], inst["status"]) == ("dodo", "sub_8fKq2ZbN4mVx", "solo", "active")
    billing_post(cloud.client, _variant(DODO_SUBSCRIPTION, "subscription.cancelled", status="cancelled"),
                 webhook_id="msg_dodo_2", timestamp=now + 1)
    assert cloud.store.installation(INSTALL)["status"] == "cancelled"
    # the same customer comes back through Polar, whose link carried `<installation>:<plan>`
    polar = _variant(POLAR_SUBSCRIPTION, "subscription.active", metadata={"referenceId": f"{INSTALL}:solo"})
    r = billing_post(cloud.client, polar, key=POLAR_SECRET.encode(), webhook_id="msg_polar_1", timestamp=now + 2)
    assert r.json()["outcome"] == "applied"
    inst = cloud.store.installation(INSTALL)
    assert (inst["provider"], inst["subscription_id"], inst["status"]) == ("polar", "1dbfc517-0bbf-4301-9ba8-555ca42b9737", "active")


def test_an_organization_needs_the_team_plan(cloud):
    org, repo = 7700, "bigco/core"
    cloud.store.upsert_installation(org, "bigco", "Organization")
    for n in range(100, 115):
        assert cloud.store.claim_trial_pr(org, repo, n, billing.FREE_PRIVATE_PRS)[0]
    cloud.github.add_pr(repo, 1, {"billing.py": (BEFORE, CLEAN)}, private=True, owner_type="Organization")
    github_post(cloud.client, "pull_request", pr_event(cloud.github, repo, 1, installation=org))
    gated = cloud.github.check_for(repo, 1)
    assert gated["conclusion"] == "action_required" and "plan=team" in gated["details_url"]
    assert "$149/month" in gated["output"]["summary"] and "Team plan" in gated["output"]["summary"]
    # asking for solo is redirected to the team checkout
    r = cloud.client.get(f"/checkout?installation_id={org}&plan=solo", follow_redirects=False)
    assert urlsplit(r.headers["location"]).path == "/buy/pdt_team" and "metadata_plan=team" in r.headers["location"]
    # a solo subscription does not cover an Organization; a team one does
    billing_post(cloud.client, subscription_event("subscription.active", org, "solo", "active"), webhook_id="evt_o1")
    assert cloud.github.check_for(repo, 1)["conclusion"] == "action_required"
    billing_post(cloud.client, subscription_event("subscription.active", org, "team", "active"), webhook_id="evt_o2",
                 timestamp=int(time.time()) + 1)
    assert cloud.github.check_for(repo, 1)["conclusion"] == "success"


def test_polar_webhooks_verify_with_the_legacy_key_and_a_pending_cancellation_revokes_nothing(cloud):
    cloud.store.upsert_installation(INSTALL, "acme", "User")
    polar = lambda kind, status: {"type": kind, "data": {"id": "polar_sub_1", "status": status,  # noqa: E731
                                                          "metadata": {"reference_id": f"{INSTALL}:solo"}}}
    key = POLAR_SECRET.encode()
    r = billing_post(cloud.client, polar("subscription.active", "active"), key=key, webhook_id="p1")
    assert r.status_code == 200 and r.json()["outcome"] == "applied"
    inst = cloud.store.installation(INSTALL)
    assert (inst["tier"], inst["status"], inst["provider"]) == ("solo", "active", "polar")
    # cancelled at period end: Polar keeps the subscription active until it is revoked
    r = billing_post(cloud.client, polar("subscription.canceled", "active"), key=key, webhook_id="p2",
                     timestamp=int(time.time()) + 1)
    assert cloud.store.installation(INSTALL)["status"] == "active"
    r = billing_post(cloud.client, polar("subscription.revoked", "canceled"), key=key, webhook_id="p3",
                     timestamp=int(time.time()) + 2)
    assert r.json()["status"] == "cancelled" and cloud.store.installation(INSTALL)["status"] == "cancelled"
    # an event that names no installation is recorded and ignored
    r = billing_post(cloud.client, {"type": "payment.succeeded", "data": {}}, key=key, webhook_id="p4")
    assert r.status_code == 200 and r.json()["outcome"] == "ignored"


# --------------------------------------------------------------------- plumbing


def test_the_store_runs_in_wal_mode_and_persists_across_connections(tmp_path):
    path = tmp_path / "nested" / "cloud.db"
    store = Store(path)
    assert store.journal_mode() == "wal"
    store.upsert_installation(1, "acme", "Organization")
    assert store.claim_trial_pr(1, "acme/a", 1, 1) == (True, 1)
    assert store.claim_trial_pr(1, "acme/a", 1, 1) == (True, 1)  # the same PR again
    assert store.claim_trial_pr(1, "acme/a", 2, 1) == (False, 1)
    store.close()
    reopened = Store(path)
    inst = reopened.installation(1)
    assert (inst["account_login"], inst["account_type"], inst["private_prs_used"]) == ("acme", "Organization", 1)
    reopened.upsert_installation(1)  # an event without account details keeps them
    assert reopened.installation(1)["account_type"] == "Organization"
    reopened.close()


def test_a_production_service_refuses_to_start_without_a_signing_key(tmp_path, app_key):
    settings = Settings(cloud_db=str(tmp_path / "c.db"), require_signing_key=True)
    with pytest.raises(RuntimeError, match="STEPCHECK_SIGNING_KEY_PEM"):
        create_app(settings)
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    configured = Settings.from_env({"STEPCHECK_SIGNING_KEY_PEM": pem.replace("\n", "\\n"), "STEPCHECK_REQUIRE_SIGNING_KEY": "1",
                                    "STEPCHECK_CLOUD_DB": str(tmp_path / "c.db"), "STEPCHECK_JUDGE_WORKERS": "3"})
    assert configured.judge_workers == 3 and configured.require_signing_key is True
    with TestClient(create_app(configured)) as client:
        served = client.get("/.well-known/stepcheck-pubkey.pem").text
    assert served == signing.Signer.from_pem(pem).public_pem()
    with pytest.raises(ValueError, match="Ed25519"):
        signing.Signer.from_pem(app_key.pem)  # an RSA key is not a signing key


def test_worker_processes_return_the_same_verdicts_as_the_in_process_judge():
    transitions = [("billing.py", BEFORE, GUARD_DROP), ("clean.py", BEFORE, CLEAN),
                   ("pay.ts", "export function pay(n: number) {\n  if (n <= 0) {\n    throw new Error('bad');\n  }\n  return n;\n}\n",
                    "export function pay(n: number) {\n  return n;\n}\n"),
                   ("two.py", BEFORE, TWO_DROPS)]
    strip = lambda results: [{**r, "ms": 0} for r in results]  # noqa: E731
    inline = asyncio.run(Judge(workers=1).run(transitions))
    pooled_judge = Judge(workers=2, pool_threshold=2)
    try:
        pooled = asyncio.run(pooled_judge.run(transitions))
    finally:
        pooled_judge.close()
    assert strip(pooled) == strip(inline)
    assert [r["path"] for r in inline] == ["billing.py", "clean.py", "pay.ts", "two.py"]
    assert [bool(r["finding"]) for r in inline] == [True, False, True, True]
    assert inline[2]["finding"]["tier"] == "1"  # the dropped TypeScript guard is a silent regression too
