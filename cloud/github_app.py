"""The GitHub App: webhook verification, App authentication, the PR firewall and the
human override.

A pull request is judged without a clone. The changed files come from the Pulls API,
each file's text at the merge base from the Contents API and at the head from the Git
Blobs API; every supported source file's transition is run through the published engine
(`retro.judge`, which calls `StateKernel(ephemeral=True).judge_transition(path, before,
after, run_probes=False)` and classifies the verdict the way `stepcheck diff` does).
Nothing is written to disk and no code from the repository is executed.

Verdicts
  success          no silent regression, or every one signed off by a human reviewer
  failure          a Tier 1 silent regression (a guard dropped or weakened, a handler
                   widened, a body stubbed, a decorator stripped) without a sign-off
  action_required  a private repository past the free trial without a subscription
  neutral          the evaluation itself failed; the pull request is not blocked
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import hmac
import json
import logging
import shlex
import sys
import tempfile
import threading
import time
from concurrent.futures import ProcessPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from . import Settings, billing, signing
from .store import Store

log = logging.getLogger("stepcheck.cloud")

CHECK_NAME = "StepCheck Contract Firewall"
FOOTER = "Protected by StepCheck Contract Firewall"
MAX_FILES = 300  # files judged per pull request
MAX_FILE_BYTES = 1_000_000
FETCH_CONCURRENCY = 8
WRITE_PERMISSIONS = {"admin", "write"}
PR_ACTIONS = {"opened", "reopened", "synchronize", "ready_for_review"}

# ------------------------------------------------------------------ webhook signature


def verify_github_signature(secret: str, body: bytes, header: str | None) -> bool:
    """`X-Hub-Signature-256` over the raw body, compared in constant time. An unset
    secret verifies nothing."""
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected.encode("ascii"), header.encode("ascii", "ignore"))


# ----------------------------------------------------------------- App authentication


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def app_jwt(app_id: str, private_key_pem: str, now: float | None = None) -> str:
    """The RS256 JWT a GitHub App authenticates with (valid nine minutes, issued a
    minute in the past to absorb clock drift)."""
    issued = int(now if now is not None else time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = _b64url(json.dumps({"iat": issued - 60, "exp": issued + 540, "iss": str(app_id)}, separators=(",", ":")).encode())
    key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    signature = key.sign(f"{header}.{claims}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{claims}.{_b64url(signature)}"


class GitHubError(RuntimeError):
    def __init__(self, response: httpx.Response) -> None:
        super().__init__(f"GitHub {response.request.method} {response.request.url.path} -> {response.status_code}")
        self.status_code = response.status_code


class GitHubApp:
    """Installation access tokens (cached until a minute before they expire) and one
    HTTP session per operation."""

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings = settings
        self._transport = transport
        self._tokens: dict[int, tuple[str, float]] = {}

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._settings.github_api_url, transport=self._transport, timeout=20.0,
            headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                     "User-Agent": "stepcheck-cloud"})

    async def _token(self, http: httpx.AsyncClient, installation_id: int) -> str:
        held = self._tokens.get(installation_id)
        if held and held[1] - 60 > time.time():
            return held[0]
        jwt = app_jwt(self._settings.github_app_id, self._settings.github_private_key_pem)
        r = await http.post(f"/app/installations/{installation_id}/access_tokens", headers={"Authorization": f"Bearer {jwt}"})
        if r.status_code != 201:
            raise GitHubError(r)
        body = r.json()
        expires = dt.datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00")).timestamp()
        self._tokens[installation_id] = (body["token"], expires)
        return body["token"]

    @asynccontextmanager
    async def connect(self, installation_id: int):
        async with self._client() as http:
            token = await self._token(http, installation_id)
            yield GitHubSession(http, token)


class GitHubSession:
    """The REST calls the firewall makes, authenticated as one installation."""

    def __init__(self, http: httpx.AsyncClient, token: str) -> None:
        self._http = http
        self._auth = {"Authorization": f"Bearer {token}"}

    async def _send(self, method: str, url: str, *, ok: tuple[int, ...] = (200,), raw: bool = False, **kwargs) -> httpx.Response:
        headers = dict(self._auth)
        if raw:
            headers["Accept"] = "application/vnd.github.raw+json"
        r = await self._http.request(method, url, headers=headers, **kwargs)
        if r.status_code not in ok:
            raise GitHubError(r)
        return r

    async def pull(self, repo: str, number: int) -> dict:
        return (await self._send("GET", f"/repos/{repo}/pulls/{number}")).json()

    async def merge_base(self, repo: str, base_sha: str, head_sha: str) -> str:
        """The commit the pull request's diff is taken against; the base tip when the
        comparison is unavailable."""
        try:
            r = await self._send("GET", f"/repos/{repo}/compare/{base_sha}...{head_sha}", params={"per_page": 1})
            return r.json()["merge_base_commit"]["sha"]
        except (GitHubError, KeyError, TypeError):
            return base_sha

    async def pull_files(self, repo: str, number: int) -> list[dict]:
        files: list[dict] = []
        for page in range(1, 31):  # the API lists at most 3,000 files
            batch = (await self._send("GET", f"/repos/{repo}/pulls/{number}/files", params={"per_page": 100, "page": page})).json()
            files.extend(batch)
            if len(batch) < 100:
                break
        return files

    async def content_at(self, repo: str, path: str, ref: str) -> bytes | None:
        """A file's raw bytes at a revision (Contents API); None when it does not exist there."""
        r = await self._send("GET", f"/repos/{repo}/contents/{quote(path, safe='/')}", params={"ref": ref}, raw=True, ok=(200, 404))
        return r.content if r.status_code == 200 else None

    async def blob(self, repo: str, sha: str) -> bytes | None:
        """A blob's raw bytes (Git Blobs API)."""
        r = await self._send("GET", f"/repos/{repo}/git/blobs/{sha}", raw=True, ok=(200, 404))
        return r.content if r.status_code == 200 else None

    async def publish_check(self, repo: str, check_run_id: int | None, payload: dict) -> int:
        if check_run_id is None:
            return (await self._send("POST", f"/repos/{repo}/check-runs", json=payload, ok=(201,))).json()["id"]
        body = {k: v for k, v in payload.items() if k != "head_sha"}
        return (await self._send("PATCH", f"/repos/{repo}/check-runs/{check_run_id}", json=body)).json()["id"]

    async def permission(self, repo: str, username: str) -> str:
        """The collaborator permission GitHub reports: admin, write, read or none."""
        r = await self._send("GET", f"/repos/{repo}/collaborators/{quote(username, safe='')}/permission", ok=(200, 404))
        return r.json().get("permission", "none") if r.status_code == 200 else "none"

    async def comment(self, repo: str, number: int, body: str) -> None:
        await self._send("POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body}, ok=(201,))


# ------------------------------------------------------------------------- the engine

_ENGINE = None
_JUDGE_LOCK = threading.Lock()  # the engine's analysis caches are module globals without locks
_JUDGE_ROOT = Path(tempfile.gettempdir()) / "stepcheck-cloud-no-project"  # never created: no cache, no root package


def _engine():
    """`retro` and `StateKernel` from the installed `stepcheck-dev` (its modules import
    each other by their bare names, so the package directory goes on the path)."""
    global _ENGINE
    if _ENGINE is None:
        import backend

        package_dir = str(Path(backend.__file__).resolve().parent)
        if package_dir not in sys.path:
            sys.path.append(package_dir)
        import retro
        from kernel import StateKernel

        _ENGINE = (retro, StateKernel)
    return _ENGINE


def judgeable(path: str) -> bool:
    """A supported source file (Python, TS/JS, Go, Rust, Java, C/C++) that is neither
    generated nor a test."""
    retro, _ = _engine()
    return retro.supported(path) and not retro.is_test_path(path)


def judge_file(path: str, before: str, after: str) -> dict:
    """One file's transition through Gates A/B/C, structurally (no probe is mined or run)."""
    retro, StateKernel = _engine()
    with _JUDGE_LOCK:
        kernel = StateKernel(ephemeral=True)
        started = time.perf_counter()
        try:
            guards = len(retro.contract(kernel, path, before, _JUDGE_ROOT, False))
        except Exception:  # noqa: BLE001 - the base text does not parse: nothing on record to audit
            guards = 0
        row = retro.judge(kernel, _JUDGE_ROOT, path, before, after, run_probes=False)
        finding = None
        if row is not None:
            finding = {"tier": row["tier"], "gate": row["gate"], "subtype": row.get("subtype"), "symbol": row["symbol"],
                       "message": row["message"], "guards_removed": [], "guards_added": []}
            if row["tier"] in ("1", "2"):
                removed, added = retro.guard_diff(kernel, path, before, after, _JUDGE_ROOT, False)
                finding["guards_removed"], finding["guards_added"] = removed, added
        return {"path": path, "guards": guards, "finding": finding, "ms": round((time.perf_counter() - started) * 1000, 1)}


def _judge_batch(items: list[tuple[int, str, str, str]]) -> list[tuple[int, dict]]:
    return [(index, judge_file(path, before, after)) for index, path, before, after in items]


class Judge:
    """Runs the transitions of one pull request: in a worker thread for a small one, across
    worker processes (as `stepcheck retro` does) once `workers` > 1 and the pull request
    has at least `pool_threshold` files."""

    def __init__(self, workers: int = 1, pool_threshold: int = 8) -> None:
        self.workers = max(1, int(workers))
        self.pool_threshold = pool_threshold
        self._pool: ProcessPoolExecutor | None = None

    async def run(self, transitions: list[tuple[str, str, str]]) -> list[dict]:
        items = [(i, *t) for i, t in enumerate(transitions)]
        if self.workers > 1 and len(items) >= self.pool_threshold:
            if self._pool is None:
                self._pool = ProcessPoolExecutor(max_workers=self.workers)
            loop = asyncio.get_running_loop()
            chunks = [items[k::self.workers] for k in range(self.workers)]
            parts = await asyncio.gather(*(loop.run_in_executor(self._pool, _judge_batch, c) for c in chunks if c))
            done = [pair for part in parts for pair in part]
        else:
            done = await asyncio.to_thread(_judge_batch, items)
        return [result for _, result in sorted(done, key=lambda pair: pair[0])]

    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None


def regressions_of(result: dict) -> list[dict]:
    """The silent regressions in one judged file, one per symbol.

    The gates stop at a file's first rejection, so the verdict names one symbol. Every
    other symbol of the file that lost a guard is listed too: a sign-off for one symbol
    must not wave through a second drop in the same file."""
    finding = result["finding"]
    if not finding or finding["tier"] != "1":
        return []
    by_symbol: dict[str, list[str]] = {finding["symbol"]: []}
    for guard in finding["guards_removed"]:
        parts = guard.split(":", 2)
        owner = parts[1] if len(parts) == 3 and parts[0] == "guard" else finding["symbol"]
        by_symbol.setdefault(owner, []).append(guard)
    out = []
    for symbol, guards in by_symbol.items():
        primary = symbol == finding["symbol"]
        out.append({"path": result["path"], "symbol": symbol, "gate": finding["gate"] if primary else "C",
                    "subtype": (finding["subtype"] if primary else None) or "GUARD",
                    "message": finding["message"] if primary else "a guard clause on record was removed",
                    "guards_removed": guards, "approval": None})
    return out


# ------------------------------------------------------------------ the human override


class AllowSyntaxError(ValueError):
    pass


@dataclass(frozen=True)
class AllowCommand:
    path: str
    symbol: str | None
    reason: str


ALLOW_USAGE = '`/stepcheck allow <path> [symbol] --reason "<why this contract change is intended>"`'


def parse_allow(body: str) -> AllowCommand | None:
    """The `/stepcheck allow` command in a comment; None when the comment holds no
    `/stepcheck` line; `AllowSyntaxError` when the line is not a well-formed command."""
    line = next((ln.strip() for ln in body.splitlines() if ln.strip().startswith("/stepcheck")), None)
    if line is None:
        return None
    try:
        tokens = shlex.split(line.replace("\u201c", '"').replace("\u201d", '"'))
    except ValueError as exc:
        raise AllowSyntaxError(str(exc)) from exc
    if len(tokens) < 2 or tokens[0] != "/stepcheck" or tokens[1] != "allow":
        raise AllowSyntaxError("the only command is `allow`")
    args = tokens[2:]
    reason = ""
    if "--reason" in args:
        at = args.index("--reason")
        reason = " ".join(args[at + 1:]).strip()
        args = args[:at]
    if not args or len(args) > 2:
        raise AllowSyntaxError("name the file and, optionally, one symbol")
    if not reason:
        raise AllowSyntaxError("a sign-off needs a --reason")
    path = args[0].replace("\\", "/")
    return AllowCommand(path[2:] if path.startswith("./") else path, args[1] if len(args) == 2 else None, reason)


def _covers(allowance: dict, regression: dict) -> bool:
    if allowance["path"] != regression["path"]:
        return False
    wanted = allowance["symbol"]
    return wanted is None or wanted == regression["symbol"] or wanted == regression["symbol"].rsplit(".", 1)[-1]


# ----------------------------------------------------------------------------- report


def _code(text: str) -> str:
    return "`" + text.replace("`", "'").replace("|", "\\|").replace("\n", " ") + "`"


def _guard_text(guard: str) -> str:
    parts = guard.split(":", 2)
    return parts[2] if len(parts) == 3 and parts[0] == "guard" else guard


def render(ev: dict) -> tuple[str, str]:
    """(title, Markdown summary) of a Check Run. The figures are what the engine measured
    for this pull request: guards audited, files judged, runtime. No cost estimate."""
    open_regs = [r for r in ev["regressions"] if not r["approval"]]
    signed = [r for r in ev["regressions"] if r["approval"]]
    if open_regs:
        title = f"{len(open_regs)} silent regression{'s' if len(open_regs) != 1 else ''} blocked"
    elif signed:
        sign_offs = len({r["approval"]["comment_id"] for r in signed})
        title = f"Passed with {sign_offs} human sign-off{'s' if sign_offs != 1 else ''}"
    elif ev["files_judged"] == 0:
        title = "No supported source files modified"
    else:
        title = "No contract regressions"
    files = ev["files_judged"]
    if files == 0:
        lines = ["No supported source files modified" + (" — 0 trial credits used" if ev.get("trial_untouched") else "") + "."]
    else:
        lines = [f"**{ev['guards_audited']:,} guards audited** across {files} file{'s' if files != 1 else ''} "
                 f"in **{ev['runtime_ms']:,} ms**."]
    if ev["regressions"]:
        lines += ["", "| Verdict | Gate | File | Symbol | Guard dropped or weakened |", "| --- | --- | --- | --- | --- |"]
        for r in ev["regressions"]:
            what = "<br>".join(_code(_guard_text(g)) for g in r["guards_removed"][:6]) or r["message"].replace("|", "\\|")
            verdict = f"signed off by @{r['approval']['actor']}" if r["approval"] else "**blocked**"
            lines.append(f"| {verdict} | Gate {r['gate']} · {r['subtype']} | {_code(r['path'])} | {_code(r['symbol'])} | {what} |")
    if signed:
        lines += ["", "**Human sign-off**"]
        seen = set()
        for r in signed:
            a = r["approval"]
            if a["comment_id"] not in seen:
                seen.add(a["comment_id"])
                scope = a["path"] + (f" · {a['symbol']}" if a["symbol"] else "")
                lines.append(f"- @{a['actor']} ({a['permission']}) allowed {_code(scope)}: {a['reason']}")
    if open_regs:
        lines += ["", "If a change is intended, a collaborator with write access can sign it off by commenting "
                  + ALLOW_USAGE + " on this pull request. A sign-off covers this commit only."]
    if ev["removals"]:
        lines += ["", f"{len(ev['removals'])} structural removal{'s' if len(ev['removals']) != 1 else ''} "
                  "(a whole symbol or signature deleted; reported, not blocking): "
                  + ", ".join(f"{_code(r['path'])} {_code(r['symbol'])}" for r in ev["removals"][:10])]
    if ev["unparsed"]:
        lines += ["", "Not judged (the file does not parse): " + ", ".join(_code(p) for p in ev["unparsed"][:10])]
    if ev["skipped"]:
        lines += ["", f"{ev['skipped']} changed file{'s' if ev['skipped'] != 1 else ''} not judged "
                  "(new, deleted, tests, generated, unsupported language or over the size limit)."]
    if ev.get("receipt_url"):
        lines += ["", f"Signed provenance (Ed25519 DSSE, in-toto Statement v1): [{ev['receipt_id']}]({ev['receipt_url']})"]
    if ev["decision"].reason == "trial":
        lines += ["", f"Free trial: {ev['decision'].trial_used} of {billing.FREE_PRIVATE_PRS} private pull requests used."]
    if ev["decision"].reason == "public":
        lines += ["", FOOTER]
    return title, "\n".join(lines)[:65000]


def render_gate(decision: billing.Decision, account_type: str) -> tuple[str, str]:
    plan = billing.PLANS[decision.plan]
    lines = [
        f"This installation has used its {billing.FREE_PRIVATE_PRS} free private pull request evaluations.",
        "",
        f"**[Subscribe to StepCheck {plan['label']} — ${plan['usd_per_month']}/month]({decision.checkout_url})** "
        "to keep the Contract Firewall on private repositories. This check re-runs as soon as the subscription is active.",
    ]
    if account_type == "Organization":
        lines += ["", "Organization accounts need the Team plan."]
    lines += ["", "Public repositories stay free."]
    return "Subscription required for private repositories", "\n".join(lines)


# --------------------------------------------------------------------------- firewall


def _iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Firewall:
    def __init__(self, settings: Settings, store: Store, signer: signing.Signer, github: GitHubApp, judge: Judge) -> None:
        self.settings, self.store, self.signer, self.github, self.judge = settings, store, signer, github, judge

    # ------------------------------------------------------------------- dispatch

    def wants(self, event: str, payload: dict) -> bool:
        """Whether a verified webhook starts any work."""
        action = payload.get("action")
        if event == "pull_request":
            return action in PR_ACTIONS
        if event == "issue_comment":
            return (action == "created" and "pull_request" in (payload.get("issue") or {})
                    and "/stepcheck" in ((payload.get("comment") or {}).get("body") or ""))
        if event in ("check_run", "check_suite"):
            return action == "rerequested"
        return event == "installation" and action == "created"

    async def handle(self, event: str, payload: dict) -> dict:
        installation_id = int(payload["installation"]["id"])
        if event == "installation":
            account = payload["installation"].get("account") or {}
            self.store.upsert_installation(installation_id, account.get("login", ""), account.get("type", ""))
            return {"status": "installed"}
        repo = payload["repository"]["full_name"]
        if event == "pull_request":
            pr = payload["pull_request"]
            return await self.evaluate(installation_id, repo, int(pr["number"]), pr=pr)
        if event == "issue_comment":
            return await self.handle_comment(installation_id, repo, payload)
        if event == "check_run":
            run = payload["check_run"]
            known = self.store.check_run_by_id(int(run["id"]))
            numbers = [known["pr_number"]] if known else [int(p["number"]) for p in run.get("pull_requests") or []]
        else:
            numbers = [int(p["number"]) for p in payload["check_suite"].get("pull_requests") or []]
        return {"status": "rerun", "results": [await self.evaluate(installation_id, repo, n) for n in numbers]}

    async def reevaluate_gated(self, installation_id: int) -> list[dict]:
        """Re-run every pull request the trial gate is holding (after a subscription activates)."""
        return [await self.evaluate(installation_id, row["repo"], row["pr_number"])
                for row in self.store.gated_check_runs(installation_id)]

    # ------------------------------------------------------------------- override

    async def handle_comment(self, installation_id: int, repo: str, payload: dict) -> dict:
        comment, number = payload["comment"], int(payload["issue"]["number"])
        actor = comment["user"]["login"]
        if comment["user"].get("type") == "Bot":
            return {"status": "ignored"}
        try:
            command = parse_allow(comment["body"])
        except AllowSyntaxError as exc:
            async with self.github.connect(installation_id) as gh:
                await gh.comment(repo, number, f"@{actor} StepCheck could not read that command ({exc}). Usage: {ALLOW_USAGE}")
            return {"status": "invalid"}
        if command is None:
            return {"status": "ignored"}
        async with self.github.connect(installation_id) as gh:
            permission = await gh.permission(repo, actor)
            if permission not in WRITE_PERMISSIONS:
                await gh.comment(repo, number, f"@{actor} only a collaborator with write or admin permission can sign off a "
                                 f"contract change; GitHub reports `{permission}` for you on this repository. Nothing was recorded.")
                return {"status": "rejected", "permission": permission}
            pr = await gh.pull(repo, number)
        self.store.add_allowance(repo=repo, pr_number=number, head_sha=pr["head"]["sha"], path=command.path,
                                 symbol=command.symbol, reason=command.reason, actor=actor, permission=permission,
                                 comment_id=int(comment["id"]))
        result = await self.evaluate(installation_id, repo, number, pr=pr)
        return {"status": "allowed", "permission": permission, "evaluation": result}

    # ----------------------------------------------------------------- evaluation

    async def evaluate(self, installation_id: int, repo: str, number: int, pr: dict | None = None) -> dict:
        """Judge one pull request head and publish (or update) its Check Run."""
        async with self.github.connect(installation_id) as gh:
            pr = pr or await gh.pull(repo, number)
            head_sha, base_sha = pr["head"]["sha"], pr["base"]["sha"]
            base_repo = pr["base"]["repo"]
            owner = base_repo.get("owner") or {}
            installation = self.store.upsert_installation(installation_id, owner.get("login", ""), owner.get("type", ""))
            private = bool(base_repo.get("private"))
            known = self.store.check_run(repo, number, head_sha)
            check_run_id = known["check_run_id"] if known else None

            async def gate(decision: billing.Decision) -> dict:
                title, summary = render_gate(decision, installation["account_type"])
                run_id = await self._publish(gh, repo, head_sha, check_run_id, "action_required", title, summary,
                                             details_url=decision.checkout_url)
                self.store.save_check_run(repo=repo, pr_number=number, head_sha=head_sha, installation_id=installation_id,
                                          check_run_id=run_id, conclusion="action_required")
                return {"conclusion": "action_required", "checkout_url": decision.checkout_url, "check_run_id": run_id}

            try:
                changed = await gh.pull_files(repo, number)
                candidates = [f for f in changed if f.get("status") in ("modified", "changed", "renamed") and f.get("sha")
                              and judgeable(f["filename"])][:MAX_FILES]
                # a preview: the trial slot is taken only once a source file has actually been judged
                decision = billing.decide(self.store, self.settings, installation, repo, number, private, consume=False)
                if candidates and not decision.allowed:
                    return await gate(decision)
                ev = await self._judge_pull(gh, repo, base_sha, head_sha, changed, candidates)
            except Exception:
                log.exception("evaluation of %s#%s failed", repo, number)
                await self._publish(gh, repo, head_sha, check_run_id, "neutral", "StepCheck could not evaluate this pull request",
                                    "The evaluation failed on StepCheck's side. The pull request is not blocked; "
                                    "re-run this check to try again.")
                raise
            if ev["files_judged"] == 0:
                # docs / config only: nothing to judge, nothing charged against the trial
                ev["trial_untouched"] = private and decision.reason != "subscribed"
                decision = billing.Decision(True, "public" if not private else "no_source")
            elif decision.reason == "trial":
                decision = billing.decide(self.store, self.settings, installation, repo, number, private)
                if not decision.allowed:  # another pull request took the last slot meanwhile
                    return await gate(decision)
            ev["decision"] = decision
            allowances = self.store.allowances(repo, number, head_sha)
            for regression in ev["regressions"]:
                for allowance in allowances:
                    if _covers(allowance, regression):
                        regression["approval"] = {k: allowance[k] for k in
                                                  ("actor", "permission", "reason", "path", "symbol", "comment_id", "created_at")}
                        break
            blocked = [r for r in ev["regressions"] if not r["approval"]]
            conclusion = "failure" if blocked else "success"
            receipt = None
            if conclusion == "success":
                envelope = self.signer.sign(self._statement(repo, number, pr, ev))
                receipt = signing.receipt_id(envelope)
                self.store.save_receipt(receipt, repo, number, head_sha, envelope)
                ev["receipt_id"] = receipt
                ev["receipt_url"] = f"{self.settings.cloud_url.rstrip('/')}/v1/receipts/{receipt}.intoto.json"
            title, summary = render(ev)
            check_run_id = await self._publish(gh, repo, head_sha, check_run_id, conclusion, title, summary)
        self.store.save_check_run(repo=repo, pr_number=number, head_sha=head_sha, installation_id=installation_id,
                                  check_run_id=check_run_id, conclusion=conclusion, receipt_id=receipt,
                                  guards_audited=ev["guards_audited"], regressions_blocked=len(blocked))
        return {"conclusion": conclusion, "check_run_id": check_run_id, "receipt_id": receipt,
                "guards_audited": ev["guards_audited"], "regressions": len(ev["regressions"]), "blocked": len(blocked)}

    async def _publish(self, gh: GitHubSession, repo: str, head_sha: str, check_run_id: int | None, conclusion: str,
                       title: str, summary: str, details_url: str | None = None) -> int:
        payload = {"name": CHECK_NAME, "head_sha": head_sha, "status": "completed", "conclusion": conclusion,
                   "completed_at": _iso_now(), "output": {"title": title, "summary": summary}}
        if details_url:
            payload["details_url"] = details_url
        return await gh.publish_check(repo, check_run_id, payload)

    async def _judge_pull(self, gh: GitHubSession, repo: str, base_sha: str, head_sha: str, changed: list[dict],
                          candidates: list[dict]) -> dict:
        started = time.perf_counter()
        merge_base = await gh.merge_base(repo, base_sha, head_sha) if candidates else base_sha
        gate = asyncio.Semaphore(FETCH_CONCURRENCY)

        async def fetch(f: dict):
            async with gate:
                before, after = await asyncio.gather(
                    gh.content_at(repo, f.get("previous_filename") or f["filename"], merge_base), gh.blob(repo, f["sha"]))
            if before is None or after is None or max(len(before), len(after)) > MAX_FILE_BYTES:
                return None
            retro, _ = _engine()
            before_text, after_text = retro.decode(before), retro.decode(after)
            if before_text is None or after_text is None or before_text == after_text:
                return None
            return f["filename"], before_text, after_text, hashlib.sha256(after).hexdigest(), f["sha"]

        fetched = [t for t in await asyncio.gather(*(fetch(f) for f in candidates)) if t is not None]
        results = await self.judge.run([(path, before, after) for path, before, after, _, _ in fetched])
        regressions = [r for result in results for r in regressions_of(result)]
        return {
            "merge_base": merge_base,
            "files": [{"path": path, "sha256": digest, "blob": blob} for path, _, _, digest, blob in fetched],
            "files_judged": len(fetched),
            "skipped": len(changed) - len(fetched),
            "guards_audited": sum(r["guards"] for r in results),
            "regressions": regressions,
            "removals": [{"path": r["path"], "symbol": r["finding"]["symbol"]} for r in results
                         if r["finding"] and r["finding"]["tier"] == "2"],
            "unparsed": [r["path"] for r in results if r["finding"] and r["finding"]["tier"] == "parse"],
            "runtime_ms": round((time.perf_counter() - started) * 1000),
        }

    def _statement(self, repo: str, number: int, pr: dict, ev: dict) -> dict:
        head_sha = pr["head"]["sha"]
        subjects = [{"name": f"git+https://github.com/{repo}", "digest": {"gitCommit": head_sha}}]
        subjects += [{"name": f["path"], "digest": {"sha256": f["sha256"], "gitBlob": f["blob"]}} for f in ev["files"]]
        approved = [r for r in ev["regressions"] if r["approval"]]
        predicate = {
            "verifier": {"name": CHECK_NAME, "engine": "stepcheck-dev", "mode": "structural (run_probes=False)"},
            "repository": repo,
            "pullRequest": number,
            "baseSha": pr["base"]["sha"],
            "mergeBaseSha": ev["merge_base"],
            "headSha": head_sha,
            "verdict": "approved" if approved else "pass",
            "filesJudged": ev["files_judged"],
            "guardsAudited": ev["guards_audited"],
            "regressions": [{"path": r["path"], "symbol": r["symbol"], "gate": r["gate"], "subtype": r["subtype"],
                             "guardsRemoved": r["guards_removed"],
                             "approvedBy": {"login": r["approval"]["actor"], "permission": r["approval"]["permission"],
                                            "reason": r["approval"]["reason"], "commentId": r["approval"]["comment_id"],
                                            "at": r["approval"]["created_at"]}} for r in approved],
            "evaluatedAt": _iso_now(),
        }
        return signing.statement(subjects, predicate)
