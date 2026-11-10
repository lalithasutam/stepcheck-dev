# StepCheck Cloud (Stage 2 MVP)

The hosted GitHub App: a pull-request firewall that publishes the **StepCheck Contract
Firewall** Check Run, a human override, Ed25519-signed provenance receipts, a free trial
and subscription billing.

It is isolated from the `stepcheck-dev` package. Nothing here ships in the wheel, nothing
under `backend/` imports it, and the service uses the published engine pinned in
`requirements.txt`.

## What it does

1. **Judges a pull request without cloning it.** The changed files come from the Pulls
   API, each file's text at the merge base from the Contents API and at the head from the
   Git Blobs API. Every supported source file (Python, TS/JS, Go, Rust, Java, C/C++;
   tests and generated files are skipped) goes through
   `StateKernel(ephemeral=True).judge_transition(path, before, after, run_probes=False)`
   via `retro.judge`, so the verdict is the one `stepcheck diff` gives. No repository
   code is executed.
2. **Publishes one Check Run per PR head** and updates it in place.

   | Conclusion | When |
   | --- | --- |
   | `success` | no silent regression, or every one is signed off |
   | `failure` | a Tier 1 silent regression without a sign-off (guard dropped or weakened, handler widened, body stubbed, decorator stripped) |
   | `action_required` | private repository, free trial used, no covering subscription |
   | `neutral` | the evaluation itself failed; the PR is not blocked |

   Structural removals (a whole symbol deleted) and files that do not parse are listed
   in the summary and do not fail the check.
3. **Human override.** A collaborator comments

   ```
   /stepcheck allow <path> [symbol] --reason "<why>"
   ```

   The service asks GitHub for the commenter's permission on the repository and accepts
   only `write` or `admin`. The sign-off is stored against that PR and head commit, so a
   new push needs a new sign-off. Without a symbol it covers the whole file. A file can
   lose guards in several symbols while the gates report only the first; every such
   symbol is listed and needs its own sign-off.
4. **Signs a receipt for every passing or approved PR.** An in-toto Statement v1
   (`predicateType` `https://stepcheck.dev/attestation/v1`) in a DSSE envelope signed with
   Ed25519. Subjects are the head commit and each judged file (SHA-256 and git blob id);
   the predicate records the verdict, the guards audited and every sign-off.

## Routes

| Route | Purpose |
| --- | --- |
| `POST /webhooks/github` | GitHub App webhooks; `X-Hub-Signature-256` verified in constant time |
| `POST /webhooks/billing` | Dodo Payments / Polar webhooks (Standard Webhooks signature, 5-minute replay window) |
| `GET /checkout?installation_id=&plan=solo\|team` | one-click redirect to the merchant's checkout |
| `GET /.well-known/stepcheck-pubkey.pem` | the Ed25519 public key |
| `GET /v1/receipts/{receipt_id}.intoto.json` | a signed receipt |
| `GET /health` | liveness and the signing key id |

## Verifying a receipt

```python
import base64, json, urllib.request
from cryptography.hazmat.primitives import serialization

base = "https://<your cloud host>"
envelope = json.load(urllib.request.urlopen(f"{base}/v1/receipts/<receipt_id>.intoto.json"))
key = serialization.load_pem_public_key(urllib.request.urlopen(f"{base}/.well-known/stepcheck-pubkey.pem").read())
payload = base64.b64decode(envelope["payload"])
kind = envelope["payloadType"].encode()
pae = b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)
key.verify(base64.b64decode(envelope["signatures"][0]["sig"]), pae)   # raises if forged
statement = json.loads(payload)
```

`cloud.signing.verify_envelope(envelope, public_pem)` does the same.

## Billing rules

- **Public repositories** are always free. Their Check Runs end with
  `Protected by StepCheck Contract Firewall`.
- **Private repositories**: the first 15 pull requests per installation are evaluated
  free. A pull request counts once, however often it is pushed, and one admitted to the
  trial stays in it.
- A pull request that changes no supported source file (docs, config, tests only) gets a
  `success` Check Run and uses no trial slot, also after the trial is used up. The slot
  is taken only once a source file has been judged.
- After that a subscription is required: **Solo, $29/month** for a personal account,
  **Team, $149/month** for an Organization (a Solo subscription does not cover an
  Organization). Without one the Check Run is `action_required` and links to `/checkout`.
- A verified `subscription.active` webhook activates the installation and re-runs every
  Check Run the gate was holding. Deliveries are deduplicated by `webhook-id`, and an
  event older than the last one applied is ignored.

## Configuration

| Variable | Meaning |
| --- | --- |
| `STEPCHECK_GITHUB_APP_ID` | the GitHub App's id |
| `STEPCHECK_GITHUB_PRIVATE_KEY_PEM` | the App's RSA private key (newlines may be written as `\n`) |
| `STEPCHECK_GITHUB_WEBHOOK_SECRET` | the App's webhook secret; unset means every GitHub webhook is rejected |
| `STEPCHECK_CLOUD_DB` | SQLite path (default `stepcheck-cloud.db`; `/data/stepcheck-cloud.db` in the image) |
| `STEPCHECK_CLOUD_URL` | the service's public base URL, used in checkout and receipt links |
| `STEPCHECK_SIGNING_KEY_PEM` | Ed25519 private key, PKCS#8 PEM |
| `STEPCHECK_REQUIRE_SIGNING_KEY` | `1` refuses to start without a signing key (set in the image) |
| `STEPCHECK_BILLING_PROVIDER` | `dodo` (default) or `polar`: how the checkout link carries metadata |
| `STEPCHECK_DODO_WEBHOOK_SECRET`, `STEPCHECK_POLAR_WEBHOOK_SECRET` | webhook signing secrets; either or both |
| `STEPCHECK_CHECKOUT_URL_SOLO`, `STEPCHECK_CHECKOUT_URL_TEAM` | the merchant's checkout link for each plan |
| `STEPCHECK_PRODUCT_ID_SOLO`, `STEPCHECK_PRODUCT_ID_TEAM` | optional: map a webhook's `product_id` to a plan when its metadata names none |
| `STEPCHECK_JUDGE_WORKERS` | worker processes for large PRs (default 1: judged in a thread) |

Generate a signing key:

```
openssl genpkey -algorithm ed25519 -out stepcheck-signing.pem
```

Without `STEPCHECK_SIGNING_KEY_PEM` the service signs with a key generated for that
process, which is only useful for development: its receipts stop verifying on restart.

## GitHub App settings

- **Webhook URL** `https://<host>/webhooks/github`, with the webhook secret.
- **Repository permissions**: Checks read & write, Contents read, Pull requests read &
  write (for the reply to a refused or malformed `/stepcheck` comment), Metadata read.
- **Events**: Pull request, Issue comment, Check run, Check suite.

## Merchant of record

Checkout links carry the installation so the webhook can be matched to it:

- **Dodo Payments**: the link gets `metadata_installation_id`, `metadata_account_login`
  and `metadata_plan` query parameters. Dodo's payment links also need `quantity` and
  `redirect_url`; put those in `STEPCHECK_CHECKOUT_URL_*`.
- **Polar**: the link gets `reference_id=<installation id>:<plan>`. A bare
  `<installation id>` works too when `STEPCHECK_PRODUCT_ID_*` maps the product to a plan.

| | Dodo Payments | Polar |
| --- | --- | --- |
| installation | `data.metadata.installation_id` | `data.metadata.referenceId` (`reference_id` also accepted) |
| plan | `data.metadata.plan`, else `data.product_id` | the `:<plan>` suffix of the reference, else `data.product_id` |
| subscription id | `data.subscription_id` | `data.id` |
| still entitled while | `data.status` is `active` (also with `cancel_at_next_billing_date`) | `data.status` is `active` or `trialing` (also after `subscription.canceled`) |
| revoked on | `subscription.cancelled` / `expired` / `failed` / `on_hold` with a terminal status | `subscription.revoked`, or status `canceled` / `unpaid` / `incomplete_expired` |

The webhook handler reads `data.metadata`, `data.status` and the subscription id. Events that
unambiguously grant or end access decide by type; `subscription.updated`,
`subscription.cancelled` and `subscription.canceled` decide by the subscription's
`status`, so a cancellation that keeps access until the period ends revokes nothing
until the subscription is no longer active.

Before going live, send a test-mode subscription through each provider you enable and
confirm the delivered payload carries the metadata where the handler reads it. The
signature scheme, header names and Polar's event names were checked against the
providers' documentation; the subscription payload fields were not fully documented
there and are covered only by this repository's offline tests.

## Run

```
pip install -r cloud/requirements.txt
uvicorn cloud.app:create_app --factory --port 8080
```

or

```
docker build -f cloud/Dockerfile -t stepcheck-cloud .
docker run -p 8080:8080 -v stepcheck-data:/data --env-file cloud.env stepcheck-cloud
```

Run one instance: the database is a local SQLite file.

## Tests

```
python -m pytest -q cloud/tests
```

Offline and end to end: the real service, engine, SQLite file and cryptography, with
GitHub's REST API faked behind `httpx.MockTransport`. The repository's `pytest -q`
(`testpaths = backend/tests`) does not collect them; `.github/workflows/cloud-ci.yml`
runs them on every change under `cloud/`, builds the image and smoke-tests the running
container (`/health`, the public key, an unsigned webhook refused, the engine judging a
transition inside the image).

## Known limits of the MVP

- Webhook work runs in the web process after the response. There is no queue or retry;
  a failed evaluation posts a `neutral` Check Run and the Checks tab's re-run retries it.
- At most 300 files per pull request are judged, and files over 1 MB are skipped.
- Added and deleted files are not judged (nothing to compare against).
- The trial counter and the entitlement are per installation, not per repository.
- No customer portal, seat counting or proration; the merchant handles payment and tax.
