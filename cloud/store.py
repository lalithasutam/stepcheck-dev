"""SQLite persistence for StepCheck Cloud (WAL mode, one file at `STEPCHECK_CLOUD_DB`).

Tables
  installations   one row per GitHub App installation: account, trial counter,
                  subscription tier and status, catch telemetry
  trial_prs       the private pull requests that consumed the free trial (a PR counts once)
  check_runs      the Check Run published for a (repo, PR, head sha) and its last verdict
  allowances      human `/stepcheck allow` sign-offs, scoped to one PR head
  receipts        signed DSSE envelopes by receipt id
  webhook_events  billing webhook ids already handled (idempotency)

One connection, serialised by a lock: the service is a single process and every write
is a short transaction.
"""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS installations (
  installation_id      INTEGER PRIMARY KEY,
  account_login        TEXT NOT NULL DEFAULT '',
  account_type         TEXT NOT NULL DEFAULT 'User',
  private_prs_used     INTEGER NOT NULL DEFAULT 0,
  tier                 TEXT NOT NULL DEFAULT 'free',
  status               TEXT NOT NULL DEFAULT 'none',
  provider             TEXT,
  subscription_id      TEXT,
  entitlement_event_ts INTEGER NOT NULL DEFAULT 0,
  prs_evaluated        INTEGER NOT NULL DEFAULT 0,
  regressions_blocked  INTEGER NOT NULL DEFAULT 0,
  guards_audited       INTEGER NOT NULL DEFAULT 0,
  created_at           TEXT NOT NULL,
  updated_at           TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS trial_prs (
  installation_id INTEGER NOT NULL,
  repo            TEXT NOT NULL,
  pr_number       INTEGER NOT NULL,
  created_at      TEXT NOT NULL,
  PRIMARY KEY (installation_id, repo, pr_number)
);
CREATE TABLE IF NOT EXISTS check_runs (
  repo            TEXT NOT NULL,
  pr_number       INTEGER NOT NULL,
  head_sha        TEXT NOT NULL,
  installation_id INTEGER NOT NULL,
  check_run_id    INTEGER NOT NULL,
  conclusion      TEXT NOT NULL,
  receipt_id      TEXT,
  counted         INTEGER NOT NULL DEFAULT 0,
  updated_at      TEXT NOT NULL,
  PRIMARY KEY (repo, pr_number, head_sha)
);
CREATE INDEX IF NOT EXISTS check_runs_by_id ON check_runs (check_run_id);
CREATE TABLE IF NOT EXISTS allowances (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  repo       TEXT NOT NULL,
  pr_number  INTEGER NOT NULL,
  head_sha   TEXT NOT NULL,
  path       TEXT NOT NULL,
  symbol     TEXT,
  reason     TEXT NOT NULL,
  actor      TEXT NOT NULL,
  permission TEXT NOT NULL,
  comment_id INTEGER NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts (
  receipt_id TEXT PRIMARY KEY,
  repo       TEXT NOT NULL,
  pr_number  INTEGER NOT NULL,
  head_sha   TEXT NOT NULL,
  envelope   TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webhook_events (
  event_id    TEXT PRIMARY KEY,
  source      TEXT NOT NULL,
  event_type  TEXT NOT NULL,
  outcome     TEXT NOT NULL,
  received_at TEXT NOT NULL
);
"""


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).resolve().parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def journal_mode(self) -> str:
        with self._lock:
            return self._db.execute("PRAGMA journal_mode").fetchone()[0]

    @contextmanager
    def _tx(self):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")

    def _one(self, sql: str, args: tuple = ()) -> dict | None:
        with self._lock:
            row = self._db.execute(sql, args).fetchone()
        return dict(row) if row else None

    def _all(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, args).fetchall()]

    # ---------------------------------------------------------------- installations

    def upsert_installation(self, installation_id: int, account_login: str = "", account_type: str = "") -> dict:
        """Create the installation if it is new and refresh the account fields that are given."""
        now = _now()
        with self._tx() as db:
            db.execute(
                "INSERT INTO installations (installation_id, account_login, account_type, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT (installation_id) DO UPDATE SET "
                "account_login = CASE WHEN excluded.account_login != '' THEN excluded.account_login ELSE account_login END, "
                "account_type = CASE WHEN ? != '' THEN excluded.account_type ELSE account_type END, "
                "updated_at = excluded.updated_at",
                (installation_id, account_login, account_type or "User", now, now, account_type),
            )
        return self.installation(installation_id)

    def installation(self, installation_id: int) -> dict | None:
        return self._one("SELECT * FROM installations WHERE installation_id = ?", (installation_id,))

    def trial_status(self, installation_id: int, repo: str, pr_number: int, limit: int) -> tuple[bool, int]:
        """What `claim_trial_pr` would answer, without consuming anything."""
        with self._lock:
            used = self._db.execute("SELECT private_prs_used FROM installations WHERE installation_id = ?",
                                    (installation_id,)).fetchone()[0]
            seen = self._db.execute("SELECT 1 FROM trial_prs WHERE installation_id = ? AND repo = ? AND pr_number = ?",
                                    (installation_id, repo, pr_number)).fetchone()
        return bool(seen) or used < limit, used

    def claim_trial_pr(self, installation_id: int, repo: str, pr_number: int, limit: int) -> tuple[bool, int]:
        """(allowed, private PRs used). A pull request already in the trial stays in it;
        a new one is admitted only while fewer than `limit` have been used."""
        with self._tx() as db:
            used = db.execute("SELECT private_prs_used FROM installations WHERE installation_id = ?",
                              (installation_id,)).fetchone()[0]
            seen = db.execute("SELECT 1 FROM trial_prs WHERE installation_id = ? AND repo = ? AND pr_number = ?",
                              (installation_id, repo, pr_number)).fetchone()
            if seen:
                return True, used
            if used >= limit:
                return False, used
            db.execute("INSERT INTO trial_prs VALUES (?, ?, ?, ?)", (installation_id, repo, pr_number, _now()))
            db.execute("UPDATE installations SET private_prs_used = private_prs_used + 1, updated_at = ? "
                       "WHERE installation_id = ?", (_now(), installation_id))
            return True, used + 1

    def apply_subscription_event(self, event_id: str, source: str, event_type: str, *, installation_id: int | None,
                                 tier: str | None, status: str | None, subscription_id: str | None = None,
                                 event_ts: int = 0, account_login: str = "") -> str:
        """Record a billing webhook and apply its entitlement change in one transaction.

        Returns "duplicate" (this webhook id was handled before; nothing changes),
        "ignored" (the event carries no entitlement change or names no installation),
        "stale" (an older event arrived after a newer one) or "applied"."""
        now = _now()
        with self._tx() as db:
            if db.execute("SELECT 1 FROM webhook_events WHERE event_id = ?", (event_id,)).fetchone():
                return "duplicate"
            outcome = "ignored"
            if installation_id is not None and status is not None:
                db.execute("INSERT OR IGNORE INTO installations (installation_id, account_login, created_at, updated_at) "
                           "VALUES (?, ?, ?, ?)", (installation_id, account_login, now, now))
                held = db.execute("SELECT entitlement_event_ts FROM installations WHERE installation_id = ?",
                                  (installation_id,)).fetchone()[0]
                if event_ts < held:
                    outcome = "stale"
                else:
                    db.execute(
                        "UPDATE installations SET tier = COALESCE(?, tier), status = ?, provider = ?, "
                        "subscription_id = COALESCE(?, subscription_id), entitlement_event_ts = ?, updated_at = ? "
                        "WHERE installation_id = ?",
                        (tier, status, source, subscription_id, event_ts, now, installation_id),
                    )
                    outcome = "applied"
            db.execute("INSERT INTO webhook_events VALUES (?, ?, ?, ?, ?)", (event_id, source, event_type, outcome, now))
            return outcome

    # ------------------------------------------------------------------- check runs

    def check_run(self, repo: str, pr_number: int, head_sha: str) -> dict | None:
        return self._one("SELECT * FROM check_runs WHERE repo = ? AND pr_number = ? AND head_sha = ?",
                         (repo, pr_number, head_sha))

    def check_run_by_id(self, check_run_id: int) -> dict | None:
        return self._one("SELECT * FROM check_runs WHERE check_run_id = ? ORDER BY updated_at DESC", (check_run_id,))

    def gated_check_runs(self, installation_id: int) -> list[dict]:
        """Pull requests of an installation whose last Check Run is the trial gate."""
        return self._all("SELECT * FROM check_runs WHERE installation_id = ? AND conclusion = 'action_required' "
                         "ORDER BY updated_at", (installation_id,))

    def save_check_run(self, *, repo: str, pr_number: int, head_sha: str, installation_id: int, check_run_id: int,
                       conclusion: str, receipt_id: str | None = None, guards_audited: int = 0,
                       regressions_blocked: int = 0) -> None:
        """Remember the Check Run for a PR head. The first real verdict for a head (anything
        but the trial gate) adds its figures to the installation's telemetry once."""
        now = _now()
        with self._tx() as db:
            row = db.execute("SELECT counted FROM check_runs WHERE repo = ? AND pr_number = ? AND head_sha = ?",
                             (repo, pr_number, head_sha)).fetchone()
            counted = bool(row and row[0])
            count_now = not counted and conclusion in ("success", "failure")
            db.execute(
                "INSERT INTO check_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (repo, pr_number, head_sha) DO UPDATE SET "
                "check_run_id = excluded.check_run_id, conclusion = excluded.conclusion, receipt_id = excluded.receipt_id, "
                "counted = excluded.counted, updated_at = excluded.updated_at",
                (repo, pr_number, head_sha, installation_id, check_run_id, conclusion, receipt_id,
                 int(counted or count_now), now),
            )
            if count_now:
                db.execute("UPDATE installations SET prs_evaluated = prs_evaluated + 1, guards_audited = guards_audited + ?, "
                           "regressions_blocked = regressions_blocked + ?, updated_at = ? WHERE installation_id = ?",
                           (guards_audited, regressions_blocked, now, installation_id))

    # ------------------------------------------------------------------- allowances

    def add_allowance(self, *, repo: str, pr_number: int, head_sha: str, path: str, symbol: str | None, reason: str,
                      actor: str, permission: str, comment_id: int) -> bool:
        """False when this comment was recorded before (a redelivered webhook)."""
        with self._tx() as db:
            if db.execute("SELECT 1 FROM allowances WHERE comment_id = ?", (comment_id,)).fetchone():
                return False
            db.execute("INSERT INTO allowances (repo, pr_number, head_sha, path, symbol, reason, actor, permission, "
                       "comment_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (repo, pr_number, head_sha, path, symbol, reason, actor, permission, comment_id, _now()))
            return True

    def allowances(self, repo: str, pr_number: int, head_sha: str) -> list[dict]:
        return self._all("SELECT * FROM allowances WHERE repo = ? AND pr_number = ? AND head_sha = ? ORDER BY id",
                         (repo, pr_number, head_sha))

    # --------------------------------------------------------------------- receipts

    def save_receipt(self, receipt_id: str, repo: str, pr_number: int, head_sha: str, envelope: dict) -> None:
        with self._tx() as db:
            db.execute("INSERT OR REPLACE INTO receipts VALUES (?, ?, ?, ?, ?, ?)",
                       (receipt_id, repo, pr_number, head_sha, json.dumps(envelope, sort_keys=True), _now()))

    def receipt(self, receipt_id: str) -> dict | None:
        row = self._one("SELECT envelope FROM receipts WHERE receipt_id = ?", (receipt_id,))
        return json.loads(row["envelope"]) if row else None
