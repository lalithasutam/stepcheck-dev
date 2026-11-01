// Built-in replay used when no gateway is reachable, so the Studio renders a
// real session end-to-end for review. Mirrors the backend fixture project.
import type { CostPoint, GateEvent, Graph, Telemetry } from "./types";

const AUTH_SRC = `import hashlib


def require_auth(fn):
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)
    return wrapper


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
`;

export const BILLING_OLD = `from auth import require_auth, check_permission


@require_auth
def charge(user: str, amount_cents: int) -> dict:
    # okf-invariant: "raise ValueError" in src
    if amount_cents <= 0:
        raise ValueError("amount must be positive")
    if not check_permission(user, "charge"):
        raise PermissionError(user)
    return {"user": user, "amount_cents": amount_cents, "status": "charged"}
`;

export const BILLING_STAGED = `from auth import require_auth, check_permission


def charge(user: str, amount_cents: int) -> dict:
    if amount_cents <= 0:
        raise ValueError("amount must be positive")
    return {"user": user, "amount_cents": amount_cents, "status": "charged"}
`;

export const demoGraph: Graph = {
  nodes: [
    {
      node_id: "auth",
      path: "auth.py",
      status: "LOCKED",
      locked: true,
      deps: [],
      exports: ["require_auth(fn)", "hash_token(token: str) -> str"],
      preserved_symbols: ["def require_auth", "def hash_token"],
      invariants: [],
      verified: 2,
      attestation: {
        payloadType: "application/vnd.stepcheck.okf-commit+json",
        payload: {
          node_id: "auth",
          path: "auth.py",
          sha256:
            "9c4f1e2ab0d85c7714febc1a7d10f3b6a8d20e5c4b1f0a9388d6c2e7514fa0d3",
          exports: ["require_auth(fn)", "hash_token(token: str) -> str"],
          turn: 2,
        },
        signatures: [
          {
            keyid: "stepcheck-deterministic-v1",
            sig: "4b7a0cf3d9e8125566aa31bc08fde94712c05ab6e3d8f14092b7c6a1d5e30f88",
          },
        ],
      },
      source: AUTH_SRC,
    },
    {
      node_id: "billing",
      path: "billing.py",
      status: "REJECTED",
      locked: false,
      deps: ["auth"],
      exports: ["charge(user: str, amount_cents: int) -> dict"],
      preserved_symbols: ["@require_auth", "def charge", "call:check_permission"],
      invariants: ['"raise ValueError" in src'],
      verified: 1,
      attestation: null,
      source: BILLING_OLD,
    },
    {
      node_id: "admin",
      path: "admin.py",
      status: "DIRTY_OMISSION_RISK",
      locked: false,
      deps: ["auth"],
      exports: ["admin_panel(user: str) -> str"],
      preserved_symbols: ["def admin_panel"],
      invariants: [],
      verified: 0,
      attestation: null,
      source: "from auth import hash_token\n\n\ndef admin_panel(user: str) -> str:\n    return hash_token(user)\n",
    },
    {
      node_id: "reports",
      path: "reports.py",
      status: "ACTIVE",
      locked: false,
      deps: ["billing"],
      exports: ["monthly_report(user: str) -> list"],
      preserved_symbols: ["def monthly_report", "call:charge"],
      invariants: [],
      verified: 0,
      attestation: null,
      source: "from billing import charge\n\n\ndef monthly_report(user: str) -> list:\n    return [charge(user, 100)]\n",
    },
  ],
  edges: [
    { source: "billing", target: "auth" },
    { source: "admin", target: "auth" },
    { source: "reports", target: "billing" },
  ],
};

export const demoTelemetry: Telemetry = {
  raw_bloated_tokens: 48210,
  compacted_okf_tokens: 7312,
  tokens_saved: 40898,
  dollars_saved: 0.1227,
  omissions_blocked: 1,
  turns: 14,
};

export const demoEvents: GateEvent[] = [
  {
    node_id: "auth",
    accepted: true,
    gate: null,
    error: null,
    subtype: null,
    dirtied: ["admin", "billing"],
    turn: 11,
  },
  {
    node_id: "billing",
    accepted: false,
    gate: "B",
    error:
      "preserved symbol '@require_auth' of 'billing' was silently dropped from the staged source",
    subtype: "INTRA_NODE_SYMBOL_DROPPED",
    dirtied: [],
    turn: 13,
  },
];

export const demoCost: CostPoint[] = Array.from({ length: 15 }, (_, i) => ({
  turn: i,
  raw: Math.round(60 * i * i + 320 * i),
  compacted: Math.round(480 * i + 120),
}));
