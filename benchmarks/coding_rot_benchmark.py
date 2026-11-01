"""50-turn coding-rot benchmark against the real StateKernel (Seam 1).

Simulates a long-running refactoring agent over a 6-module project, one
focused checkout + folded patch commit per turn (the agent works on AST
skeleton slices and submits append / replace_symbol ops), 6 minutes apart — a realistic big-refactor
cadence, so every re-read lands past the 5-minute prompt-cache cliff and the
unfirewalled baseline re-bills every touched file at full input rate. Three faults are injected:

  Turn 20 — omission: a rewrite of payments.py silently drops the protected
            @audit decorator          -> Gate B must reject (symbol dropped).
  Turn 25 — propagation: a legitimate exported-signature change on
            payments.charge() (new `currency` kwarg) — accepted, but its
            dependents api and workers flip to DIRTY_OMISSION_RISK and
            finalize_session() is blocked until T26/T27 re-verify them.
  Turn 35 — logical: a diff removes the positive-amount guard. payments.py
            has NO # okf-invariant comments; the guard was auto-mined into
            `call:charge(account="x", amount_cents=0) raises ValueError`
                                      -> Gate C must reject (LogicalError).
  Turn 36 — locked: a mutation of the pinned core.py module
                                      -> Gate A must reject (LOCKED).

Writes benchmarks/results.json (per-turn telemetry series + gate events) and
exits non-zero if any injected fault slips through.

Run:  python3 benchmarks/coding_rot_benchmark.py
"""
from __future__ import annotations

import ast
import json
import sys
import tempfile
import textwrap
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from kernel import OmissionError, StateKernel  # noqa: E402

TURNS = 50
SECONDS_PER_TURN = 360.0

CORE = textwrap.dedent('''\
    """Core utilities — pinned early and locked for the whole session."""


    def normalize(value: str) -> str:
        # okf-invariant: "value.strip()" in src
        return value.strip().lower()


    def clamp(n: int, low: int, high: int) -> int:
        return max(low, min(high, n))
    ''') + "".join(f"CORE_CONST_{i} = {i} * 7  # ballast\n" for i in range(40))

MODELS = textwrap.dedent('''\
    from core import normalize


    class Account:
        pass


    def account_key(name: str) -> str:
        return normalize(name)
    ''') + "".join(f"MODEL_ROW_{i} = '{'m' * 48}'\n" for i in range(60))

PAYMENTS = textwrap.dedent('''\
    from core import clamp
    from models import account_key


    def audit(fn):
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        return wrapper


    @audit
    def charge(account: str, amount_cents: int) -> dict:
        if amount_cents <= 0:
            raise ValueError("amount must be positive")
        key = account_key(account)
        return {"account": key, "amount_cents": clamp(amount_cents, 1, 10_000_00)}
    ''') + "".join(f"FEE_TABLE_{i} = {i} + 30\n" for i in range(50))

API = textwrap.dedent('''\
    from models import account_key
    from payments import charge


    def post_charge(account: str, cents: int) -> dict:
        return charge(account_key(account), cents)
    ''') + "".join(f"ROUTE_{i} = '/v1/r{i}'\n" for i in range(45))

WORKERS = textwrap.dedent('''\
    from payments import charge


    def retry_charge(account: str, cents: int) -> dict:
        return charge(account, cents)
    ''') + "".join(f"QUEUE_{i} = 'q{i}'\n" for i in range(45))

CLI = textwrap.dedent('''\
    from api import post_charge


    def main(argv: list) -> int:
        post_charge(argv[0], int(argv[1]))
        return 0
    ''') + "".join(f"FLAG_{i} = '--opt{i}'\n" for i in range(40))

PROJECT = {
    "core": CORE,
    "models": MODELS,
    "payments": PAYMENTS,
    "api": API,
    "workers": WORKERS,
    "cli": CLI,
}

ROTATION = ["models", "payments", "api", "workers", "cli"]

GUARD_BLOCK = (
    "    if amount_cents <= 0:\n"
    '        raise ValueError("amount must be positive")\n'
)


def symbol_source(source: str, name: str) -> str:
    """Verbatim text of one top-level def (decorators included) — what the agent
    sees in a focused checkout and rewrites in a replace_symbol op."""
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    node = next(s for s in tree.body if isinstance(s, ast.FunctionDef) and s.name == name)
    start = min([node.lineno] + [d.lineno for d in node.decorator_list])
    return "".join(lines[start - 1 : node.end_lineno])


def omission_patch(current: str) -> list[dict]:
    """Turn 20: the agent's rewrite of charge() silently drops @audit."""
    code = symbol_source(current, "charge").replace("@audit\n", "")
    return [{"op": "replace_symbol", "name": "charge", "code": code}]


def logical_patch(current: str) -> list[dict]:
    """Turn 35: the guard is gone, statement count intact, exports intact.
    payments.py carries no annotations at all — the invariant that catches
    this was auto-mined from the guard clause at init_session()."""
    code = symbol_source(current, "charge").replace(
        GUARD_BLOCK,
        "    if amount_cents == 0:\n"
        "        amount_cents = 1\n",
    )
    assert "raise ValueError" not in code
    return [{"op": "replace_symbol", "name": "charge", "code": code}]


def signature_patch(current: str) -> list[dict]:
    """Turn 25: legitimate exported-signature change — charge() grows a
    `currency` kwarg. Passes every gate; dirties api and workers."""
    code = symbol_source(current, "charge").replace(
        "def charge(account: str, amount_cents: int) -> dict:",
        'def charge(account: str, amount_cents: int, currency: str = "USD") -> dict:',
    ).replace(
        '    return {"account": key, "amount_cents": clamp(amount_cents, 1, 10_000_00)}',
        '    return {"account": key, "amount_cents": clamp(amount_cents, 1, 10_000_00), "currency": currency}',
    )
    assert "currency" in code
    return [{"op": "replace_symbol", "name": "charge", "code": code}]


def growth_patch(turn: int) -> list[dict]:
    """The agent's ordinary per-turn edit: append one private helper."""
    return [
        {
            "op": "append",
            "code": f"def _step_{turn}(x: int) -> int:\n    return x + {turn}\n",
        }
    ]


def _patch_target_before(current: str, patch: list[dict]) -> str:
    """What the agent saw before its edit: the replaced symbol, or nothing for an append."""
    op = patch[0]
    if op["op"] == "replace_symbol":
        return symbol_source(current, op["name"])
    return ""


def canonical(kernel: StateKernel, sid: str, node: str) -> str:
    return next(n["source"] for n in kernel.graph(sid)["nodes"] if n["node_id"] == node)


def run() -> dict:
    root = Path(tempfile.mkdtemp(prefix="stepcheck-bench-"))
    for name, src in PROJECT.items():
        (root / f"{name}.py").write_text(src, encoding="utf-8", newline="\n")

    kernel = StateKernel()
    sid = kernel.init_session(root)
    sources = dict(PROJECT)
    series: list[dict] = []
    turns: list[dict] = []
    gate_events: list[dict] = []
    caught = {
        "turn20_gateB": False,
        "turn25_dirty": False,
        "turn35_gateC": False,
        "turn36_gateA": False,
    }

    for turn in range(1, TURNS + 1):
        at = turn * SECONDS_PER_TURN
        if turn == 5:
            kernel.lock_node(sid, "core")
            gate_events.append({"turn": turn, "node": "core", "event": "LOCKED by user"})

        finalize_blocked = None
        if turn == 25:
            node, focus, patch = "payments", ["charge"], signature_patch(sources["payments"])
        elif turn == 26:
            node, focus, patch = "api", [], growth_patch(turn)
        elif turn == 27:
            node, focus, patch = "workers", [], growth_patch(turn)
        elif turn == 20:
            node, focus, patch = "payments", ["charge"], omission_patch(sources["payments"])
        elif turn == 35:
            node, focus, patch = "payments", ["charge"], logical_patch(sources["payments"])
        elif turn == 36:
            node, focus, patch = "core", [], [{"op": "append", "code": "EXTRA = 1\n"}]
        else:
            node, focus, patch = ROTATION[turn % len(ROTATION)], [], growth_patch(turn)

        payload = kernel.checkout(sid, node, focus=focus, at=at)
        kernel.record_draft(sid, node, f"turn {turn}: exploring {node} " + "…" * 200)
        before_snippet = _patch_target_before(sources[node], patch)
        verdict = kernel.commit(sid, node, patch=patch, at=at + 30.0)
        recovery = None

        if verdict.accepted:
            sources[node] = canonical(kernel, sid, node)
            if verdict.dirtied:
                # Mid-flight finalization must be refused while dependents are dirty.
                try:
                    kernel.finalize_session(sid)
                    finalize_blocked = False
                except OmissionError as exc:
                    finalize_blocked = exc.subtype == "INTER_NODE_DIRTY"
                if turn == 25 and verdict.dirtied == ["api", "workers"] and finalize_blocked:
                    caught["turn25_dirty"] = True
                gate_events.append(
                    {
                        "turn": turn,
                        "node": node,
                        "gate": "B",
                        "subtype": "INTER_NODE_DIRTY",
                        "propagation": True,
                        "error": (
                            f"exported signature changed → {', '.join(verdict.dirtied)} "
                            f"now DIRTY_OMISSION_RISK; finalize_session blocked until re-verified"
                        ),
                    }
                )
        else:
            gate_events.append(
                {
                    "turn": turn,
                    "node": node,
                    "gate": verdict.gate,
                    "subtype": getattr(verdict.error, "subtype", None),
                    "error": str(verdict.error),
                    "auto_mined": "auto-mined" in str(verdict.error),
                }
            )
            if turn == 20 and verdict.gate == "B":
                caught["turn20_gateB"] = True
            if turn == 35 and verdict.gate == "C":
                caught["turn35_gateC"] = True
            if turn == 36 and verdict.gate == "A":
                caught["turn36_gateA"] = True
            # The agent recovers on the spot with an ordinary growth patch.
            if node != "core":
                recovery = kernel.commit(sid, node, patch=growth_patch(turn), at=at + 45.0)
                assert recovery.accepted, f"recovery at turn {turn} failed: {recovery.error}"
                sources[node] = canonical(kernel, sid, node)

        t = kernel.get_telemetry(sid)
        graph = kernel.graph(sid)
        turns.append(
            {
                "turn": turn,
                "node": node,
                "focus": focus,
                "patch": patch,
                "checkout_tokens": payload.token_count,
                "accepted": verdict.accepted,
                "gate": verdict.gate,
                "subtype": getattr(verdict.error, "subtype", None),
                "error": str(verdict.error) if verdict.error else None,
                "dirtied": verdict.dirtied,
                "recovered": bool(recovery and recovery.accepted),
                "finalize_blocked": finalize_blocked,
                "before": before_snippet,
                "after": patch[0]["code"],
                "statuses": {n["node_id"]: n["status"] for n in graph["nodes"]},
                "locked": [n["node_id"] for n in graph["nodes"] if n["locked"]],
                "preserved_symbols": next(
                    n["preserved_symbols"] for n in graph["nodes"] if n["node_id"] == node
                ),
                "invariants": next(n["invariants"] for n in graph["nodes"] if n["node_id"] == node),
                "invariants_auto_mined": next(
                    n["invariants_auto_mined"] for n in graph["nodes"] if n["node_id"] == node
                ),
                "auto_mined_catch": bool(verdict.error) and "auto-mined" in str(verdict.error),
                "attestation": (verdict.attestation or (recovery.attestation if recovery else None)),
                "raw": t.raw_bloated_tokens,
                "compacted": t.compacted_okf_tokens,
                "dollars": round(t.dollars_saved, 4),
                "omissions_blocked": t.omissions_blocked,
            }
        )
        series.append(
            {
                "turn": turn,
                "raw": t.raw_bloated_tokens,
                "compacted": t.compacted_okf_tokens,
                "saved": t.tokens_saved,
                "dollars": round(t.dollars_saved, 4),
            }
        )

    final = kernel.get_telemetry(sid)
    results = {
        "turns": TURNS,
        "modules": sorted(PROJECT),
        "caught": caught,
        "gate_events": gate_events,
        "series": series,
        "turns": turns,
        "initial_sources": PROJECT,
        "edges": [
            {"source": n["node_id"], "target": d}
            for n in kernel.graph(sid)["nodes"]
            for d in n["deps"]
        ],
        "final": {
            "raw_bloated_tokens": final.raw_bloated_tokens,
            "compacted_okf_tokens": final.compacted_okf_tokens,
            "tokens_saved": final.tokens_saved,
            "dollars_saved": round(final.dollars_saved, 4),
            "omissions_blocked": final.omissions_blocked,
            "kernel_turns": final.turns,
            "savings_pct": round(100 * final.tokens_saved / final.raw_bloated_tokens, 1),
        },
    }
    out = Path(__file__).with_name("results.json")
    out.write_text(json.dumps(results, indent=2), encoding="utf-8", newline="\n")
    return results


def main() -> int:
    r = run()
    f = r["final"]
    print(f"StepCheck 50-turn coding-rot benchmark ({len(r['modules'])} modules)")
    print("-" * 64)
    for ev in r["gate_events"]:
        tag = ev.get("gate", "—")
        what = ev.get("subtype") or ev.get("event") or ev.get("error", "")
        if ev.get("propagation"):
            what = f"{ev['subtype']} (accepted; {ev['error']})"
        print(f"  T{ev['turn']:>2}  {ev['node']:<9} Gate {tag}: {what}")
    print("-" * 64)
    print(f"  raw bloated tokens : {f['raw_bloated_tokens']:>12,}")
    print(f"  compacted (OKF)    : {f['compacted_okf_tokens']:>12,}")
    print(f"  saved              : {f['tokens_saved']:>12,}  ({f['savings_pct']}%)")
    print(f"  dollars saved      : {f['dollars_saved']:>12.4f}  ($3.00/MTok input)")
    print(f"  omissions blocked  : {f['omissions_blocked']:>12}")
    ok = all(r["caught"].values())
    print("  injected faults    :", "ALL CAUGHT ✓" if ok else f"MISSED {r['caught']}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
