"""Team FinOps & governance ledger: one summary across every registered session.

Reads only the kernel's public surface (`graph`, `get_telemetry`, `events`) and
the per-user registry; prices come from `pricing`. Deterministic for a given
state: sessions are visited in sorted order and nothing is timestamped.
"""
from __future__ import annotations

from pathlib import Path

import hooks
import pricing
from kernel import StateKernel


def _arbitrage(event: dict) -> tuple[float, bool, bool]:
    """(usd saved, was a fast-tier turn, was escalated) for one Door 1 event."""
    routing = event.get("routing") or {}
    sent = float(event.get("sent_tokens") or 0)
    fast = pricing.price_for_model(routing.get("model") if routing.get("tier") == "fast" else routing.get("fast_model"))
    frontier = pricing.price_for_model(routing.get("frontier_model"))
    if routing.get("tier") == "fast" and not routing.get("escalated"):
        if fast is None or frontier is None:
            return 0.0, True, False
        return (frontier - fast) * sent / 1e6, True, False
    if routing.get("escalated"):
        return -((fast or 0.0) * sent / 1e6), False, True
    return 0.0, False, False


def summarize(kernel: StateKernel, roots: list[Path] | None = None, *, tier: str = "free",
              enforcement: bool = False) -> dict:
    wanted = {Path(r).resolve() for r in roots} if roots else None
    sessions = sorted((sid, Path(root).resolve()) for sid, root in hooks.registry().items())
    out = {
        "sessions": 0, "project_roots": [], "session_ids": [],
        "tokens": {"raw_bloated": 0, "compacted": 0, "saved": 0, "usd_saved_checkouts": 0.0, "turns": 0},
        "door1": {"turns": 0, "tokens_before": 0, "tokens_after": 0, "tokens_compacted": 0,
                  "cache_cliff_turns": 0, "cache_cliff_tokens_shielded": 0, "messages_pruned": 0, "messages_folded": 0},
        "arbitrage": {"fast_turns": 0, "escalations": 0, "usd_saved": 0.0},
        "gates": {"commits_accepted": 0, "regressions_caught": {"A": 0, "B": 0, "C": 0}, "omissions_blocked": 0},
        "omission_risk": {"flags_raised": 0, "re_verified": 0, "still_dirty": 0},
        "tier": {"enforcement": enforcement, "tier": tier, "label": pricing.TIERS[tier]["label"],
                 "capabilities": list(pricing.TIERS[tier]["capabilities"]), "price": pricing.tier_price(tier)},
        "pricing": {"usd_per_mtok_input": dict(pricing.USD_PER_MTOK_INPUT), "tiers": {t: pricing.tier_price(t) for t in pricing.TIER_ORDER}},
    }
    roots_seen: set[str] = set()
    for sid, root in sessions:
        if wanted is not None and root not in wanted:
            continue
        try:
            graph = kernel.graph(sid)
            tele = kernel.get_telemetry(sid)
            events = kernel.events(sid)
        except KeyError:
            continue
        out["sessions"] += 1
        out["session_ids"].append(sid)
        roots_seen.add(str(root))
        t = out["tokens"]
        t["raw_bloated"] += tele.raw_bloated_tokens
        t["compacted"] += tele.compacted_okf_tokens
        t["saved"] += tele.tokens_saved
        t["usd_saved_checkouts"] += tele.dollars_saved
        t["turns"] += tele.turns
        out["gates"]["omissions_blocked"] += tele.omissions_blocked
        commits_by_node: dict[str, list[int]] = {}
        for i, ev in enumerate(events):
            kind = ev.get("kind")
            if kind == "commit":
                out["gates"]["commits_accepted"] += 1
                commits_by_node.setdefault(ev.get("node_id"), []).append(i)
            elif kind == "reject":
                g = ev.get("gate")
                if g in out["gates"]["regressions_caught"]:
                    out["gates"]["regressions_caught"][g] += 1
            elif kind == "door1":
                d = out["door1"]
                d["turns"] += 1
                before, after = int(ev.get("tokens_before") or 0), int(ev.get("tokens_after") or 0)
                d["tokens_before"] += before
                d["tokens_after"] += after
                d["tokens_compacted"] += max(before - after, 0)
                d["messages_pruned"] += int(ev.get("pruned_messages") or 0)
                d["messages_folded"] += int(ev.get("folded_messages") or 0)
                if ev.get("cache_cliff"):
                    d["cache_cliff_turns"] += 1
                    d["cache_cliff_tokens_shielded"] += max(before - after, 0)
                usd, fast, escalated = _arbitrage(ev)
                out["arbitrage"]["usd_saved"] += usd
                out["arbitrage"]["fast_turns"] += int(fast)
                out["arbitrage"]["escalations"] += int(escalated)
        for i, ev in enumerate(events):
            if ev.get("kind") != "commit":
                continue
            for dep in ev.get("dirtied") or []:
                out["omission_risk"]["flags_raised"] += 1
                if any(j > i for j in commits_by_node.get(dep, [])):
                    out["omission_risk"]["re_verified"] += 1
        out["omission_risk"]["still_dirty"] += sum(1 for n in graph["nodes"] if n["status"] == "DIRTY_OMISSION_RISK")
    out["project_roots"] = sorted(roots_seen)
    for key in ("usd_saved_checkouts",):
        out["tokens"][key] = round(out["tokens"][key], 6)
    out["arbitrage"]["usd_saved"] = round(out["arbitrage"]["usd_saved"], 6)
    return out
