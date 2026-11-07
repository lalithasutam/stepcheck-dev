"""Telemetry math — the one place rate constants live (GLOSSARY: Telemetry terms).

Private implementation of StateKernel; reached only through get_telemetry().
Raw model: an unfirewalled agent re-reads the full source of every file touched
so far on every turn. A re-read more than CACHE_CLIFF_SECONDS after the previous
one bills at full input rate; inside the window it bills at CACHE_HIT_FRACTION.
"""
from __future__ import annotations

import math

USD_PER_MTOK_INPUT = 3.00  # Sonnet-class input rate
CACHE_HIT_FRACTION = 0.1
CACHE_CLIFF_SECONDS = 300.0


def compute(events: list[dict]) -> tuple[int, int, int]:
    """-> (raw_bloated_tokens, compacted_okf_tokens, turns).

    Events are the session's ordered checkout/commit records, each carrying
    `node_id`, `tokens` (what the firewall actually sent), `full_tokens`
    (the node's full-source size at that moment) and `at` (seconds; None means
    "same instant as the previous event").

    Only the read path is context: a turn is a checkout, and `compacted` is the
    frames checkouts returned to the agent. Commits — patches, whole-source
    writes, `sync` adoptions of bytes an agent's own tool wrote, and the in-kernel
    re-verification of dependents — charge nothing and add no turn; a commit
    only updates the size a later raw re-read of an already-read file costs.
    """
    raw = 0
    compacted = 0
    turns = 0
    touched: dict[str, int] = {}  # node_id -> latest full-source tokens
    last_read: dict[str, float] = {}
    clock = 0.0

    for ev in events:
        if ev["kind"] == "commit":
            if ev["node_id"] in touched:
                touched[ev["node_id"]] = ev["full_tokens"]
            if ev.get("at") is not None:
                clock = ev["at"]
            continue
        if ev["kind"] != "checkout":
            continue
        turns += 1
        at = ev["at"] if ev.get("at") is not None else clock
        clock = at
        compacted += ev["tokens"]
        touched[ev["node_id"]] = ev["full_tokens"]
        for node_id, full in touched.items():
            prev = last_read.get(node_id)
            if prev is None or (at - prev) > CACHE_CLIFF_SECONDS:
                raw += full
            else:
                raw += math.ceil(full * CACHE_HIT_FRACTION)
            last_read[node_id] = at

    return raw, compacted, turns


def dollars(tokens_saved: int) -> float:
    return tokens_saved * USD_PER_MTOK_INPUT / 1_000_000
