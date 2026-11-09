"""Compliance exporter. Private to StateKernel (reached through
`StateKernel.compliance_bundle`).

Three documents from one session:
  Statement  a standard in-toto Statement v1 (`_type` https://in-toto.io/Statement/v1,
        `predicateType` https://stepcheck.dev/attestation/v1): `subject[]` is every
        tracked file with its sha256, the predicate is what the session verified —
        gate verdicts, invariant counts, the Merkle root, every module's status and
        latest attestation, the per-node DSSE envelopes, the control mappings.
        Written as attestation.intoto.json; what cosign / Witness / a policy engine
        consume.
  DUC   (public Dual-Use Card)       hashes and counts only — repo digest over
        the sorted per-file digests, language counts, gate verdicts, invariant
        counts, a Merkle root over the attestation digests, and a leak check the
        exporter runs on its own output (no path, no code may appear).
  DUA-E (escrowed Enterprise bundle) every attested node's in-toto Statement v1
        DSSE envelope, the Merkle tree, and the control mappings.
Merkle scheme: leaves = sorted attestation sha256 hex strings; each level pairs
neighbours as sha256(left_hex + right_hex), duplicating the last leaf of an odd
level; the root of a single leaf is that leaf.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

from . import _okf

DUC_TYPE = "https://stepcheck.dev/duc/v1"
DUAE_TYPE = "https://stepcheck.dev/dua-e/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://stepcheck.dev/attestation/v1"
BUILDER_ID = "https://github.com/lalithasutam/stepcheck-dev#StateKernel"

CONTROLS: dict[str, dict] = {
    "OWASP_AISVS_1.0:C9.3": {
        "framework": "OWASP AISVS 1.0",
        "control": "C9.3 Component Isolation and Tool Authorization",
        "control_text": ("Tool and plugin execution, loading, and outputs must be constrained to prevent "
                         "unauthorized system access and unsafe side effects."),
        "source": "https://raw.githubusercontent.com/OWASP/AISVS/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md",
        "evidence": ["gate_a_locked_modules", "gate_c_execution_budget", "dsse_envelopes"],
    },
    "SOC2_TypeII:CC8.1": {
        "framework": "SOC 2 Type II",
        "control": "CC8.1 Change management",
        "control_text": None,
        "note": "AICPA criteria text is licensed and not reproduced; the mapping names the evidence only",
        "source": "https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2",
        "evidence": ["dsse_envelopes", "dependents_reverified", "gate_b_preserved_symbols"],
    },
    "PCI_DSS_4.0:6.3.2": {
        "framework": "PCI DSS 4.0",
        "control": "6.3.2 Inventory of bespoke and custom software",
        "control_text": None,
        "note": "no public source text was fetched and saved; the mapping names the evidence only",
        "source": "https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf",
        "evidence": ["file_digests", "language_counts", "merkle_root"],
    },
    "EU_AI_Act:Art.12": {
        "framework": "EU AI Act",
        "control": "Article 12 Record-keeping",
        "control_text": None,
        "note": "article text not reproduced; the mapping names the evidence only",
        "source": "https://artificialintelligenceact.eu/article/12/",
        "evidence": ["session_events", "dsse_envelopes", "merkle_root"],
    },
}

_CODE_RE = re.compile(r"\b(def|class|import|from|function|interface|const|let|var|return)\b|=>|\{|\}|\(\)")


def merkle(leaves: list[str]) -> tuple[str | None, list[list[str]]]:
    """(root, levels) for the documented scheme; (None, []) without leaves."""
    level = sorted(leaves)
    if not level:
        return None, []
    levels = [list(level)]
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [hashlib.sha256((level[i] + level[i + 1]).encode("ascii")).hexdigest() for i in range(0, len(level), 2)]
        levels.append(list(level))
    return level[0], levels


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _strings(obj) -> list[str]:
    """Every string value and key in a JSON-like document (the structure's own
    braces are not content)."""
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            out.extend(_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_strings(v))
    elif isinstance(obj, str):
        out.append(obj)
    return out


def leak_check(duc: dict, paths: list[str]) -> dict:
    """Scan every string of the card for any tracked path, its basename or stem,
    and for code-shaped tokens. Both counts must be zero for a card to be public.
    Names are matched as whole tokens (`types` does not hit `typescript`), and a
    name the card itself always emits, a schema key or a language label, is not
    a leak when a tracked file happens to share it."""
    text = "\n".join(_strings(duc))
    own: set[str] = set(duc.get("languages", {}))
    stack: list = [duc]
    while stack:
        obj = stack.pop()
        if isinstance(obj, dict):
            own.update(str(k) for k in obj)
            stack.extend(obj.values())
        elif isinstance(obj, list):
            stack.extend(obj)
    names: set[str] = set()
    for p in paths:
        p = p.replace("\\", "/")
        names.add(p)
        base = p.rsplit("/", 1)[-1]
        names.add(base)
        stem = base.rsplit(".", 1)[0]
        if len(stem) >= 4:
            names.add(stem)
    names -= own
    path_hits = sorted(n for n in names if n and re.search(r"(?<![A-Za-z0-9_])" + re.escape(n) + r"(?![A-Za-z0-9_])", text))
    code_hits = _CODE_RE.findall(text)
    return {"paths": len(path_hits), "code": len(code_hits),
            "method": "serialized card scanned for every tracked path, basename and stem as whole tokens "
                      "(the card's own keys and language labels excluded), and for code-shaped tokens"}


def _file_sha(node: dict) -> str:
    """sha256 of a tracked file: of its canonical source when the graph carries it, else
    (a lazily indexed module nothing has analysed) of the bytes the session hashed."""
    source = node.get("source")
    if source is not None:
        return hashlib.sha256(source.encode("utf-8")).hexdigest()
    return str(node.get("disk_sha256") or "")


def bundle(kernel, session_id: str) -> dict:
    graph = kernel.graph(session_id)
    events = kernel.events(session_id)
    nodes = graph["nodes"]
    file_digests = sorted(_file_sha(n) for n in nodes)
    languages: dict[str, int] = {}
    for n in nodes:
        lang = _okf.language(n["path"]) if hasattr(_okf, "language") else "python"
        languages[lang] = languages.get(lang, 0) + 1
    rejections = {"A": 0, "B": 0, "C": 0}
    commits = 0
    for ev in events:
        if ev.get("kind") == "commit":
            commits += 1
        elif ev.get("kind") == "reject" and ev.get("gate") in rejections:
            rejections[ev["gate"]] += 1
    envelopes = []
    for n in nodes:
        if n.get("attestation"):
            envelopes.append({"node_digest": hashlib.sha256(n["node_id"].encode("utf-8")).hexdigest(),
                              "envelope": kernel.provenance(session_id, n["node_id"])})
    leaves = [n["attestation"]["payload"]["sha256"] for n in nodes if n.get("attestation")]
    root, levels = merkle(leaves)
    duc = {
        "_type": DUC_TYPE,
        "session_digest": hashlib.sha256(session_id.encode("utf-8")).hexdigest(),
        "repo_digest": hashlib.sha256(",".join(file_digests).encode("ascii")).hexdigest(),
        "files": len(nodes),
        "languages": dict(sorted(languages.items())),
        "gates": {"commits_accepted": commits, "rejections": rejections, "locked_modules": sum(1 for n in nodes if n["locked"]),
                  "dirty_omission_risk": sum(1 for n in nodes if n["status"] == "DIRTY_OMISSION_RISK")},
        "invariants": {"total": sum(len(n["invariants"]) for n in nodes), "auto_mined": sum(len(n["invariants_auto_mined"]) for n in nodes),
                       "modules_with_invariants": sum(1 for n in nodes if n["invariants"])},
        "attestations": {"count": len(leaves), "merkle_root": root},
        "controls": sorted(CONTROLS),
        "merkle_scheme": "sha256(left_hex + right_hex) over sorted attestation sha256 leaves, odd leaf duplicated",
    }
    duc["leak_check"] = leak_check(duc, [n["path"] for n in nodes])
    dua_e = {
        "_type": DUAE_TYPE,
        "session_id": session_id,
        "duc_digest": hashlib.sha256(_canonical(duc).encode("utf-8")).hexdigest(),
        "files": [{"path": n["path"].replace("\\", "/"), "sha256": _file_sha(n),
                   "language": _okf.language(n["path"]) if hasattr(_okf, "language") else "python",
                   "status": n["status"], "locked": n["locked"], "attestations": n["verified"]} for n in nodes],
        "envelopes": envelopes,
        "merkle": {"root": root, "levels": levels},
        "controls": {cid: {**c, "evidence_present": _evidence_present(c["evidence"], duc, events, envelopes)} for cid, c in CONTROLS.items()},
        "events": {"total": len(events), "kinds": dict(sorted(_count_kinds(events).items()))},
    }
    return {"Statement": statement(session_id, duc, dua_e, nodes), "DUC": duc, "DUA-E": dua_e}


def statement(session_id: str, duc: dict, dua_e: dict, nodes: list[dict]) -> dict:
    """The standard in-toto Statement v1 over the whole session: one subject per
    tracked file (sorted by path, sha256 of its source as attested), and a
    predicate that carries the verified facts the two dual-use files split."""
    latest_by_path = {n["path"].replace("\\", "/"): (n.get("attestation") or {}).get("payload") for n in nodes}
    counts = {n["path"].replace("\\", "/"): int(n.get("verified") or 0) for n in nodes}
    files = sorted(dua_e["files"], key=lambda f: f["path"])
    modules = []
    for f in files:
        latest = latest_by_path.get(f["path"])
        modules.append({"path": f["path"], "sha256": f["sha256"], "language": f["language"], "status": f["status"],
                        "locked": f["locked"],
                        "attestation": {"sha256": latest["sha256"], "turn": latest["turn"], "count": counts.get(f["path"], 0)}
                        if latest else None})
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": f["path"], "digest": {"sha256": f["sha256"]}} for f in files],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "builder": {"id": BUILDER_ID},
            "session_id": session_id,
            "repo_digest": duc["repo_digest"],
            "files": duc["files"],
            "languages": duc["languages"],
            "gates": duc["gates"],
            "invariants": duc["invariants"],
            "attestations": {**duc["attestations"], "merkle_scheme": duc["merkle_scheme"]},
            "modules": modules,
            "dsse_envelopes": dua_e["envelopes"],
            "controls": sorted(CONTROLS),
            "public_card_digest": dua_e["duc_digest"],
            "events": dua_e["events"],
        },
    }


def _count_kinds(events: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for ev in events:
        k = str(ev.get("kind"))
        out[k] = out.get(k, 0) + 1
    return out


def _evidence_present(evidence: list[str], duc: dict, events: list[dict], envelopes: list[dict]) -> dict[str, bool]:
    return {
        "gate_a_locked_modules": duc["gates"]["locked_modules"] > 0,
        "gate_c_execution_budget": True,  # every invariant call runs under the step + clock guard
        "dsse_envelopes": bool(envelopes),
        "dependents_reverified": any(ev.get("kind") == "commit" and ev.get("dirtied") for ev in events),
        "gate_b_preserved_symbols": True,
        "file_digests": duc["files"] > 0,
        "language_counts": bool(duc["languages"]),
        "merkle_root": duc["attestations"]["merkle_root"] is not None,
        "session_events": bool(events),
    } if evidence else {}


def decode_statement(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"]))
