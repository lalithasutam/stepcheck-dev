"""Slice 28 — in-kernel re-verification of untouched dependents, and read-path-only
telemetry (Seam 1 and Seam 2; zero mocks).

1. A commit that only *adds* to a base module (a new helper) leaves its dependents'
   contract intact: the kernel re-runs Gates A/B/C on each untouched dependent
   against the new base, in memory, refreshes its attestation and leaves nothing
   DIRTY. A contract break (a signature a dependent uses changes) still dirties it.
2. Telemetry counts only what the read path returned to the agent (checkout
   frames): commits, `sync` adoptions and background re-verifications charge
   nothing to `compacted_okf_tokens` and add no turn to `raw_bloated_tokens`.
"""
from pathlib import Path

from fastapi.testclient import TestClient

BASE = "def area(w: int, h: int) -> int:\n    return w * h\n"
SHAPES = "from base import area\n\n\ndef square(n: int) -> int:\n    return area(n, n)\n"
REPORT = "import base\n\n\ndef line(w: int, h: int) -> str:\n    return str(base.area(w, h))\n"
HELPER = "def perimeter(w: int, h: int) -> int:\n    return 2 * (w + h)\n"
BREAK = "def area(w: int, h: int, d: int) -> int:\n    return w * h * d\n"


def _project(root: Path) -> Path:
    for name, src in (("base.py", BASE), ("shapes.py", SHAPES), ("report.py", REPORT)):
        (root / name).write_text(src, encoding="utf-8", newline="\n")
    return root


def _status(kernel, sid: str) -> dict[str, str]:
    return {n["node_id"]: n["status"] for n in kernel.graph(sid)["nodes"]}


def test_additive_helper_in_a_base_module_reverifies_clean_dependents_in_kernel(kernel, tmp_path):
    sid = kernel.init_session(_project(tmp_path))
    before = kernel.get_telemetry(sid)

    v = kernel.commit(sid, "base", patch=[{"op": "append", "code": HELPER}])
    assert v.accepted and v.dirtied == []
    assert v.reverified == ["report", "shapes"]          # `import base` and `from base import area`
    assert kernel.omission_report(sid) == {"dirty": [], "can_finalize": True}
    status = _status(kernel, sid)
    assert status["shapes"] == status["report"] == "VERIFIED"
    for dep in ("shapes", "report"):                     # a fresh attestation of the untouched bytes
        node = next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == dep)
        assert node["verified"] == 1 and node["attestation"]["payload"]["sha256"]
    assert (tmp_path / "shapes.py").read_text(encoding="utf-8") == SHAPES  # nothing rewritten

    after = kernel.get_telemetry(sid)                    # the write path charges no context tokens
    assert after.compacted_okf_tokens == before.compacted_okf_tokens
    assert after.raw_bloated_tokens == before.raw_bloated_tokens and after.turns == before.turns


def test_a_contract_break_still_dirties_the_dependents_that_rely_on_it(kernel, tmp_path):
    sid = kernel.init_session(_project(tmp_path))
    v = kernel.commit(sid, "base", patch=[{"op": "replace_symbol", "name": "area", "code": BREAK}])
    assert v.accepted and v.dirtied == ["report", "shapes"] and v.reverified == []
    assert kernel.omission_report(sid)["dirty"] == ["report", "shapes"]


def test_a_dependent_edited_behind_the_session_is_not_silently_reattested(kernel, tmp_path):
    sid = kernel.init_session(_project(tmp_path))
    (tmp_path / "shapes.py").write_text(SHAPES + "\n\nX = 1\n", encoding="utf-8", newline="\n")
    v = kernel.commit(sid, "base", patch=[{"op": "append", "code": HELPER}])
    assert v.accepted and v.reverified == ["report"] and v.dirtied == ["shapes"]


def test_telemetry_counts_checkout_frames_only_over_http(tmp_path):
    import server

    client = TestClient(server.app)
    sid = client.post("/v1/step/init", json={"project_root": str(_project(tmp_path))}).json()["session_id"]
    frame = client.post("/v1/step/checkout", json={"session_id": sid, "node_id": "base", "focus": []}).json()
    t0 = client.get(f"/v1/step/telemetry/{sid}").json()
    assert t0["turns"] == 1 and t0["compacted_okf_tokens"] == frame["token_count"]

    big = BASE + "".join(f"\n\ndef f{i}(x: int) -> int:\n    return x + {i}\n" for i in range(40))
    v = client.post("/v1/step/commit", json={"session_id": sid, "node_id": "base", "source": big}).json()
    assert v["accepted"] and v["reverified"] == ["report", "shapes"]
    t1 = client.get(f"/v1/step/telemetry/{sid}").json()
    assert (t1["turns"], t1["compacted_okf_tokens"], t1["raw_bloated_tokens"]) == (
        t0["turns"], t0["compacted_okf_tokens"], t0["raw_bloated_tokens"])
