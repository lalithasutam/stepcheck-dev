"""Slice 10 — real-world hardening: package trees, async defs, surgical patches,
session persistence (Seam 1 + Seam 2). Includes StepCheck hosting itself."""
import hashlib
import importlib
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kernel import OmissionError, StateKernel

BACKEND = Path(__file__).resolve().parents[1]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _node(kernel, sid, nid) -> dict:
    return next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == nid)


def _ids(kernel, sid) -> dict[str, str]:
    return {n["node_id"]: n["path"].replace("\\", "/") for n in kernel.graph(sid)["nodes"]}


def _replace(name: str, code: str) -> list[dict]:
    return [{"op": "replace_symbol", "name": name, "code": code}]


# ------------------------------------------------- 1. packages & duplicate stems

PKG_RULES = '''\
def check(amount: int) -> int:
    if amount <= 0:
        raise ValueError("amount must be positive")
    return amount
'''

PKG_INIT = '''\
from .rules import check


def charge(amount: int) -> dict:
    # okf-invariant: call:charge(0) raises ValueError
    return {"amount": check(amount)}
'''

SVC_API = '''\
from pkg import charge


def handle(amount: int) -> dict:
    return charge(amount)
'''

SVC_INIT = "from .api import handle\n"

APP = '''\
import svc


def main() -> dict:
    return svc.handle(5)
'''


def _package_project(root: Path) -> Path:
    _write(root / "pkg" / "__init__.py", PKG_INIT)
    _write(root / "pkg" / "rules.py", PKG_RULES)
    _write(root / "svc" / "__init__.py", SVC_INIT)
    _write(root / "svc" / "api.py", SVC_API)
    _write(root / "app.py", APP)
    return root


def test_duplicate_stems_disambiguate_while_unique_stems_stay_flat(kernel, tmp_path):
    sid = kernel.init_session(_package_project(tmp_path))

    assert _ids(kernel, sid) == {
        "app": "app.py",
        "pkg.__init__": "pkg/__init__.py",
        "rules": "pkg/rules.py",
        "svc.__init__": "svc/__init__.py",
        "api": "svc/api.py",
    }
    for nid in _ids(kernel, sid):
        assert (tmp_path / ".stepcheck" / "okf" / f"{nid}.md").is_file()
    deps = {n["node_id"]: n["deps"] for n in kernel.graph(sid)["nodes"]}
    assert deps == {
        "app": ["svc.__init__"],
        "pkg.__init__": ["rules"],
        "rules": [],
        "svc.__init__": ["api"],
        "api": ["pkg.__init__"],
    }


def test_flat_projects_keep_stem_node_ids(kernel, project):
    sid = kernel.init_session(project)
    assert set(_ids(kernel, sid)) == {"admin", "auth", "billing", "reports", "unrelated_sibling"}


def test_relative_imports_resolve_at_gate_c_and_gates_see_through_packages(kernel, tmp_path):
    sid = kernel.init_session(_package_project(tmp_path))

    # Gate C execs pkg/__init__.py, whose `from .rules import check` must resolve
    # against the canonical sources, not the filesystem.
    ok = kernel.commit(
        sid, "pkg.__init__",
        patch=[{"op": "append", "code": "def refund(amount: int) -> dict:\n    return {\"amount\": -check(amount)}\n"}],
    )
    assert ok.accepted, ok.error
    assert _sha(tmp_path / "pkg" / "__init__.py") == ok.attestation["payload"]["sha256"]

    bypass = kernel.commit(
        sid, "pkg.__init__",
        patch=_replace("charge", 'def charge(amount: int) -> dict:\n    return {"amount": amount}\n'),
    )
    assert not bypass.accepted and bypass.gate == "C"

    weak = kernel.commit(
        sid, "rules",
        patch=_replace("check", 'def check(amount: int) -> int:\n    if amount < 0:\n        raise ValueError("x")\n    return amount\n'),
    )
    assert weak.gate == "C" and "auto-mined" in str(weak.error)

    # svc/api.py does `from pkg import charge`: deleting charge breaks a dependent.
    gone = kernel.commit(sid, "pkg.__init__", patch=[{"op": "delete_symbol", "name": "charge"}], allow_deletion=True)
    assert gone.gate == "A" and "api" in str(gone.error)

    sig = kernel.commit(
        sid, "pkg.__init__",
        patch=_replace(
            "charge",
            'def charge(amount: int, currency: str = "usd") -> dict:\n'
            "    # okf-invariant: call:charge(0) raises ValueError\n"
            '    return {"amount": check(amount), "currency": currency}\n',
        ),
    )
    assert sig.accepted, sig.error
    assert sig.dirtied == ["api"]


def test_self_hosting_on_stepchecks_own_backend(kernel, tmp_path):
    real_kernel_bytes = (BACKEND / "kernel" / "__init__.py").read_bytes()
    root = tmp_path / "backend"
    shutil.copytree(BACKEND, root, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    sid = kernel.init_session(root)
    ids = _ids(kernel, sid)
    assert ids["__init__"] == "__init__.py"
    assert ids["kernel.__init__"] == "kernel/__init__.py"
    assert {"_gates", "_okf", "_sandbox", "server", "cli", "audit", "conftest"} <= set(ids)
    assert "kernel.__init__" in _node(kernel, sid, "server")["deps"]
    # Function-scoped (lazy) imports are dependencies too: `_compactor` and `_compliance`
    # are imported inside StateKernel methods.
    assert set(_node(kernel, sid, "kernel.__init__")["deps"]) == {
        "_gates", "_okf", "_telemetry", "_tokens", "_compactor", "_compliance"}

    frame = kernel.checkout(sid, "_gates", focus=["gate_b"])
    rendered = frame.rendered()
    assert "def gate_b(" in rendered and "INTRA_NODE_MASS_DELETION" in rendered
    assert "def gate_c(" in rendered and "tree = ast.parse(staged_source)" not in rendered
    assert frame.token_count < 4000 and not frame.auto_skeletonized

    dropped = kernel.commit(sid, "_gates", patch=[{"op": "delete_symbol", "name": "gate_b"}])
    assert dropped.gate == "B" and isinstance(dropped.error, OmissionError)

    # Gate C on a kernel module: the staged copy loads as `kernel._okf`, parent package included.
    assert 'call:module_name(path="") raises ValueError' in _node(kernel, sid, "_okf")["invariants_auto_mined"]
    weak = kernel.commit(
        sid, "_okf",
        patch=_replace(
            "module_name",
            "def module_name(path: str) -> str:\n"
            '    parts = path.replace("\\\\", "/").removesuffix(".py").split("/")\n'
            '    if parts[-1] == "__init__" and len(parts) > 1:\n'
            "        parts = parts[:-1]\n"
            '    return ".".join(parts)\n',
        ),
    )
    assert weak.gate == "C" and "auto-mined" in str(weak.error)

    # A verified commit to the package __init__ itself: `from . import _gates, _okf, …` resolves in the sandbox.
    assert 'call:StateKernel().graph("nope") raises KeyError' in _node(kernel, sid, "kernel.__init__")["invariants"]
    landed = kernel.commit(
        sid, "kernel.__init__",
        patch=[{"op": "append", "code": "def _slice10_probe() -> str:\n    return _DSSE_KEYID\n"}],
    )
    assert landed.accepted, landed.error
    assert _sha(root / "kernel" / "__init__.py") == landed.attestation["payload"]["sha256"]
    assert "_slice10_probe" in (root / "kernel" / "__init__.py").read_text(encoding="utf-8")

    # The real kernel was neither written nor swapped out from under the test process.
    import kernel as real_kernel

    assert (BACKEND / "kernel" / "__init__.py").read_bytes() == real_kernel_bytes
    assert type(kernel) is real_kernel.StateKernel and not hasattr(real_kernel, "_slice10_probe")


# ------------------------------------------------------------- 2. async parity

ASYNC_SRC = '''\
import asyncio


def audit(fn):
    return fn


@audit
async def charge(amount_cents: int, currency: str) -> dict:
    if amount_cents <= 0:
        raise ValueError("amount_cents must be positive")
    await asyncio.sleep(0)
    return {"amount_cents": amount_cents, "currency": currency}


# okf-invariant: raises(lambda: ns["refund"](-1), "ValueError")
async def refund(amount_cents: int) -> dict:
    if amount_cents <= 0:
        raise ValueError("refund must be positive")
    return {"amount_cents": -amount_cents}
'''

ASYNC_WEAK = (
    "@audit\nasync def charge(amount_cents: int, currency: str) -> dict:\n"
    "    if amount_cents < 0:\n"
    '        raise ValueError("amount_cents must be positive")\n'
    '    return {"amount_cents": amount_cents, "currency": currency}\n'
)


def test_async_def_is_mined_sliced_and_preserved(kernel, tmp_path):
    _write(tmp_path / "pay.py", ASYNC_SRC)
    sid = kernel.init_session(tmp_path)
    node = _node(kernel, sid, "pay")

    assert 'call:charge(amount_cents=0, currency="x") raises ValueError' in node["invariants_auto_mined"]
    assert "def charge" in node["preserved_symbols"] and "@audit" in node["preserved_symbols"]
    rendered = kernel.checkout(sid, "pay", focus=["refund"]).rendered()
    assert "async def charge(amount_cents: int, currency: str) -> dict:" in rendered
    assert "await asyncio.sleep(0)" not in rendered  # skeletonized
    assert "async def refund(amount_cents: int) -> dict:\n    if amount_cents <= 0:" in rendered

    dropped = kernel.commit(sid, "pay", patch=[{"op": "delete_symbol", "name": "charge"}])
    assert dropped.gate == "B"


def test_async_guards_are_enforced_at_gate_c_and_signature_growth_is_mocked(kernel, tmp_path):
    target = tmp_path / "pay.py"
    _write(target, ASYNC_SRC)
    sid = kernel.init_session(tmp_path)

    weak = kernel.commit(sid, "pay", patch=_replace("charge", ASYNC_WEAK))
    assert weak.gate == "C", weak.error

    # Same statement count as the original (so Gate B stays quiet): only the
    # mined `call:charge(amount_cents=0, …)` guard, awaited, can catch it.
    no_raise = kernel.commit(
        sid, "pay",
        patch=_replace(
            "charge",
            "@audit\nasync def charge(amount_cents: int, currency: str) -> dict:\n"
            "    if amount_cents <= 0:\n"
            "        amount_cents = 1\n"
            "    await asyncio.sleep(0)\n"
            '    return {"amount_cents": amount_cents, "currency": currency}\n',
        ),
    )
    assert no_raise.gate == "C", no_raise.error
    assert "auto-mined" in str(no_raise.error)

    # The hand-written `raises(lambda: ns["refund"](-1), …)` helper form awaits too.
    refund_weak = kernel.commit(
        sid, "pay",
        patch=_replace(
            "refund",
            "async def refund(amount_cents: int) -> dict:\n"
            "    if amount_cents <= 0:\n"
            "        amount_cents = 1\n"
            '    return {"amount_cents": -amount_cents}\n',
        ),
    )
    assert refund_weak.gate == "C", refund_weak.error
    assert 'raises(lambda: ns["refund"](-1)' in str(refund_weak.error)

    grown = kernel.commit(
        sid, "pay",
        patch=_replace(
            "charge",
            "@audit\nasync def charge(amount_cents: int, currency: str, idempotency_key: str) -> dict:\n"
            "    if amount_cents <= 0:\n"
            '        raise ValueError("amount_cents must be positive")\n'
            '    return {"amount_cents": amount_cents, "key": idempotency_key}\n',
        ),
    )
    assert grown.accepted, grown.error
    assert _sha(target) == grown.attestation["payload"]["sha256"]
    assert 'call:charge(amount_cents=0, currency="x", idempotency_key="x") raises ValueError' in _node(
        kernel, sid, "pay"
    )["invariants_auto_mined"]


def test_async_invariants_evaluate_inside_the_gateway_event_loop(tmp_path):
    import server

    _write(tmp_path / "pay.py", ASYNC_SRC)
    with TestClient(server.app) as client:
        sid = client.post("/v1/step/init", json={"project_root": str(tmp_path)}).json()["session_id"]
        weak = client.post(
            "/v1/step/commit",
            json={"session_id": sid, "node_id": "pay", "patch": _replace("charge", ASYNC_WEAK)},
        ).json()
        assert not weak["accepted"] and weak["gate"] == "C"
        ok = client.post(
            "/v1/step/commit",
            json={"session_id": sid, "node_id": "pay", "patch": [{"op": "append", "code": "LIMIT = 5\n"}]},
        ).json()
        assert ok["accepted"], ok


# -------------------------------------------- 3. comment-preserving AST patching

COMMENTED = '''\
# Module header: keep me.
"""Docs."""
import os  # noqa: F401

LIMIT = 3  # inline tail comment


def tag(fn):
    return fn


def first(x: int) -> int:
    return x + 1  # noqa: E501


# Attached to second: travels with the symbol.
@tag
def second(y: int) -> int:
    # body comment
    return y * 2


# ---- section banner ----

def third(z: int) -> int:  # noqa
    return z - 1
# trailing comment at EOF
'''

OLD_SECOND = (
    "# Attached to second: travels with the symbol.\n@tag\ndef second(y: int) -> int:\n"
    "    # body comment\n    return y * 2\n"
)
NEW_SECOND = "# Attached to second: rewritten.\n@tag\ndef second(y: int) -> int:\n    return y * 3\n"


def test_replace_symbol_splices_only_the_symbols_own_lines(kernel, tmp_path):
    target = tmp_path / "mod.py"
    _write(target, COMMENTED)
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(sid, "mod", patch=_replace("second", NEW_SECOND))

    assert v.accepted, v.error
    text = target.read_text(encoding="utf-8")
    assert text == COMMENTED.replace(OLD_SECOND, NEW_SECOND)
    assert text.count("# Attached to second") == 1
    for kept in ("# Module header: keep me.", "# noqa: F401", "# inline tail comment",
                 "# noqa: E501", "# ---- section banner ----", "  # noqa\n", "# trailing comment at EOF"):
        assert kept in text


def test_delete_symbol_removes_its_attached_comment_and_nothing_else(kernel, tmp_path):
    target = tmp_path / "mod.py"
    _write(target, COMMENTED)
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(sid, "mod", patch=[{"op": "delete_symbol", "name": "second"}], allow_deletion=True)

    assert v.accepted, v.error
    text = target.read_text(encoding="utf-8")
    assert text == COMMENTED.replace(OLD_SECOND + "\n\n", "")
    assert "\n\n\n\n" not in text


# ------------------------------------------------------- 4. session persistence


def test_session_rehydrates_in_a_fresh_kernel_instance(kernel, project):
    sid = kernel.init_session(project)
    first = kernel.commit(sid, "billing", patch=[{"op": "append", "code": "def _h1() -> int:\n    return 1\n"}])
    assert first.accepted, first.error
    kernel.lock_node(sid, "auth")
    turns_before = kernel.get_telemetry(sid).turns
    assert (project / ".stepcheck" / "sessions" / f"{sid}.json").is_file()

    fresh = StateKernel()  # a restarted process knows nothing in memory
    assert fresh.get_telemetry(sid).turns == turns_before
    graph = {n["node_id"]: n for n in fresh.graph(sid)["nodes"]}
    assert graph["billing"]["status"] == "VERIFIED"
    assert graph["billing"]["attestation"] == first.attestation
    assert graph["auth"]["status"] == "LOCKED"
    assert "def charge" in fresh.checkout(sid, "billing", focus=["charge"]).rendered()

    second = fresh.commit(sid, "billing", patch=[{"op": "append", "code": "def _h2() -> int:\n    return 2\n"}])
    assert second.accepted, second.error
    assert second.attestation["payload"]["turn"] == 2
    assert _sha(project / "billing.py") == second.attestation["payload"]["sha256"]
    locked = fresh.commit(sid, "auth", patch=[{"op": "append", "code": "X = 1\n"}])
    assert locked.gate == "A"


def test_unknown_or_malformed_session_ids_stay_keyerrors(kernel):
    for sid in ("sk-000000000000", "../../etc/passwd", "nope", ""):
        with pytest.raises(KeyError):
            kernel.graph(sid)


def test_rest_session_survives_a_gateway_restart(project):
    import server

    with TestClient(server.app) as client:
        sid = client.post("/v1/step/init", json={"project_root": str(project)}).json()["session_id"]
        client.post("/v1/step/checkout", json={"session_id": sid, "node_id": "billing", "focus": []})
        out = client.post(
            "/v1/step/commit",
            json={"session_id": sid, "node_id": "billing",
                  "patch": [{"op": "append", "code": "def _h() -> int:\n    return 1\n"}]},
        ).json()
        assert out["accepted"], out

    server = importlib.reload(server)  # fresh KERNEL and app: the restart
    with TestClient(server.app) as client:
        graph = client.get(f"/v1/step/graph/{sid}")
        assert graph.status_code == 200
        billing = next(n for n in graph.json()["nodes"] if n["node_id"] == "billing")
        assert billing["status"] == "VERIFIED" and billing["attestation"] == out["attestation"]
        assert client.get(f"/v1/step/telemetry/{sid}").json()["turns"] == 1
        assert client.get("/v1/step/graph/sk-deadbeef0000").status_code == 404
