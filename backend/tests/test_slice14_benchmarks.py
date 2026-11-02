"""Slice 14 — deterministic benchmarks and a fault-injection matrix at the two
public seams: self-hosted compaction on StepCheck's own production modules,
latency budgets for checkout / gated commit / runaway Gate C invariants, and ten
adversarial fault classes each paired with a valid counter-commit (Seam 1 + CLI).

Every threshold below was set from a measurement on the development machine
(Windows 11, Python 3.12) and then given headroom; the measured values are
recorded next to each assertion so a CI regression is readable."""
import shutil
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

import cli
from kernel import CommitVerdict, LogicalError, MechanicalError, OmissionError, StateKernel

BACKEND = Path(__file__).resolve().parents[1]
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".stepcheck")


def _replace(name: str, code: str) -> list[dict]:
    return [{"op": "replace_symbol", "name": name, "code": code}]


def _append(code: str) -> list[dict]:
    return [{"op": "append", "code": code}]


def _p95(samples: list[float]) -> float:
    ordered = sorted(samples)
    return ordered[round(0.95 * (len(ordered) - 1))]


def _ms(fn: Callable[[], object]) -> float:
    start = time.perf_counter()
    fn()
    return (time.perf_counter() - start) * 1000


# --------------------------------------------- 1. self-hosted compaction


# One production module each, focused on a single real function.
FOCUSED = [("server", "_build_mcp"), ("cli", "cmd_ci"), ("audit", "display_path"), ("_okf", "apply_patch")]


def _first_touch(kernel: StateKernel, sid: str, node: str, focus: list[str] | None):
    """Checkout once and read what telemetry charged for it. The first checkout
    of a node is charged at full raw-read price, so the raw delta is the token
    count of reading the whole file and the compacted delta is the payload."""
    before = kernel.get_telemetry(sid)
    payload = kernel.checkout(sid, node, focus=focus)
    after = kernel.get_telemetry(sid)
    raw = after.raw_bloated_tokens - before.raw_bloated_tokens
    compacted = after.compacted_okf_tokens - before.compacted_okf_tokens
    assert compacted == payload.token_count
    return payload, raw, compacted


@pytest.fixture()
def own_backend(tmp_path) -> Path:
    root = tmp_path / "backend"
    shutil.copytree(BACKEND, root, ignore=IGNORE)
    return root


def test_single_function_focus_compacts_real_production_modules(kernel, own_backend):
    sid = kernel.init_session(own_backend)
    saved = {}
    for node, symbol in FOCUSED:
        payload, raw, compacted = _first_touch(kernel, sid, node, [symbol])
        assert f"def {symbol}(" in payload.rendered() and not payload.auto_skeletonized
        assert payload.token_count < 4000
        saved[node] = 100 * (raw - compacted) / raw
    # Measured 2026-11-03 (token counts are deterministic for a given source):
    # server 32.6%, cli 57.8%, audit 57.2%, _okf 65.4% (mean 53.2%). `_build_mcp`
    # is server.py's largest function, and the payload also carries the
    # kernel's interface skeleton; a leaf module with a mid-sized focus is where
    # single-function compaction reaches 65%.
    assert min(saved.values()) >= 30, saved
    assert statistics.mean(saved.values()) >= 50, saved
    assert saved["_okf"] >= 60, saved


def test_focused_checkout_beats_reading_the_module_and_its_dependencies(kernel, own_backend):
    """What an agent reads without StepCheck is the module *and* the modules it
    imports; the payload already contains those interfaces as skeletons."""
    sid = kernel.init_session(own_backend)
    raw_of: dict[str, int] = {}
    touched = {}
    for node, symbol in FOCUSED:  # every target first, so each is charged as a first read
        payload, raw, compacted = _first_touch(kernel, sid, node, [symbol])
        raw_of[node] = raw
        touched[node] = (compacted, list(payload.dependency_skeletons))
    for _, deps in touched.values():
        for dep in deps:
            if dep not in raw_of:
                raw_of[dep] = _first_touch(kernel, sid, dep, [])[1]
    neighbourhood = {}
    for node, (compacted, deps) in touched.items():
        full_read = raw_of[node] + sum(raw_of[d] for d in deps)
        neighbourhood[node] = 100 * (full_read - compacted) / full_read
    # Measured 2026-11-03: server 79.7% (1 dep), audit >= 70% (2 deps), cli 57.8% and
    # _okf 65.4% (leaf modules, so identical to the module-only figure).
    assert neighbourhood["server"] >= 70, neighbourhood
    assert statistics.mean(neighbourhood.values()) >= 65, neighbourhood


# ------------------------------------------------- 2. latency budgets


def test_focused_checkout_p95_under_50ms(kernel, project):
    sid = kernel.init_session(project)
    kernel.checkout(sid, "billing", focus=["charge"])  # warm-up
    samples = [_ms(lambda: kernel.checkout(sid, "billing", focus=["charge"])) for _ in range(20)]
    assert _p95(samples) < 50, samples  # measured p95 5.6 ms


def test_gated_commit_p95_under_50ms_and_disk_backed_under_250ms(project):
    # Gates A+B+C plus the DSSE envelope, nothing written: the kernel's own cost.
    ephemeral = StateKernel(ephemeral=True)
    sid = ephemeral.init_session(project)
    assert ephemeral.commit(sid, "billing", patch=_append("W = 0\n")).accepted  # warm-up
    gated = []
    for i in range(20):
        verdict = None

        def one(i=i):
            nonlocal verdict
            verdict = ephemeral.commit(sid, "billing", patch=_append(f"K{i} = {i}\n"))

        gated.append(_ms(one))
        assert verdict.accepted and verdict.attestation["payload"]["sha256"]
    assert _p95(gated) < 50, gated  # measured p95 8.9 ms

    # The same commits landing on disk: atomic write-back + session persistence.
    disk = StateKernel()
    sid = disk.init_session(project)
    assert disk.commit(sid, "billing", patch=_append("W = 0\n")).accepted
    landed = [_ms(lambda i=i: disk.commit(sid, "billing", patch=_append(f"K{i} = {i}\n"))) for i in range(20)]
    assert _p95(landed) < 250, landed  # measured p95 59 ms on Windows


def test_runaway_gate_c_invariant_terminates_deterministically(kernel, project):
    sid = kernel.init_session(project)
    # `charge` carries a hand-written src invariant and a mined `call:` guard;
    # the loop sits before the guard so the callable invariant has to run it.
    elapsed = []
    verdict = None

    def runaway():
        nonlocal verdict
        verdict = kernel.commit(
            sid, "billing",
            patch=_replace(
                "charge",
                "@require_auth\ndef charge(user: str, amount_cents: int) -> dict:\n"
                '    # okf-invariant: "amount_cents <= 0" in src and "raise ValueError" in src\n'
                "    while True:\n        pass\n"
                "    if amount_cents <= 0:\n        raise ValueError(\"amount must be positive\")\n"
                "    if not check_permission(user, \"charge\"):\n        raise PermissionError(user)\n"
                "    return {}\n",
            ),
        )

    elapsed.append(_ms(runaway))
    assert not verdict.accepted and verdict.gate == "C" and isinstance(verdict.error, LogicalError)
    assert "budget" in str(verdict.error).lower() or "steps" in str(verdict.error).lower()
    assert elapsed[0] < 5000, elapsed  # measured 95 ms: 200k line events, not a hang
    # The node is untouched and still commits a bounded version.
    bounded = kernel.commit(
        sid, "billing",
        patch=_replace(
            "charge",
            "@require_auth\ndef charge(user: str, amount_cents: int) -> dict:\n"
            '    # okf-invariant: "amount_cents <= 0" in src and "raise ValueError" in src\n'
            "    for _ in range(100):\n        pass\n"
            "    if amount_cents <= 0:\n        raise ValueError(\"amount must be positive\")\n"
            "    if not check_permission(user, \"charge\"):\n        raise PermissionError(user)\n"
            '    return {"user": user, "amount_cents": amount_cents, "status": "charged"}\n',
        ),
    )
    assert bounded.accepted, bounded.error


# ------------------------------------- 3. adversarial fault-injection matrix

CORE = '''\
import json

RATE = 3
LIMIT = 10
CURRENCY = "usd"
RETRIES = 2
TIMEOUT = 30


def audit(fn):
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)
    return wrapper


def check(amount: int) -> int:
    if amount <= 0:
        raise ValueError("amount must be positive")
    return amount


# okf-invariant: ns["encode"]({"a": 1}) == '{"a": 1}'
def encode(d: dict) -> str:
    return json.dumps(d)
'''

API = '''\
from core import audit, check, RATE


@audit
def charge(account: str, amount: int) -> dict:
    return {"account": account, "amount": check(amount) * RATE}


def refund(account: str, amount: int) -> dict:
    return {"account": account, "amount": -amount}
'''

GUARDED_CHECK = (
    "def check(amount: int) -> int:\n"
    "    if amount <= 0:\n        raise ValueError(\"amount must be positive\")\n"
    "    return amount\n"
)


@pytest.fixture()
def matrix_project(tmp_path) -> Path:
    (tmp_path / "core.py").write_text(CORE, encoding="utf-8", newline="\n")
    (tmp_path / "api.py").write_text(API, encoding="utf-8", newline="\n")
    # A sub-package module named like the stdlib: must never shadow `import json`.
    (tmp_path / "utils").mkdir()
    (tmp_path / "utils" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "utils" / "json.py").write_text(
        'def dumps(_):\n    raise RuntimeError("shadow")\n', encoding="utf-8", newline="\n"
    )
    return tmp_path


def _ci(root: Path, capsys) -> tuple[int, str]:
    rc = cli.main(["ci", str(root)])
    return rc, capsys.readouterr().out


@dataclass(frozen=True)
class Fault:
    name: str
    gate: str
    inject: Callable  # (kernel, sid, root, capsys) -> rejected verdict / evidence
    counter: Callable  # (kernel, sid, root, capsys) -> accepted verdict / evidence


def _a_syntax(k, sid, root, capsys):
    v = k.commit(sid, "api", patch=_replace("refund", "def refund(:\n    pass\n"))
    assert isinstance(v.error, MechanicalError) and "syntax" in str(v.error)
    return v


def _a_syntax_ok(k, sid, root, capsys):
    return k.commit(sid, "api", patch=_replace(
        "refund", "def refund(account: str, amount: int) -> dict:\n    return {\"account\": account, \"amount\": -abs(amount)}\n"
    ))


def _a_lock(k, sid, root, capsys):
    k.lock_node(sid, "core")
    v = k.commit(sid, "core", patch=_append("X = 1\n"))
    assert "LOCKED" in str(v.error)
    return v


def _a_lock_ok(k, sid, root, capsys):
    return k.commit(sid, "api", patch=_append("X = 1\n"))  # the unlocked neighbour


def _a_export(k, sid, root, capsys):
    v = k.commit(sid, "core", patch=[{"op": "delete_symbol", "name": "check"}])
    assert "required by dependent 'api'" in str(v.error)
    return v


def _a_export_ok(k, sid, root, capsys):
    return k.commit(sid, "core", patch=_append("def helper() -> int:\n    return 1\n"))


def _b_decorator(k, sid, root, capsys):
    v = k.commit(sid, "api", patch=_replace(
        "charge", "def charge(account: str, amount: int) -> dict:\n    return {\"account\": account, \"amount\": check(amount) * RATE}\n"
    ))
    assert isinstance(v.error, OmissionError) and v.error.subtype == "INTRA_NODE_SYMBOL_DROPPED"
    assert "@audit" in str(v.error)
    return v


def _b_decorator_ok(k, sid, root, capsys):
    return k.commit(sid, "api", patch=_replace(
        "charge",
        "@audit\ndef charge(account: str, amount: int) -> dict:\n"
        "    return {\"account\": account, \"amount\": check(amount) * RATE, \"ok\": True}\n",
    ))


def _b_constants(k, sid, root, capsys):
    # Patch ops address defs and classes, so a constant block only disappears
    # through a whole-module rewrite; four of sixteen statements is a mass deletion.
    rewritten = CORE.replace('LIMIT = 10\nCURRENCY = "usd"\nRETRIES = 2\nTIMEOUT = 30\n', "")
    v = k.commit(sid, "core", source=rewritten)
    assert isinstance(v.error, OmissionError) and v.error.subtype == "INTRA_NODE_MASS_DELETION"
    return v


def _b_constants_ok(k, sid, root, capsys):
    return k.commit(sid, "core", source=CORE.replace("LIMIT = 10", "LIMIT = 20").replace("RETRIES = 2", "RETRIES = 5"))


def _b_signature(k, sid, root, capsys):
    v = k.commit(sid, "core", patch=_replace(
        "check",
        'def check(amount: int, currency: str = "usd") -> int:\n'
        "    if amount <= 0:\n        raise ValueError(\"amount must be positive\")\n    return amount\n",
    ))
    assert v.accepted and v.dirtied == ["api"], v.error
    with pytest.raises(OmissionError, match="DIRTY_OMISSION_RISK"):
        k.finalize_session(sid)
    return None  # the fault is the blocked finalize, not a gate rejection


def _b_signature_ok(k, sid, root, capsys):
    v = k.commit(sid, "api", patch=_append("Y = 1\n"))  # the caller re-verified
    assert v.accepted and v.dirtied == [] and k.finalize_session(sid) is True
    return v


def _c_guard(k, sid, root, capsys):
    # Same statement count as the guarded version, so Gate B cannot see it.
    v = k.commit(sid, "core", patch=_replace(
        "check", "def check(amount: int) -> int:\n    amount = max(amount, 1)\n    _ = amount\n    return amount\n"
    ))
    assert isinstance(v.error, LogicalError) and "call:check(amount=0) raises ValueError" in str(v.error)
    return v


def _c_guard_ok(k, sid, root, capsys):
    return k.commit(sid, "core", patch=_replace(
        "check", "def check(amount: int) -> int:\n    if amount <= 0:\n        raise ValueError(\"must be > 0\")\n    return int(amount)\n"
    ))


def _c_loop(k, sid, root, capsys):
    started = time.perf_counter()
    v = k.commit(sid, "core", patch=_replace(
        "check", "def check(amount: int) -> int:\n    while True:\n        pass\n" + GUARDED_CHECK.split("\n", 1)[1]
    ))
    assert (time.perf_counter() - started) < 5 and isinstance(v.error, LogicalError)
    return v


def _c_loop_ok(k, sid, root, capsys):
    return k.commit(sid, "core", patch=_replace(
        "check", "def check(amount: int) -> int:\n    for _ in range(100):\n        pass\n" + GUARDED_CHECK.split("\n", 1)[1]
    ))


def _c_shadow(k, sid, root, capsys):
    v = k.commit(sid, "core", patch=_replace("encode", "def encode(d: dict) -> str:\n    return str(d)\n"))
    assert isinstance(v.error, LogicalError) and 'ns["encode"]' in str(v.error)
    return v


def _c_shadow_ok(k, sid, root, capsys):
    # Evaluated against the real stdlib `json`; through utils/json.py this would
    # raise RuntimeError("shadow") and be a false positive.
    return k.commit(sid, "core", patch=_append("Z = 1\n"))


def _ci_drift(k, sid, root, capsys):
    assert k.commit(sid, "core", patch=_append("Z = 1\n")).accepted
    assert _ci(root, capsys)[0] == 0
    target = root / "core.py"
    target.write_bytes(target.read_bytes() + b"\nTAMPERED = 1\n")  # edited behind the kernel's back
    rc, out = _ci(root, capsys)
    assert rc == 1 and "core.py" in out and "sha256" in out.lower()
    return rc


def _ci_drift_ok(k, sid, root, capsys):
    StateKernel().init_session(root)  # a fresh session re-reads the disk and re-attests
    rc, out = _ci(root, capsys)
    assert rc == 0, out
    return rc


MATRIX = [
    Fault("A1 syntax error", "A", _a_syntax, _a_syntax_ok),
    Fault("A2 locked module mutation", "A", _a_lock, _a_lock_ok),
    Fault("A3 exported symbol dropped", "A", _a_export, _a_export_ok),
    Fault("B1 decorator silently dropped", "B", _b_decorator, _b_decorator_ok),
    Fault("B2 constant block silently deleted", "B", _b_constants, _b_constants_ok),
    Fault("B3 signature change dirties callers", "B", _b_signature, _b_signature_ok),
    Fault("C1 auto-mined guard removed", "C", _c_guard, _c_guard_ok),
    Fault("C2 runaway loop under an invariant", "C", _c_loop, _c_loop_ok),
    Fault("C3 invariant beside a stdlib-named module", "C", _c_shadow, _c_shadow_ok),
    Fault("CI attestation drift on disk", "ci", _ci_drift, _ci_drift_ok),
]


@pytest.mark.parametrize("fault", MATRIX, ids=[f.name for f in MATRIX])
def test_fault_is_caught_and_its_counter_commit_is_not(fault, kernel, matrix_project, capsys):
    sid = kernel.init_session(matrix_project)
    rejected = fault.inject(kernel, sid, matrix_project, capsys)
    if isinstance(rejected, CommitVerdict):  # B3 is accepted-but-dirty and CI is an exit code
        assert not rejected.accepted and rejected.gate == fault.gate, rejected.error
        assert rejected.attestation is None
    accepted = fault.counter(kernel, sid, matrix_project, capsys)
    if isinstance(accepted, CommitVerdict):
        assert accepted.accepted and accepted.gate is None, accepted.error
        assert accepted.attestation["payload"]["sha256"]


def test_matrix_covers_every_gate_and_the_ci_seam():
    gates = [f.gate for f in MATRIX]
    assert len(MATRIX) == 10 and gates.count("A") == 3 and gates.count("B") == 3 and gates.count("C") == 3
    assert gates.count("ci") == 1
