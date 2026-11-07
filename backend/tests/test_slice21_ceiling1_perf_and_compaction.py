"""Slice 21 — warm, memory-buffered checkouts for the lifecycle hooks (telemetry
charged in memory, persisted by the next mutating call or `flush()`, payloads
memoized per focus), the cheap kernel queries the hook policy needs
(`locate`, `node_source`, `omission_report`), sibling-class collapse and
import scoping on a dotted focus, frontmatter scoped to the focus, and the
unfocused budget ladder that keeps every public name (Seam 1 + Seam 2)."""
import json
import shutil
import statistics
import textwrap
import time
from pathlib import Path

import pytest
import yaml
from conftest import BILLING_SRC
from fastapi.testclient import TestClient

from kernel import StateKernel

BACKEND = Path(__file__).resolve().parents[1]
BUDGET = 4000


def _body(payload) -> str:
    return payload.frame_markdown.split("```python\n", 1)[1].rsplit("```", 1)[0]


def _meta(payload) -> dict:
    return yaml.safe_load(payload.frame_markdown.split("---\n")[1])


def _p95(xs):
    s = sorted(xs)
    return s[round(0.95 * (len(s) - 1))]


def _session_file(project: Path, sid: str) -> Path:
    return project / ".stepcheck" / "sessions" / f"{sid}.json"


# ------------------------------------- 1. deferred persistence + public queries


def test_checkouts_are_charged_in_memory_and_persisted_by_the_next_mutating_call_or_flush(kernel, project):
    sid = kernel.init_session(project)
    on_disk = _session_file(project, sid).read_bytes()
    for _ in range(3):
        kernel.checkout(sid, "billing", focus=["charge"])
    assert kernel.get_telemetry(sid).turns == 3  # charged in memory...
    assert _session_file(project, sid).read_bytes() == on_disk  # ...nothing written per checkout
    assert StateKernel().get_telemetry(sid).turns == 0  # another process does not see the burst yet

    kernel.flush(sid)
    assert StateKernel().get_telemetry(sid).turns == 3  # flush closes the gap

    kernel.checkout(sid, "billing", focus=[])
    kernel.lock_node(sid, "auth")  # a mutating call flushes on its own
    assert StateKernel().get_telemetry(sid).turns == 4
    assert kernel.commit(sid, "billing", patch=[{"op": "append", "code": "LIMIT = 1\n"}]).accepted
    assert StateKernel().get_telemetry(sid).turns == 5

    ephemeral = StateKernel(ephemeral=True)
    esid = ephemeral.init_session(project)
    ephemeral.checkout(esid, "billing", focus=[])
    ephemeral.flush(esid)  # a no-op: an ephemeral kernel never writes
    assert not (project / ".stepcheck" / "sessions" / f"{esid}.json").exists()


def test_payloads_are_memoized_per_focus_until_the_session_mutates(kernel, project):
    sid = kernel.init_session(project)
    on_disk = _session_file(project, sid).read_bytes()
    first = kernel.checkout(sid, "billing", focus=["charge"])
    again = kernel.checkout(sid, "billing", focus=["charge"])
    assert again.rendered() == first.rendered() and again.token_count == first.token_count
    assert kernel.get_telemetry(sid).turns == 2  # every checkout is still a charged turn
    assert _session_file(project, sid).read_bytes() == on_disk  # served from memory, nothing serialized

    v = kernel.commit(sid, "billing", patch=[{"op": "append", "code": "def _h() -> int:\n    return 1\n"}])
    assert v.accepted
    after = kernel.checkout(sid, "billing", focus=[])
    assert "def _h(" in after.frame_markdown  # the memo did not outlive the commit
    assert _meta(after)["status"] == "VERIFIED"


def test_locate_node_source_and_omission_report_are_cheap_public_queries(kernel, project):
    sid = kernel.init_session(project)
    hit = kernel.locate(sid, project / "billing.py")
    assert hit["node_id"] == "billing" and hit["status"] == "ACTIVE" and hit["locked"] is False
    assert hit["path"] == "billing.py" and hit["source_tokens"] > 0 and "source" not in hit
    assert kernel.locate(sid, project / "README.md") is None
    assert kernel.locate(sid, project.parent / "elsewhere.py") is None
    assert kernel.node_source(sid, "billing") == BILLING_SRC
    assert kernel.omission_report(sid) == {"dirty": [], "can_finalize": True}

    kernel.lock_node(sid, "auth")
    assert kernel.locate(sid, project / "auth.py")["status"] == "LOCKED"
    changed = BILLING_SRC.replace(
        "def charge(user: str, amount_cents: int) -> dict:",
        'def charge(user: str, amount_cents: int, currency: str = "usd") -> dict:',
    )
    assert kernel.commit(sid, "billing", source=changed).dirtied == ["reports"]
    assert kernel.omission_report(sid) == {"dirty": ["reports"], "can_finalize": False}
    with pytest.raises(KeyError):
        kernel.omission_report("sk-000000000000")


# ---------------------------------------- 2. the hook endpoint under 25 ms p95


@pytest.fixture()
def client(project):
    import server

    with TestClient(server.app) as c:
        yield c


def _hook(client, **event) -> dict:
    r = client.post("/v1/step/hook", json=event)
    assert r.status_code == 200, r.text
    return r.json()


def test_hook_read_deny_with_a_real_skeleton_checkout_is_under_25ms_p95(client, project):
    # A 10-module project whose denied module is server-sized: the gateway's own
    # server.py (imports neutralised so it is a leaf of this project).
    big = (BACKEND / "server.py").read_text(encoding="utf-8").replace("from kernel import", "from kernelx import")
    (project / "big.py").write_text(big, encoding="utf-8", newline="\n")
    for i in range(4):
        (project / f"mod{i}.py").write_text(f"def f{i}(x: int) -> int:\n    if x < 0:\n        raise ValueError(x)\n    return x + {i}\n",
                                            encoding="utf-8", newline="\n")
    sid = client.post("/v1/step/init", json={"project_root": str(project)}).json()["session_id"]
    deny = dict(hook_event_name="PreToolUse", tool_name="Read", cwd=str(project), tool_input={"file_path": str(project / "big.py")})
    first = _hook(client, **deny)  # the one uncached assembly
    assert first["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "def _build_mcp(" in first["hookSpecificOutput"]["additionalContext"]

    samples = []
    for _ in range(50):
        started = time.perf_counter()
        out = _hook(client, **deny)
        samples.append((time.perf_counter() - started) * 1000)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert statistics.median(samples) < 15, (statistics.median(samples), _p95(samples))
    assert _p95(samples) < 25, (statistics.median(samples), _p95(samples))
    # every interception was charged as a turn, in memory, nothing serialized per call
    assert client.get(f"/v1/step/telemetry/{sid}").json()["turns"] == 51
    assert StateKernel().get_telemetry(sid).turns == 0
    assert client.post("/v1/step/lock", json={"session_id": sid, "node_id": "auth"}).status_code == 200
    assert StateKernel().get_telemetry(sid).turns == 51  # the mutating call flushed the burst

    # governance decisions stay fast too
    gov = [dict(hook_event_name="Stop", cwd=str(project)),
           dict(hook_event_name="PreToolUse", tool_name="Edit", cwd=str(project), tool_input={"file_path": str(project / "auth.py")})]
    fast = []
    for i in range(20):
        started = time.perf_counter()
        _hook(client, **gov[i % 2])
        fast.append((time.perf_counter() - started) * 1000)
    assert _p95(fast) < 25, fast


def test_gate_a_rejection_on_a_locked_node_does_not_re_render_the_project(tmp_path):
    """Regression: the probe commit behind an Edit deny on a locked node (made so that
    Gate A speaks for itself) ran the full flush on rejection, re-rendering every OKF
    frame of the project, so the deny cost grew with the module count. A rejection on
    a locked node changes no frame: it records the event, persists the session and
    leaves the checkout memo alone."""
    big = (BACKEND / "server.py").read_text(encoding="utf-8").replace("from kernel import", "from kernelx import")
    for i in range(30):
        (tmp_path / f"big{i}.py").write_text(big, encoding="utf-8", newline="\n")
    kernel = StateKernel()
    sid = kernel.init_session(tmp_path)
    kernel.lock_node(sid, "big0")
    source = kernel.node_source(sid, "big0")
    first = kernel.commit(sid, "big0", source=source)
    assert not first.accepted and first.gate == "A"

    samples = []
    for _ in range(10):
        started = time.perf_counter()
        assert kernel.commit(sid, "big0", source=source).gate == "A"
        samples.append((time.perf_counter() - started) * 1000)
    assert statistics.median(samples) < 40, samples

    fresh = StateKernel()  # the rejections are on the record for a fresh process, the node still locked
    assert sum(1 for e in fresh.events(sid) if e["kind"] == "reject") == 11
    assert next(n for n in fresh.graph(sid)["nodes"] if n["node_id"] == "big0")["status"] == "LOCKED"


# ------------------------- 3. dotted focus: sibling collapse, import scoping


MODULE = textwrap.dedent('''\
    """Store of widgets.

    A longer description that an editing view does not need to carry.
    """
    import json
    import os
    import re
    from dataclasses import dataclass

    LIMIT = 10


    class Base:
        """Base."""

        def describe(self) -> str:
            return "base"


    @dataclass
    class Config:
        """Config."""

        retries: int = 3

        def validate(self) -> bool:
            return self.retries >= 0

        def as_json(self) -> str:
            return json.dumps({"retries": self.retries})


    class Noise(Base):
        """Never referenced by Repo.add."""

        def one(self) -> int:
            return 1

        def two(self) -> int:
            return 2

        def three(self) -> int:
            return 3


    class Repo(Base):
        """Store of non-negative integers."""

        def __init__(self, config: Config) -> None:
            """Keep the config."""
            self.items: list[int] = []
            self.config = config

        def add(self, item: int) -> None:
            if item < 0:
                raise ValueError(item)
            if not Config(1).validate():
                raise RuntimeError("config")
            self.items.append(json.loads(json.dumps(item)))

        def total(self) -> int:
            """Sum of the items."""
            return sum(self.items)

        def _reset(self) -> None:
            self.items = []


    def helper(v: int) -> int:
        """Public helper."""
        return v + 1


    def guarded(n: int) -> int:
        if n < 0:
            raise ValueError(n)
        return n


    def _private(v: int) -> int:
        return v - 1
    ''')


def test_dotted_focus_collapses_unreferenced_siblings_scopes_imports_and_keeps_the_target_signatures(kernel, tmp_path):
    (tmp_path / "store.py").write_text(MODULE, encoding="utf-8", newline="\n")
    sid = kernel.init_session(tmp_path)
    body = _body(kernel.checkout(sid, "store", focus=["Repo.add"]))

    # the target method verbatim; its class keeps __init__ verbatim (v0.3.2 causal cone: the
    # self.<attr> declarations) and every other own method as a signature, bodies and docstrings gone
    assert "self.items.append(json.loads(json.dumps(item)))" in body
    assert "def __init__(self, config: Config) -> None:" in body and "self.config = config" in body
    assert "def total(self) -> int:" in body and "return sum(self.items)" not in body and "Sum of the items" not in body
    assert "def _reset(self) -> None:" in body
    # referenced siblings keep their skeleton (Base: a base class; Config: called in the method)
    assert "class Base:" in body and "def describe(self) -> str:" in body
    assert "class Config:" in body and "def validate(self) -> bool:" in body
    # the unreferenced sibling collapses to a counted stub
    assert "class Noise(Base): ...\n    # + 3 method signatures elided\n" in body and "def one" not in body
    # top-level functions keep their signatures
    assert "def helper(v: int) -> int:" in body and "Public helper" not in body and "def _private(v: int) -> int:" in body
    # imports the focus cannot reach are counted, the one it uses stays (a sibling's
    # decorator is not the focus's business: its skeleton shows `@dataclass` anyway)
    assert "import json\n" in body and "import os\n" not in body and "import re\n" not in body
    assert "from dataclasses import dataclass" not in body and "@dataclass\nclass Config:" in body
    assert "# + 3 imports elided (unreferenced by the focus)" in body
    # the module docstring collapses to its summary line
    assert '"""Store of widgets."""' in body and "A longer description" not in body


def test_a_run_of_unreferenced_siblings_folds_into_one_line_naming_them(kernel, tmp_path):
    src = "".join(f"class S{i}:\n    def m(self) -> int:\n        return {i}\n\n\n" for i in range(6)) + \
          "class Target:\n    def go(self) -> int:\n        return 7\n"
    (tmp_path / "many.py").write_text(src, encoding="utf-8", newline="\n")
    sid = kernel.init_session(tmp_path)
    body = _body(kernel.checkout(sid, "many", focus=["Target.go"]))
    assert "# + 6 unreferenced sibling classes elided: S0, S1, S2, S3, S4, S5" in body
    assert "class S0" not in body and "return 7" in body
    unfocused = _body(kernel.checkout(sid, "many", focus=[]))
    for i in range(6):
        assert f"class S{i}:" in unfocused  # the orientation view folds nothing away


def test_focused_frontmatter_is_scoped_to_the_focus(kernel, tmp_path):
    (tmp_path / "store.py").write_text(MODULE, encoding="utf-8", newline="\n")
    sid = kernel.init_session(tmp_path)
    full = _meta(kernel.checkout(sid, "store", focus=[]))
    scoped = _meta(kernel.checkout(sid, "store", focus=["Repo.add"]))

    assert "exports_elided" not in full and len(full["exports"]) == 6
    assert full["invariants"] == ["call:guarded(n=-1) raises ValueError"]  # the orientation view keeps the contract
    assert scoped["exports"] == ["class Repo(Base)"] and scoped["exports_elided"] == 5
    assert all("Repo" in s or "Config" in s or "Base" in s for s in scoped["preserved_symbols"])
    assert "class Repo" in scoped["preserved_symbols"] and "def helper" not in scoped["preserved_symbols"]
    assert scoped["preserved_symbols_elided"] >= 1
    assert scoped["invariants"] == [] and scoped["invariants_elided"] == 1  # guarded()'s invariant is not Repo.add's
    assert "Frontmatter scoped to the focus" in kernel.checkout(sid, "store", focus=["Repo.add"]).frame_markdown
    # a focus on the guarded function keeps its own invariant in view
    own = _meta(kernel.checkout(sid, "store", focus=["guarded"]))
    assert own["invariants"] == ["call:guarded(n=-1) raises ValueError"] and "invariants_elided" not in own
    # the frame on disk is never scoped
    on_disk = yaml.safe_load((tmp_path / ".stepcheck" / "okf" / "store.md").read_text(encoding="utf-8").split("---\n")[1])
    assert len(on_disk["exports"]) == 6 and "exports_elided" not in on_disk


# ------------------------------- 4. unfocused budget ladder keeps every public name


def _huge(classes: int, functions: int) -> str:
    out = ['"""Huge module."""', "import json", "import os", "import re", ""]
    for i in range(classes):
        out.append(f"class Model{i}:\n    \"\"\"Model number {i} with a docstring that costs tokens.\"\"\"\n"
                   f"    def __init__(self, value_{i}: int = {i}, label: str = 'model-{i}', retries: int = 3) -> None:\n        self.v = value_{i}\n"
                   f"    def _check_{i}(self, candidate: int, strict: bool = False) -> bool:\n        return candidate >= 0\n"
                   f"    def _render_{i}(self, width: int = 80, indent: int = 4) -> str:\n        return str(self.v)\n\n")
    for i in range(functions):
        out.append(f"def build_{i}(payload: dict, retries: int = {i}, label: str = 'build-{i}', strict: bool = True) -> dict:\n"
                   f"    \"\"\"Builder number {i}.\"\"\"\n    return {{'id': {i}, 'size': len(payload)}}\n\n")
    return "\n".join(out)


def test_unfocused_over_budget_module_climbs_the_ladder_but_keeps_every_public_name(kernel, tmp_path):
    (tmp_path / "huge.py").write_text(_huge(120, 40), encoding="utf-8", newline="\n")
    sid = kernel.init_session(tmp_path)
    payload = kernel.checkout(sid, "huge", focus=[])
    assert payload.token_count < BUDGET and not payload.auto_skeletonized
    assert payload.elided and "Budget backstop" in payload.frame_markdown
    body = _body(payload)
    for i in range(120):
        assert f"class Model{i}:" in body
    for i in range(40):
        assert f"def build_{i}(" in body
    assert "_check_0" not in body and "Model number" not in body  # private members and docstrings went
    assert "# + 3 method signatures elided" in body  # each stub says what it hides
    meta = _meta(payload)
    assert meta.get("exports_elided", 0) + len(meta["exports"]) == 160  # counts stand in for the lists

    # the same ladder never touches a module that fits
    small = kernel.checkout(sid, "huge", focus=["build_0"])
    assert small.token_count < BUDGET and "def build_0(" in small.frame_markdown


# ------------------------------------------- 5. self-hosted: the kernel's own class


def test_statekernel_method_focus_is_half_the_class_focus_on_the_real_kernel(kernel, tmp_path):
    root = tmp_path / "backend"
    shutil.copytree(BACKEND, root, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".stepcheck"))
    sid = kernel.init_session(root)
    whole = kernel.checkout(sid, "kernel.__init__", focus=["StateKernel"])
    method = kernel.checkout(sid, "kernel.__init__", focus=["StateKernel.commit"])
    assert "Stage either a full `source`" in method.frame_markdown  # the method, verbatim
    assert "Frontmatter scoped to the focus" in method.frame_markdown
    # Measured 2026-11-03 (receipts/slice21_metrics_{before,after}.json, own_backend):
    # before Slice 21 the method view was 2,076 tokens against 5,718 for the class
    # (36.3%); after, 1,904 against 5,535 (34.4%). Slices 23–24 then added
    # `record_event`, `events` and `compliance_bundle` to StateKernel: 2,046
    # against 6,789 (30.1%). The method view tracks the class's own signatures
    # by design, so the absolute floor carries headroom for that growth.
    # Slice 27 renders the same-file callees of the focus verbatim, within a
    # 1,000-token callee budget (`_okf.CALLEE_TOKEN_BUDGET`): 3,063 against
    # 8,275 (37.0%) on 2026-11-05. v0.3.2 adds the class state (`__init__`)
    # to that cone, inside the same budget: 3,180 against 8,365 (38.0%) on
    # 2026-11-07. The floor is the old one plus that budget:
    assert method.token_count < 2300 + 1000, (method.token_count, whole.token_count)
    assert "of the focus, expanded verbatim: StateKernel.__init__, StateKernel._flush, StateKernel._get" in method.frame_markdown
    assert method.token_count <= 0.4 * whole.token_count, (method.token_count, whole.token_count)
