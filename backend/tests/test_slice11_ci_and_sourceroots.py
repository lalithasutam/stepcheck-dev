"""Slice 11 — source-root imports from the repo root, trimmed persistence I/O,
`stepcheck ci`, and the GitHub Actions workflow (Seam 1 + CLI seam)."""
import hashlib
import json
import os
import shutil
import time
from pathlib import Path

import yaml

import cli
from kernel import StateKernel

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".stepcheck")


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


APPEND_H = [{"op": "append", "code": "def _h() -> int:\n    return 1\n"}]


# ------------------------------------------------ 1. source roots from repo root

K_INIT = '''\
from . import rules


def charge(amount: int) -> dict:
    return {"amount": rules.check(amount)}
'''

K_RULES = '''\
def check(amount: int) -> int:
    if amount <= 0:
        raise ValueError("amount must be positive")
    return amount
'''

SERVER = '''\
from kernel import charge


# okf-invariant: call:handle(0) raises ValueError
def handle(amount: int) -> dict:
    return charge(amount)
'''


def _backend_layout(root: Path) -> Path:
    _write(root / "backend" / "__init__.py", "")
    _write(root / "backend" / "kernel" / "__init__.py", K_INIT)
    _write(root / "backend" / "kernel" / "rules.py", K_RULES)
    _write(root / "backend" / "server.py", SERVER)
    _write(root / "README.md", "# not python\n")
    return root


def test_backend_subroot_imports_resolve_from_the_repo_root(kernel, tmp_path):
    sid = kernel.init_session(_backend_layout(tmp_path))

    assert _ids(kernel, sid) == {
        "backend.__init__": "backend/__init__.py",
        "backend.kernel.__init__": "backend/kernel/__init__.py",
        "rules": "backend/kernel/rules.py",
        "server": "backend/server.py",
    }
    assert _node(kernel, sid, "server")["deps"] == ["backend.kernel.__init__"]
    assert _node(kernel, sid, "backend.kernel.__init__")["deps"] == ["rules"]

    # Gate C execs backend/server.py: `from kernel import charge` must bind the
    # canonical package (two hops down to the mined guard), not whatever sys.path holds.
    ok = kernel.commit(sid, "server", patch=[{"op": "append", "code": 'def ping() -> str:\n    return "pong"\n'}])
    assert ok.accepted, ok.error
    assert _sha(tmp_path / "backend" / "server.py") == ok.attestation["payload"]["sha256"]

    # Still calls charge (so Gate B's preserved `call:charge` is intact) but swallows
    # the guard: only the hand-written invariant, evaluated through the alias, catches it.
    weak = kernel.commit(
        sid, "server",
        patch=_replace(
            "handle",
            "def handle(amount: int) -> dict:\n"
            "    try:\n"
            "        return charge(amount)\n"
            "    except ValueError:\n"
            '        return {"amount": amount}\n',
        ),
    )
    assert weak.gate == "C" and "call:handle(0)" in str(weak.error)

    # Gate A sees through the alias: svc code imports `charge` via `from kernel import charge`.
    gone = kernel.commit(
        sid, "backend.kernel.__init__", patch=[{"op": "delete_symbol", "name": "charge"}], allow_deletion=True
    )
    assert gone.gate == "A" and "server" in str(gone.error)


def test_src_layout_resolves_from_the_repo_root(kernel, tmp_path):
    _write(tmp_path / "src" / "pkg" / "__init__.py", "")
    _write(tmp_path / "src" / "pkg" / "core.py", 'def run(n: int) -> int:\n    if n < 0:\n        raise ValueError("n")\n    return n\n')
    _write(tmp_path / "src" / "app.py", "from pkg.core import run\n\n\n# okf-invariant: call:main(-1) raises ValueError\ndef main(n: int) -> int:\n    return run(n)\n")
    sid = kernel.init_session(tmp_path)

    assert _ids(kernel, sid) == {"__init__": "src/pkg/__init__.py", "core": "src/pkg/core.py", "app": "src/app.py"}
    assert _node(kernel, sid, "app")["deps"] == ["core"]
    ok = kernel.commit(sid, "app", patch=APPEND_H)
    assert ok.accepted, ok.error


def test_root_relative_names_win_and_ambiguous_aliases_resolve_to_nothing(kernel, tmp_path):
    _write(tmp_path / "helpers.py", "def top() -> int:\n    return 1\n")
    _write(tmp_path / "tools" / "helpers.py", "def nested() -> int:\n    return 2\n")
    _write(tmp_path / "a" / "util.py", "A = 1\n")
    _write(tmp_path / "b" / "util.py", "B = 2\n")
    _write(tmp_path / "main.py", "import helpers\nimport util\n\n\ndef go() -> int:\n    return helpers.top()\n")
    sid = kernel.init_session(tmp_path)

    assert set(_ids(kernel, sid)) == {"helpers", "tools.helpers", "a.util", "b.util", "main"}
    assert _node(kernel, sid, "main")["deps"] == ["helpers"]


def test_repo_root_session_resolves_stepchecks_backend_subroot(kernel, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(BACKEND, repo / "backend", ignore=IGNORE)
    sid = kernel.init_session(repo)

    assert "backend.kernel.__init__" in _node(kernel, sid, "server")["deps"]
    assert {"_okf", "_telemetry"} <= set(_node(kernel, sid, "audit")["deps"])
    assert "cli" in _node(kernel, sid, "test_audit_cli")["deps"]


# ------------------------------------------------------- 2. persistence I/O


def test_registry_is_a_light_index_and_unchanged_state_is_not_rewritten(kernel, project):
    home = Path(os.environ["STEPCHECK_HOME"])
    sid = kernel.init_session(project)
    root = str(project.resolve())
    assert json.loads((home / "sessions.json").read_text(encoding="utf-8")) == {sid: root}

    okf = project / ".stepcheck" / "okf"
    auth_md = okf / "auth.md"
    auth_md.write_bytes(auth_md.read_bytes() + b"\n<!-- survives only if unchanged frames are skipped -->\n")
    assert kernel.commit(sid, "billing", patch=APPEND_H).accepted
    assert b"<!-- survives" in auth_md.read_bytes()
    assert "def _h" in (okf / "billing.md").read_text(encoding="utf-8")

    session_file = project / ".stepcheck" / "sessions" / f"{sid}.json"
    kernel.lock_node(sid, "auth")
    before = (session_file.stat().st_mtime_ns, auth_md.stat().st_mtime_ns)
    time.sleep(0.05)
    kernel.lock_node(sid, "auth")  # idempotent: nothing mutated, nothing rewritten
    assert (session_file.stat().st_mtime_ns, auth_md.stat().st_mtime_ns) == before

    registry = home / "sessions.json"
    assert json.loads(registry.read_text(encoding="utf-8")) == {sid: root}
    assert registry.stat().st_size < 256


# -------------------------------------------------------------- 3. stepcheck ci


def _ci(path: Path, capsys) -> tuple[int, str]:
    rc = cli.main(["ci", str(path)])
    captured = capsys.readouterr()
    return rc, captured.out + captured.err


def test_ci_passes_a_clean_project_and_leaves_its_files_untouched(project, capsys):
    before = {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in project.glob("*.py")}
    time.sleep(0.05)

    rc, out = _ci(project, capsys)

    assert rc == 0, out
    assert "PASS" in out and "5 modules" in out
    for nid in ("admin", "auth", "billing", "reports", "unrelated_sibling"):
        assert nid in out
    assert {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in project.glob("*.py")} == before


def test_ci_fails_on_a_syntax_error_naming_the_file(project, capsys):
    _write(project / "broken.py", "def nope(:\n    pass\n")
    rc, out = _ci(project, capsys)
    assert rc == 1 and "broken.py" in out and "Gate A" in out


def test_ci_fails_when_an_invariant_does_not_hold(project, capsys):
    _write(project / "rules.py", '# okf-invariant: "def missing" in src\ndef present() -> int:\n    return 1\n')
    rc, out = _ci(project, capsys)
    assert rc == 1 and "rules" in out and "Gate C" in out and "def missing" in out


def test_ci_detects_attestation_drift_then_dirty_nodes(kernel, project, capsys):
    sid = kernel.init_session(project)
    assert kernel.commit(sid, "billing", patch=APPEND_H).accepted
    target = project / "billing.py"
    target.write_bytes(target.read_bytes() + b"\nTAMPERED = 1\n")  # edited behind the kernel's back

    rc, out = _ci(project, capsys)
    assert rc == 1 and "billing.py" in out and "sha256" in out.lower()

    sid2 = kernel.init_session(project)  # fresh session re-reads the disk and re-attests...
    sig = kernel.commit(
        sid2, "billing",
        patch=_replace(
            "charge",
            "@require_auth\ndef charge(user: str, amount_cents: int, currency: str = \"usd\") -> dict:\n"
            '    # okf-invariant: "amount_cents <= 0" in src and "raise ValueError" in src\n'
            "    if amount_cents <= 0:\n"
            '        raise ValueError("amount must be positive")\n'
            '    if not check_permission(user, "charge"):\n'
            "        raise PermissionError(user)\n"
            '    return {"user": user, "amount_cents": amount_cents, "status": "charged", "currency": currency}\n',
        ),
    )
    assert sig.accepted and sig.dirtied == ["reports"], sig.error

    rc, out = _ci(project, capsys)  # ...but leaves `reports` DIRTY_OMISSION_RISK
    assert rc == 1 and "reports" in out and "DIRTY_OMISSION_RISK" in out


def test_ci_verifies_a_copy_of_stepchecks_own_backend(tmp_path, capsys):
    shutil.copytree(BACKEND, tmp_path / "backend", ignore=IGNORE)
    rc, out = _ci(tmp_path / "backend", capsys)
    assert rc == 0, out
    assert "_okf" in out and "kernel.__init__" in out and "PASS" in out


# -------------------------------------------------------- 4. GitHub Actions


def test_github_actions_workflow_runs_tests_ci_and_benchmark_on_both_oses():
    wf = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    triggers = wf.get("on") or wf.get(True)  # PyYAML reads a bare `on:` key as True
    assert "push" in triggers and "pull_request" in triggers
    job = next(iter(wf["jobs"].values()))
    matrix = job["strategy"]["matrix"]
    assert set(matrix["os"]) == {"ubuntu-latest", "windows-latest"}
    assert [str(v) for v in matrix["python-version"]] == ["3.12"]
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    for command in ("pip install", "pytest -q", "stepcheck ci backend", "stepcheck benchmark"):
        assert command in runs, command
