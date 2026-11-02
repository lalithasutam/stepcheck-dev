"""Slice 12 — CI hardening: UTF-8-safe CLI output on piped stdout, a side-effect-free
`stepcheck ci`, no stdlib shadowing by sub-directory aliases, LF-normalized checkouts
(Seam 1 + CLI seam)."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import cli
from kernel import StateKernel

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
FIXTURE = REPO / "benchmarks" / "fixtures" / "sample_session.jsonl"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def _tree(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*") if p.is_file()
    }


def _node(kernel, sid, nid) -> dict:
    return next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == nid)


# ------------------------------------------- 1. the Windows runner failure


def _cli_piped_through_cp1252(*argv: str) -> subprocess.CompletedProcess:
    """Run the real CLI entry point with stdout as a cp1252 pipe — what a Windows
    CI runner gives a Python process — and capture the raw bytes."""
    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    return subprocess.run(
        [sys.executable, "-m", "cli", *argv], cwd=BACKEND, env=env, capture_output=True, timeout=300
    )


def test_benchmark_output_survives_a_cp1252_pipe():
    done = _cli_piped_through_cp1252("benchmark")
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")[-800:]
    assert b"UnicodeEncodeError" not in done.stderr
    out = done.stdout.decode("utf-8")  # strict: the pipe must carry UTF-8, not mojibake
    assert "ALL CAUGHT ✓" in out and "→" in out


def test_audit_and_ci_output_survive_a_cp1252_pipe(tmp_path):
    audit = _cli_piped_through_cp1252("audit", str(FIXTURE), "--out", str(tmp_path / "r.html"))
    assert audit.returncode == 0, audit.stderr.decode("utf-8", "replace")[-800:]
    assert "receipt →" in audit.stdout.decode("utf-8")

    _write(tmp_path / "proj" / "m.py", "def f(x: int) -> int:\n    return x\n")
    ci = _cli_piped_through_cp1252("ci", str(tmp_path / "proj"))
    assert ci.returncode == 0, ci.stderr.decode("utf-8", "replace")[-800:]
    assert "stepcheck ci: PASS —" in ci.stdout.decode("utf-8")


# ---------------------------------------------- 2. ci is side-effect free


def test_ci_never_touches_stepcheck_state(kernel, project, capsys):
    home = Path(os.environ["STEPCHECK_HOME"])
    sid = kernel.init_session(project)
    assert kernel.commit(sid, "billing", patch=[{"op": "append", "code": "def _h() -> int:\n    return 1\n"}]).accepted
    state_before = _tree(project / ".stepcheck")
    registry_before = (home / "sessions.json").read_bytes()
    assert state_before  # frames + a session file exist to be protected

    assert cli.main(["ci", str(project)]) == 0, capsys.readouterr().out

    assert _tree(project / ".stepcheck") == state_before
    assert (home / "sessions.json").read_bytes() == registry_before
    assert json.loads(registry_before) == {sid: str(project.resolve())}


def test_ci_on_a_pristine_project_creates_no_state(tmp_path, capsys):
    _write(tmp_path / "m.py", "def f(x: int) -> int:\n    if x < 0:\n        raise ValueError(x)\n    return x\n")
    home = Path(os.environ["STEPCHECK_HOME"])

    assert cli.main(["ci", str(tmp_path)]) == 0, capsys.readouterr().out

    assert not (tmp_path / ".stepcheck").exists()
    assert not home.exists() or not (home / "sessions.json").exists()


def test_ephemeral_kernel_verifies_without_writing_anything(project):
    home = Path(os.environ["STEPCHECK_HOME"])
    before = {p.name: p.read_bytes() for p in project.glob("*.py")}
    kernel = StateKernel(ephemeral=True)
    sid = kernel.init_session(project)

    v = kernel.commit(sid, "billing", patch=[{"op": "append", "code": "def _h() -> int:\n    return 1\n"}])

    assert v.accepted, v.error
    assert v.attestation["payload"]["sha256"]  # attests the bytes that *would* land
    assert {p.name: p.read_bytes() for p in project.glob("*.py")} == before
    assert not (project / ".stepcheck").exists()
    assert not (home / "sessions.json").exists()
    # still a full kernel: dirty propagation and the graph work in memory
    assert _node(kernel, sid, "billing")["status"] == "VERIFIED"


# ------------------------------------- 3. aliases never shadow the stdlib


def test_subdirectory_aliases_never_shadow_stdlib_modules(kernel, tmp_path):
    _write(tmp_path / "app" / "utils" / "json.py", "def loads(_: str) -> dict:\n    return {}\n")
    _write(tmp_path / "app" / "utils" / "__init__.py", "")
    _write(
        tmp_path / "app" / "main.py",
        "import json\n\n\n"
        '# okf-invariant: ns["encode"]({"a": 1}) == \'{"a": 1}\'\n'
        "def encode(d: dict) -> str:\n    return json.dumps(d)\n",
    )
    sid = kernel.init_session(tmp_path)

    assert _node(kernel, sid, "main")["deps"] == []  # `import json` is the stdlib, not app/utils/json.py
    ok = kernel.commit(sid, "main", patch=[{"op": "append", "code": "LIMIT = 1\n"}])
    assert ok.accepted, ok.error  # Gate C ran against the real json module


# --------------------------------------------- 5. stale frames from old sessions


def _orphan_frame(project: Path, name: str) -> Path:
    """A frame left behind by a session that named this node differently (as the
    repo's own `__init__` -> `backend.kernel.__init__` rename did): same path,
    stale attestation."""
    okf = project / ".stepcheck" / "okf"
    text = (okf / "billing.md").read_text(encoding="utf-8").replace("node_id: billing", f"node_id: {name}")
    ghost = okf / f"{name}.md"
    ghost.write_text(text, encoding="utf-8")
    return ghost


def test_ci_ignores_frames_of_nodes_no_longer_tracked(kernel, project, capsys):
    sid = kernel.init_session(project)
    v = kernel.commit(sid, "billing", patch=[{"op": "append", "code": "def _h() -> int:\n    return 1\n"}])
    assert v.accepted
    # Planted after the kernel's last write (every flush prunes untracked frames)
    # and carrying a sha256 that matches nothing on disk.
    ghost = _orphan_frame(project, "old_billing")
    ghost.write_text(
        ghost.read_text(encoding="utf-8").replace(v.attestation["payload"]["sha256"], "0" * 64),
        encoding="utf-8",
    )

    rc = cli.main(["ci", str(project)])

    assert rc == 0, capsys.readouterr().out
    assert ghost.exists()  # ci is ephemeral: it ignores the ghost, it does not clean it up


def test_init_session_prunes_frames_of_nodes_it_does_not_track(kernel, project):
    kernel.init_session(project)
    ghost = _orphan_frame(project, "old_billing")
    assert ghost.exists()

    kernel.init_session(project)

    assert not ghost.exists()
    index = (project / ".stepcheck" / "okf" / "index.md").read_text(encoding="utf-8")
    assert "old_billing" not in index and "billing.md" not in index  # index lists node ids, no ghosts


def test_ci_accepts_a_bom_prefixed_module_like_the_kernel_does(tmp_path, capsys):
    # Windows editors (and PowerShell's -Encoding utf8) prepend U+FEFF; the kernel strips it.
    (tmp_path / "m.py").write_bytes(b"\xef\xbb\xbf" + b"def f(x: int) -> int:\n    return x\n")

    assert cli.main(["ci", str(tmp_path)]) == 0, capsys.readouterr().out


# ---------------------------------------------------- 4. LF everywhere


def test_gitattributes_pins_lf_so_hashes_match_across_oses():
    rules = [ln.split() for ln in (REPO / ".gitattributes").read_text(encoding="utf-8").splitlines()
             if ln.strip() and not ln.startswith("#")]
    assert ["*", "text=auto", "eol=lf"] in rules
