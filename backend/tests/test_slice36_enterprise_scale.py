"""Slice 36 — enterprise scale without weakening a gate.

1. Function-incremental analysis: a commit that changes one symbol re-mines only that symbol;
   the result is byte-identical to a full analysis of the same source (soundness), and the
   kernel reports the work it skipped through `perf_stats()`.
2. Gate C skips the sandbox when no runtime `call:` probe can be affected by the edit (the
   probe's function, everything it names, and the module level are untouched); it still runs
   when they are, and a weakened guard anywhere is still rejected.
3. Content-addressed analysis cache: a second kernel on the same tree reads the per-file cache
   instead of re-mining; an ephemeral kernel never writes it.
4. Enterprise file discovery: generated and vendored paths are not indexed, `.gitignore` is
   honoured inside a git repository.
5. Resilience: a file in a newer Python syntax is left untracked instead of aborting the index;
   deep nesting, BOM + CRLF and circular `import *` packages index and commit.
"""
from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

from kernel import StateKernel

BACKEND = Path(__file__).resolve().parents[1]


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, src in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(textwrap.dedent(src), encoding="utf-8", newline="\n")
    return root


def _node(kernel: StateKernel, sid: str, rel: str) -> dict:
    return next(n for n in kernel.graph(sid)["nodes"] if n["path"].replace("\\", "/") == rel)


def _facts(n: dict) -> tuple:
    return (n["exports"], n["preserved_symbols"], n["invariants"], n["invariants_auto_mined"], n["deps"])


BIG = "import os\n\nLIMIT = 10\n\n\n" + "".join(
    f"def f{i}(x):\n    if x < 0:\n        raise ValueError({i})\n    if x > LIMIT:\n        return None\n    return x + {i}\n\n\n"
    for i in range(60)
) + "class Box:\n" + "".join(
    f"    def m{i}(self, v):\n        if v is None:\n            raise TypeError({i})\n        assert v != {i}\n        return v\n\n"
    for i in range(40)
) + "\n\ndef far():\n    return os.sep\n"


# ------------------------------------------------- 1. incremental analysis is sound


@pytest.mark.parametrize("module", sorted(p.name for p in (BACKEND / "kernel").glob("*.py")) + ["hooks.py", "cli.py", "server.py"])
def test_an_incremental_commit_mines_exactly_what_a_full_analysis_mines(kernel, tmp_path, module):
    """For every module of this repo: insert a no-op into one function and commit; the node's
    facts must equal those of a fresh session indexed on the edited source."""
    src_path = (BACKEND / "kernel" / module) if (BACKEND / "kernel" / module).exists() else BACKEND / module
    src = src_path.read_text(encoding="utf-8").replace("\r\n", "\n")
    root = _write(tmp_path / "a", {"m.py": src})
    sid = kernel.init_session(root)
    lines = src.split("\n")
    target = next((i for i, ln in enumerate(lines) if ln.startswith("def ") or ln.startswith("    def ")), None)
    if target is None:
        pytest.skip("no def")
    # the first statement line of that def, at its indentation
    j = target + 1
    while j < len(lines) and (not lines[j].strip() or lines[j].lstrip().startswith(('"""', "'''", "#"))):
        j += 1
    indent = lines[j][: len(lines[j]) - len(lines[j].lstrip())]
    edited = "\n".join(lines[: j] + [f"{indent}_stepcheck_probe = 0"] + lines[j:])
    before = kernel.perf_stats()
    # declared: a flat copy of a package module cannot be imported for its runtime probes;
    # the analysis under test runs the same way either way
    v = kernel.commit(sid, "m", source=edited, allow_deletion=True)
    if not v.accepted and "failed to load" in str(v.error):
        pytest.skip("hand-written invariants need the module importable; a flat copy is not")
    assert v.accepted, (module, v.gate, str(v.error)[:160])
    after = kernel.perf_stats()
    assert after["analysis_incremental"] > before["analysis_incremental"], module
    fresh = StateKernel().init_session(_write(tmp_path / "b", {"m.py": edited}))
    assert _facts(_node(kernel, sid, "m.py")) == _facts(_node(StateKernel(), fresh, "m.py")), module


def test_incremental_commit_on_a_large_module_touches_one_symbol(kernel, tmp_path):
    root = _write(tmp_path, {"big.py": BIG})
    sid = kernel.init_session(root)
    base = kernel.perf_stats()
    v = kernel.commit(sid, "big", source=BIG.replace("def f30(x):\n", "def f30(x):\n    _ = 0\n"))
    assert v.accepted, str(v.error)
    now = kernel.perf_stats()
    assert now["analysis_incremental"] == base["analysis_incremental"] + 1
    assert now["symbols_remined"] - base["symbols_remined"] == 1
    assert now["gate_c_symbols_checked"] - base["gate_c_symbols_checked"] == 1
    # a module-level change (the constant every guard reads) is a full analysis again
    v = kernel.commit(sid, "big", source=kernel.node_source(sid, "big").replace("LIMIT = 10", "LIMIT = 11"))
    assert v.accepted, str(v.error)
    assert kernel.perf_stats()["analysis_full"] == now["analysis_full"] + 1
    assert kernel.perf_stats()["analysis_incremental"] == now["analysis_incremental"]


# ------------------------------------------------- 2. Gate C sandbox is skipped when unaffected


def test_gate_c_loads_the_sandbox_only_when_a_probe_can_be_affected(kernel, tmp_path):
    root = _write(tmp_path, {"big.py": BIG})
    sid = kernel.init_session(root)
    assert any(i.startswith("call:f0(") for i in _node(kernel, sid, "big.py")["invariants"])  # runtime probes exist
    loads = kernel.perf_stats()["gate_c_sandbox_loads"]
    v = kernel.commit(sid, "big", source=BIG.replace("def far():\n    return os.sep\n", "def far():\n    return os.sep * 2\n"))
    assert v.accepted and kernel.perf_stats()["gate_c_sandbox_loads"] == loads  # far() reaches no probe
    src = kernel.node_source(sid, "big")
    v = kernel.commit(sid, "big", source=src.replace("def f0(x):\n    if x < 0:", "def f0(x):\n    x = int(x)\n    if x < 0:"))
    assert v.accepted and kernel.perf_stats()["gate_c_sandbox_loads"] == loads + 1  # f0 carries a probe
    src = kernel.node_source(sid, "big")
    v = kernel.commit(sid, "big", source=src.replace("LIMIT = 10", "LIMIT = 12"))
    assert v.accepted and kernel.perf_stats()["gate_c_sandbox_loads"] == loads + 2  # module level: everything
    # weakenings are still Gate C wherever they are, sandbox or not
    src = kernel.node_source(sid, "big")
    for old, new in (("def f0(x):\n    x = int(x)\n    if x < 0:", "def f0(x):\n    x = int(x)\n    if x < -1:"),
                     ("    def m7(self, v):\n        if v is None:\n            raise TypeError(7)\n", "    def m7(self, v):\n"),
                     ("        assert v != 39\n", "        assert v != 40\n")):
        assert src.count(old) == 1, old
        v = kernel.commit(sid, "big", source=src.replace(old, new))
        assert not v.accepted and v.gate == "C", (old, v.gate, str(v.error)[:120])


# ------------------------------------------------- 3. content-addressed cache


def test_a_second_kernel_reads_the_analysis_cache_and_an_ephemeral_one_writes_nothing(tmp_path):
    root = _write(tmp_path / "p", {"a.py": "def f(x):\n    if x < 0:\n        raise ValueError(x)\n    return x\n",
                                   "b.py": "from a import f\n\n\ndef g(y):\n    return f(y)\n"})
    k1 = StateKernel()
    sid1 = k1.init_session(root)
    assert len(list((root / ".stepcheck" / "cache" / "analysis").glob("*.json"))) >= 2
    k2 = StateKernel()  # same process: the memory cache answers
    before = k2.perf_stats()
    sid2 = k2.init_session(root)
    assert k2.perf_stats()["analysis_memory_hits"] >= before["analysis_memory_hits"] + 2
    assert _facts(_node(k1, sid1, "a.py")) == _facts(_node(k2, sid2, "a.py"))
    assert _facts(_node(k1, sid1, "b.py")) == _facts(_node(k2, sid2, "b.py"))
    # a fresh process: the on-disk cache answers, and the facts are identical
    import json as _json
    import os
    import subprocess as _sp
    import sys
    code = ("import json, sys; sys.path.insert(0, sys.argv[1]); from kernel import StateKernel; k = StateKernel(); "
            "sid = k.init_session(sys.argv[2]); n = {x['path']: [x['exports'], x['preserved_symbols'], x['invariants'], "
            "x['invariants_auto_mined'], x['deps']] for x in k.graph(sid)['nodes']}; print(json.dumps([k.perf_stats(), n]))")
    done = _sp.run([sys.executable, "-c", code, str(BACKEND), str(root)], capture_output=True, text=True, env={**os.environ, "PYTHONUTF8": "1"}, timeout=120)
    assert done.returncode == 0, done.stderr[-400:]
    stats, facts = _json.loads(done.stdout.strip().splitlines()[-1])
    assert stats["analysis_disk_hits"] >= 2 and stats["analysis_full"] == 0
    assert facts["a.py"] == list(_facts(_node(k1, sid1, "a.py"))) and facts["b.py"] == list(_facts(_node(k1, sid1, "b.py")))
    clean = _write(tmp_path / "q", {"a.py": "x = 1\n"})
    StateKernel(ephemeral=True).init_session(clean)
    assert not (clean / ".stepcheck").exists()


# ------------------------------------------------- 4. file discovery


NOISE = {
    "app/models.py": "class User:\n    pass\n",
    "app/migrations/0001_initial.py": "x = 1\n",
    "app/migrations/__init__.py": "",
    "proto/foo_pb2.py": "# Generated by the protocol buffer compiler.  DO NOT EDIT!\ny = 2\n",
    "proto/foo_pb2_grpc.py": "import grpc\n",
    "web/index.d.ts": "export declare function f(x: number): number;\n",
    "web/bundle.min.js": "!function(){var a=1}();\n",
    "web/app.generated.ts": "export const g = 1;\n",
    "web/src/app.ts": "export function run(x: number): number {\n  return x;\n}\n",
    "vendor/lib/x.py": "def v():\n    return 1\n",
    "dist/out.py": "x = 1\n",
    "build/lib/pkg/m.py": "y = 2\n",
    ".next/server/page.js": "module.exports = {};\n",
    "target/debug/gen.rs": "fn g() {}\n",
    "artifacts/big.py": "def gen(a):\n    return a\n",
    "tools/keep.py": "def keep():\n    return 1\n",
}


def test_generated_vendored_and_gitignored_files_are_not_indexed(kernel, tmp_path):
    root = _write(tmp_path, {**NOISE, ".gitignore": "artifacts/\ntools/keep.py\n"})
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    paths = {n["path"].replace("\\", "/") for n in kernel.graph(kernel.init_session(root))["nodes"]}
    assert paths == {"app/models.py", "web/src/app.ts"}


def test_generated_patterns_are_skipped_without_git_too(kernel, tmp_path):
    root = _write(tmp_path, NOISE)  # no .gitignore, no repository
    paths = {n["path"].replace("\\", "/") for n in kernel.graph(kernel.init_session(root))["nodes"]}
    assert paths == {"app/models.py", "web/src/app.ts", "artifacts/big.py", "tools/keep.py"}


# ------------------------------------------------- 5. resilience


def test_a_file_in_a_newer_python_syntax_is_left_untracked_not_fatal(kernel, tmp_path):
    root = _write(tmp_path, {"modern.py": "type Username = ???\n\n\ndef f(x):\n    return x\n",
                             "ok.py": "def g(y):\n    if y < 0:\n        raise ValueError(y)\n    return y\n"})
    sid = kernel.init_session(root)
    paths = {n["path"] for n in kernel.graph(sid)["nodes"]}
    assert "ok.py" in paths and "modern.py" not in paths
    assert kernel.commit(sid, "ok", source="def g(y):\n    if y < 0:\n        raise ValueError(y)\n    return y + 0\n").accepted


def test_deep_nesting_indexes_and_commits_or_is_left_untracked_past_the_parser_limit(kernel, tmp_path):
    def nested(depth: int) -> str:
        return "def deep(x):\n" + "".join("    " * (i + 1) + f"if x > {i}:\n" for i in range(depth)) + "    " * (depth + 1) + "return x\n    return 0\n"

    root = _write(tmp_path, {"deep.py": nested(90), "deeper.py": nested(300), "ok.py": "def f():\n    return 1\n"})
    sid = kernel.init_session(root)  # CPython's parser refuses 100+ indentation levels: that file is untracked, nothing crashes
    paths = {n["path"] for n in kernel.graph(sid)["nodes"]}
    assert "deep.py" in paths and "ok.py" in paths and "deeper.py" not in paths
    v = kernel.commit(sid, "deep", source=nested(90).replace("return 0", "return 1"))
    assert v.accepted, str(v.error)[:160]
    v = kernel.commit(sid, "deep", source=nested(300))  # growing past the limit is a Gate A verdict, not an exception
    assert not v.accepted and v.gate == "A"


def test_bom_crlf_and_circular_star_imports_survive(kernel, tmp_path):
    root = _write(tmp_path, {
        "pkg/__init__.py": "from .a import *\nfrom .b import *\n",
        "pkg/a.py": "from . import b\n\n\ndef fa(x):\n    if x < 0:\n        raise ValueError(x)\n    return b.fb(x) + 1\n",
        "pkg/b.py": "from . import a\n\n\ndef fb(x):\n    if x > 100:\n        raise ValueError(x)\n    return x\n\n\ndef uses_a(y):\n    return a.fa(y)\n",
        "consumer.py": "from pkg import fa, fb\n\n\ndef run(v):\n    return fa(v) + fb(v)\n",
    })
    raw = (root / "pkg" / "a.py").read_bytes()
    (root / "pkg" / "a.py").write_bytes(b"\xef\xbb\xbf" + raw.replace(b"\n", b"\r\n"))
    sid = kernel.init_session(root)
    ids = {n["path"].replace("\\", "/"): n["node_id"] for n in kernel.graph(sid)["nodes"]}
    v = kernel.commit(sid, ids["pkg/a.py"], source="from . import b\n\n\ndef fa(x, strict=False):\n    if x < 0:\n        raise ValueError(x)\n    return b.fb(x) + 1\n")
    assert v.accepted, str(v.error)[:160]
    assert (root / "pkg" / "a.py").read_bytes().startswith(b"\xef\xbb\xbf") and b"\r\n" in (root / "pkg" / "a.py").read_bytes()
    assert kernel.omission_report(sid)["can_finalize"] in (True, False)  # terminated; no infinite propagation
