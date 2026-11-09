"""Slice 37 — lazy sessions and the fast monolith path, without weakening a gate.

1. A one-function commit on a monolith parses only the edited block (the held tree is
   stitched), re-parses the whole file zero times, and mines exactly what a full analysis
   of the edited source mines.
2. A large tree is indexed lazily: paths, hashes and import edges only; no module is
   analysed until a checkout, a commit or a dependent needs it, and the session file holds
   no source text for a node whose bytes are recoverable.
3. A lazy node is judged against its baseline, never against the bytes a shell just wrote:
   the baseline comes back from git (a clean tree) or from the kept blob (no git).
4. A fresh process loads a lazy session without analysing anything; stored facts come back
   without the source text and a checkout still shows the committed code.
5. `verify_node`: Gate A plus the hand-written invariants of the bytes a node holds, no
   mining, no mutation — the read-only check `stepcheck ci` runs on unattested modules.
6. `stepcheck ci` skips a module whose latest attestation still matches its bytes (and whose
   dependencies do too), re-verifies the rest, and passes a tree holding a module this
   Python cannot parse, a star-import chain and a module whose third-party import is absent.
"""
from __future__ import annotations

import json
import subprocess
import textwrap
from pathlib import Path

import pytest

import cli
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


def _guarded(i: int) -> str:
    return f"def f{i}(x):\n    if x < 0:\n        raise ValueError({i})\n    return x + {i}\n"


def _chain(root: Path, n: int) -> Path:
    """mod_0 … mod_{n-1}; mod_i imports f{i-1} from mod_{i-1}. Every function carries a guard."""
    files = {}
    for i in range(n):
        head = f"from mod_{i - 1} import f{i - 1}\n\n\n" if i else ""
        files[f"mod_{i}.py"] = head + _guarded(i)
    return _write(root, files)


BIG = "import os\n\nLIMIT = 10\n\n\n" + "".join(
    f"def f{i}(x):\n    if x < 0:\n        raise ValueError({i})\n    if x > LIMIT:\n        return None\n    return x + {i}\n\n\n"
    for i in range(60)
) + "class Box:\n" + "".join(
    f"    def m{i}(self, v):\n        if v is None:\n            raise TypeError({i})\n        assert v != {i}\n        return v\n\n"
    for i in range(40)
) + "\n\ndef far():\n    return os.sep\n"


# ------------------------------------------------- 1. the stitched monolith commit


def test_a_one_function_commit_never_reparses_the_whole_module_and_mines_identical_facts(kernel, tmp_path):
    user = "from big import f7\n\n\ndef run(x):\n    return f7(x)\n"
    sid = kernel.init_session(_write(tmp_path / "a", {"big.py": BIG, "user.py": user}))
    old = "def f7(x):\n    if x < 0:\n        raise ValueError(7)\n    if x > LIMIT:\n        return None\n    return x + 7\n"
    new = old.replace("    return x + 7\n", "    y = x\n    return y + 7\n")
    assert BIG.count(old) == 1
    edited = BIG.replace(old, new)

    before = kernel.perf_stats()
    v = kernel.commit(sid, "big", source=edited)
    after = kernel.perf_stats()
    assert v.accepted, str(v.error)[:200]
    assert after["full_parses"] == before["full_parses"], "the whole module was parsed again"
    assert after["stitched"] == before["stitched"] + 1
    assert after["analysis_full"] == before["analysis_full"]

    fresh = StateKernel()
    sid2 = fresh.init_session(_write(tmp_path / "b", {"big.py": edited, "user.py": user}))
    assert _facts(_node(kernel, sid, "big.py")) == _facts(_node(fresh, sid2, "big.py"))


def test_a_syntax_error_inside_the_edited_function_is_a_gate_a_verdict(kernel, tmp_path):
    sid = kernel.init_session(_write(tmp_path, {"big.py": BIG}))
    broken = BIG.replace("    return x + 7\n", "    return x +\n", 1)
    v = kernel.commit(sid, "big", source=broken)
    assert not v.accepted and v.gate == "A" and "syntax" in str(v.error).lower()


# ------------------------------------------------- 2. lazy indexing


def test_a_large_tree_is_indexed_without_analysing_any_module(kernel, tmp_path, monkeypatch):
    monkeypatch.setenv("STEPCHECK_LAZY_THRESHOLD", "20")
    root = _chain(tmp_path, 40)
    before = kernel.perf_stats()
    sid = kernel.init_session(root)
    after = kernel.perf_stats()
    assert after["analysis_full"] == before["analysis_full"]
    assert after["full_parses"] == before["full_parses"]

    paths = kernel.node_paths(sid)
    assert len(paths) == 40 and paths["mod_7"] == "mod_7.py"
    text = (root / ".stepcheck" / "sessions" / f"{sid}.json").read_text(encoding="utf-8")
    data = json.loads(text)
    assert all("info" not in n for n in data["nodes"].values())
    assert data["nodes"]["mod_5"]["deps"] == ["mod_4"] and data["nodes"]["mod_0"]["deps"] == []
    assert '"source"' not in text
    assert len(text.encode("utf-8")) < 40 * 600


def test_a_checkout_materializes_one_node_and_a_commit_touches_only_its_neighbours(kernel, tmp_path, monkeypatch):
    monkeypatch.setenv("STEPCHECK_LAZY_THRESHOLD", "10")
    root = _chain(tmp_path, 30)
    sid = kernel.init_session(root)

    base = kernel.perf_stats()["analysis_full"]
    payload = kernel.checkout(sid, "mod_0", focus=[])  # a leaf: exactly one analysis
    assert "def f0" in payload.frame_markdown
    assert kernel.perf_stats()["analysis_full"] == base + 1
    assert kernel.locate(sid, root / "mod_19.py")["node_id"] == "mod_19"
    assert kernel.perf_stats()["analysis_full"] == base + 2  # the path match is free; the hit's invariants are its analysis

    v = kernel.commit(sid, "mod_12", source=_chain_source(12) + "\n\ndef extra(z):\n    return z\n")
    assert v.accepted, str(v.error)[:200]
    assert set(v.dirtied) | set(v.reverified) == {"mod_13"}  # the one dependent is judged, nothing else
    materialized = {n["node_id"] for n in kernel.graph(sid)["nodes"] if n["materialized"]}
    assert materialized == {"mod_0", "mod_19", "mod_12", "mod_13"}  # 26 modules never analysed
    assert kernel.perf_stats()["analysis_full"] <= base + 2 + 4  # baseline + staged for mod_12, baseline + re-verify for mod_13
    report = kernel.omission_report(sid)
    assert report["can_finalize"] or report["dirty"] == ["mod_13"]


def _chain_source(i: int) -> str:
    return (f"from mod_{i - 1} import f{i - 1}\n\n\n" if i else "") + _guarded(i)


# ------------------------------------------------- 3. baseline recovery


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "user.email=t@t", "-c", "user.name=t", *args],
                   cwd=root, check=True, capture_output=True, timeout=120)


@pytest.mark.parametrize("via", ["git", "blob"])
def test_a_shell_write_to_a_never_opened_lazy_file_is_judged_against_its_baseline(kernel, tmp_path, monkeypatch, via):
    monkeypatch.setenv("STEPCHECK_LAZY_THRESHOLD", "5")
    root = _chain(tmp_path, 12)
    if via == "git":
        _git(root, "init", "-q")
        _git(root, "add", "-A")
        _git(root, "commit", "-q", "-m", "baseline")
    sid = kernel.init_session(root)
    base = kernel.perf_stats()["analysis_full"]
    assert base == kernel.perf_stats()["analysis_full"]

    original = (root / "mod_7.py").read_text(encoding="utf-8")
    stripped = original.replace("    if x < 0:\n        raise ValueError(7)\n", "")
    assert stripped != original
    (root / "mod_7.py").write_text(stripped, encoding="utf-8", newline="\n")

    res = kernel.sync(sid)
    assert "mod_7" in res["rejected"] and res["rejected"]["mod_7"].startswith("C:"), res
    assert kernel.node_source(sid, "mod_7") == original  # the baseline, not the shell's bytes
    assert not any(e["kind"] == "baseline_lost" for e in kernel.events(sid))
    assert kernel.omission_report(sid)["rejected"] == ["mod_7"]


# ------------------------------------------------- 4. a fresh process


def test_a_fresh_process_loads_a_lazy_session_without_analysing_and_keeps_stored_facts_without_source(
    kernel, tmp_path, monkeypatch,
):
    monkeypatch.setenv("STEPCHECK_LAZY_THRESHOLD", "10")
    root = _chain(tmp_path, 25)
    sid = kernel.init_session(root)
    committed = _chain_source(3) + "\n\ndef extra(z):\n    return z\n"
    assert kernel.commit(sid, "mod_3", source=committed).accepted

    data = json.loads((root / ".stepcheck" / "sessions" / f"{sid}.json").read_text(encoding="utf-8"))
    assert "info" in data["nodes"]["mod_3"] and "source" not in data["nodes"]["mod_3"]["info"]
    assert data["nodes"]["mod_3"]["info"]["exports"]  # the facts are stored, the text is not
    assert "info" not in data["nodes"]["mod_20"]

    other = StateKernel()
    base = other.perf_stats()["analysis_full"]
    assert len(other.node_paths(sid)) == 25
    assert other.perf_stats()["analysis_full"] == base
    assert other.node_source(sid, "mod_3") == committed  # recovered from the disk bytes it attested
    payload = other.checkout(sid, "mod_3", focus=["extra"])
    assert "def extra(z):" in payload.frame_markdown
    assert other.perf_stats()["analysis_full"] == base  # stored facts: nothing re-mined
    assert other.omission_report(sid)["can_finalize"]


# ------------------------------------------------- 5. verify_node


def test_verify_node_runs_gate_a_and_the_hand_written_invariants_without_mining_or_mutating(kernel, tmp_path):
    root = _write(tmp_path, {
        "m.py": "def f(x):\n    # okf-invariant: \"raise ValueError\" in src\n    if x < 0:\n        raise ValueError(x)\n    return x\n",
        "consumer.py": "from m import f\n\n\ndef run(v):\n    return f(v)\n",
    })
    sid = kernel.init_session(root)
    base = kernel.perf_stats()
    v = kernel.verify_node(sid, "m")
    assert v.accepted and v.attestation is None and v.dirtied == []
    assert kernel.perf_stats()["analysis_full"] == base["analysis_full"]
    assert kernel.perf_stats()["symbols_remined"] == base["symbols_remined"]
    assert len(kernel.events(sid)) == 0 or all(e["kind"] != "commit" for e in kernel.events(sid))

    (root / "m.py").write_text("def f(x):\n    # okf-invariant: \"raise ValueError\" in src\n    return x\n", encoding="utf-8")
    kernel2 = StateKernel()  # a session opened on the broken tree holds exactly these bytes
    sid2 = kernel2.init_session(root)
    v = kernel2.verify_node(sid2, "m")
    assert not v.accepted and v.gate == "C"

    (root / "m.py").write_text("def g(x):\n    return x\n", encoding="utf-8")
    kernel3 = StateKernel()
    sid3 = kernel3.init_session(root)
    v = kernel3.verify_node(sid3, "m")
    assert not v.accepted and v.gate == "A" and "consumer" in str(v.error)


# ------------------------------------------------- 6. stepcheck ci


def test_ci_skips_attested_unchanged_modules_and_re_verifies_the_rest(tmp_path, capsys):
    root = _write(tmp_path, {
        "a.py": "def fa(x):\n    if x < 0:\n        raise ValueError(x)\n    return x\n",
        "b.py": "from a import fa\n\n\ndef fb(y):\n    return fa(y) + 1\n",
        "c.py": "from b import fb\n\n\ndef fc(z):\n    return fb(z) * 2\n",
    })
    kernel = StateKernel()
    sid = kernel.init_session(root)
    for nid in ("a", "b", "c"):
        assert kernel.commit(sid, nid, source=kernel.node_source(sid, nid)).accepted

    assert cli.main(["ci", str(root)]) == 0
    out = capsys.readouterr().out
    assert out.count("ATTESTED") == 3 and "PASS" in out
    assert "3 attested" in out

    _write(root, {"d.py": "from c import fc\n\n\ndef fd(w):\n    # okf-invariant: call:fd(1) == 4\n    return fc(w)\n"})
    assert cli.main(["ci", str(root)]) == 0
    out = capsys.readouterr().out
    assert out.count("ATTESTED") == 3 and "  d " in out and "1 invariant" in out


def test_ci_passes_a_tree_with_an_unparsable_file_a_star_import_chain_and_an_absent_third_party_import(tmp_path, capsys):
    root = _write(tmp_path, {
        "pkg/__init__.py": "from .a import *\n",
        "pkg/a.py": "def fa(x):\n    if x < 0:\n        raise ValueError(x)\n    return x\n",
        "consumer.py": "from pkg import fa\n\n\ndef run(v):\n    return fa(v)\n",
        "modern.py": "type Username = str\n\n\ndef f(x):\n    return x\n",
        "envdep.py": ("import no_such_third_party_pkg_xyz\n\n\n"
                      "def g(x):\n    # okf-invariant: call:g(-1) raises ValueError\n"
                      "    if x < 0:\n        raise ValueError(x)\n    return x\n"),
    })
    code = cli.main(["ci", str(root)])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "modern.py" in out and "cannot parse" in out
    assert "envdep" in out and "ENV" in out
    assert "stepcheck ci: PASS" in out


def test_ci_parses_each_unattested_module_once(tmp_path, capsys):
    root = _chain(tmp_path, 12)
    before = StateKernel().perf_stats()["full_parses"]
    assert cli.main(["ci", str(root)]) == 0, capsys.readouterr().out
    assert StateKernel().perf_stats()["full_parses"] - before <= 12  # parse phase; Gate A and the import contracts reuse it


def test_the_index_frame_is_still_yaml_and_lists_every_edge(kernel, tmp_path):
    import yaml

    root = _chain(tmp_path, 6)
    sid = kernel.init_session(root)
    front = (root / ".stepcheck" / "okf" / "index.md").read_text(encoding="utf-8").split("---\n")[1]
    meta = yaml.safe_load(front)
    assert meta["node_id"] == "__index__" and meta["nodes"] == sorted(kernel.node_paths(sid))
    assert "mod_3 -> mod_2" in meta["edges"] and len(meta["edges"]) == 5


def test_a_root_that_is_itself_a_package_imports_as_that_package(tmp_path, capsys):
    """A session opened on `django/` (the package, not the repository): `from django import
    forms` reaches `forms/__init__.py`, not a file that happens to be named `django.py`,
    and `from http import cookies` is the standard library, not `http/__init__.py`."""
    root = _write(tmp_path / "django", {
        "__init__.py": "VERSION = (6, 0)\n",
        "forms/__init__.py": "def Form(x):\n    if x is None:\n        raise ValueError(x)\n    return x\n",
        "template/backends/django.py": "def engine():\n    return 'django'\n",
        "contrib/admin/helpers.py": "from django import forms\n\n\ndef helper(v):\n    return forms.Form(v)\n",
        "http/__init__.py": "from .cookie import parse\n",
        "http/cookie.py": "from http import cookies\n\n\ndef parse(s):\n    return cookies.SimpleCookie(s)\n",
    })
    kernel = StateKernel()
    sid = kernel.init_session(root)
    ids = {n["path"].replace("\\", "/"): n["node_id"] for n in kernel.graph(sid)["nodes"]}
    assert ids["forms/__init__.py"] in _node(kernel, sid, "contrib/admin/helpers.py")["deps"]
    assert ids["template/backends/django.py"] not in _node(kernel, sid, "contrib/admin/helpers.py")["deps"]
    assert _node(kernel, sid, "http/cookie.py")["deps"] == []
    v = kernel.commit(sid, ids["template/backends/django.py"], source="def engine():\n    return 'django-templates'\n")
    assert v.accepted, str(v.error)[:200]
    assert cli.main(["ci", str(root)]) == 0, capsys.readouterr().out


CONDITIONAL = '''\
import sys

try:
    import ujson as json_impl
except ImportError:
    def loads(text):
        if not text:
            raise ValueError("empty")
        return text

if sys.platform == "win32":
    def lock_file(handle):
        if handle is None:
            raise OSError("no handle")
        return True
else:
    def lock_file(handle):
        if handle is None:
            raise OSError("no handle")
        return False


def f(x):
    if x < 0:
        raise ValueError(x)
    return x + 1


def g(y):
    return y * 2
'''


def test_invariants_of_defs_nested_in_module_level_blocks_survive_an_incremental_commit(kernel, tmp_path):
    """Commit 1 edits an unrelated top-level function: the guards of the `try:`- and
    `if sys.platform`-nested functions stay on record (and equal a from-scratch analysis);
    Commit 2 drops the guard inside the `try:`-nested function and is blocked at Gate C."""
    root = _write(tmp_path / "a", {"cond.py": CONDITIONAL})
    sid = kernel.init_session(root)
    before = set(_node(kernel, sid, "cond.py")["invariants_auto_mined"])
    nested = {inv for inv in before if inv.startswith(("guard:loads:", "guard:lock_file:"))}
    assert len(nested) >= 2, before

    v = kernel.commit(sid, "cond", source=CONDITIONAL.replace("    return y * 2\n", "    z = y\n    return z * 2\n"))
    assert v.accepted, str(v.error)[:200]
    after = set(_node(kernel, sid, "cond.py")["invariants_auto_mined"])
    assert nested <= after, sorted(nested - after)
    fresh = StateKernel()
    sid2 = fresh.init_session(_write(tmp_path / "b", {"cond.py": kernel.node_source(sid, "cond")}))
    assert after == set(_node(fresh, sid2, "cond.py")["invariants_auto_mined"])

    stripped = kernel.node_source(sid, "cond").replace('        if not text:\n            raise ValueError("empty")\n', "")
    assert stripped != kernel.node_source(sid, "cond")
    v = kernel.commit(sid, "cond", source=stripped)
    assert not v.accepted and v.gate == "C" and "loads" in str(v.error), str(v.error)[:200]


def test_a_remainder_def_that_names_an_edited_symbol_puts_everything_in_scope(kernel, tmp_path):
    """`main()` under `if __name__ == "__main__":` calls f; editing f is not a local edit for
    the remainder, so the analysis is full and still equals a from-scratch one."""
    src = CONDITIONAL + '\n\nif __name__ == "__main__":\n    def main():\n        if f(1) != 2:\n            raise SystemExit(1)\n        return f(2)\n'
    root = _write(tmp_path / "a", {"cond.py": src})
    sid = kernel.init_session(root)
    v = kernel.commit(sid, "cond", source=src.replace("    return x + 1\n", "    return x + 2\n"))
    assert v.accepted, str(v.error)[:200]
    fresh = StateKernel()
    sid2 = fresh.init_session(_write(tmp_path / "b", {"cond.py": kernel.node_source(sid, "cond")}))
    assert set(_node(kernel, sid, "cond.py")["invariants_auto_mined"]) == set(_node(fresh, sid2, "cond.py")["invariants_auto_mined"])


def test_a_tree_that_is_large_by_bytes_is_indexed_lazily(kernel, tmp_path, monkeypatch):
    monkeypatch.setenv("STEPCHECK_LAZY_BYTES", "20000")  # 20 KB
    big = "".join(f"def f{i}(x):\n    if x < {i}:\n        raise ValueError({i})\n    return x\n\n\n" for i in range(400))
    root = _write(tmp_path, {"big.py": big, "small.py": "def s():\n    return 1\n"})
    base = kernel.perf_stats()["analysis_full"]
    sid = kernel.init_session(root)
    assert kernel.index_mode(sid) == "lazy" and kernel.perf_stats()["analysis_full"] == base
    assert kernel.checkout(sid, "small", focus=[]).frame_markdown and kernel.perf_stats()["analysis_full"] == base + 1
    monkeypatch.setenv("STEPCHECK_LAZY_BYTES", "10000000")
    assert kernel.index_mode(kernel.init_session(_write(tmp_path / "e", {"big.py": big}))) == "eager"


def test_ci_still_fails_a_project_import_that_is_really_missing(tmp_path, capsys):
    root = _write(tmp_path, {
        "m.py": "def f(x):\n    return x\n",
        "user.py": "from m import gone\n\n\ndef run(v):\n    # okf-invariant: call:run(1) == 1\n    return gone(v)\n",
    })
    code = cli.main(["ci", str(root)])
    out = capsys.readouterr().out
    assert code == 1 and "FAIL" in out
