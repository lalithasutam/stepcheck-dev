"""Slice 31 — boundary cases from the external certification and session cleanup.

A gateway kept answering from sessions archived on disk; a locked module made
dirty by an upstream change could never return to clean; a tiny module's frame
outweighed its source; computed early returns and `.get(key, default)` lookups
went unguarded; and outside Python any export change dirtied every importer.
"""
import shutil

import pytest
from fastapi.testclient import TestClient

from kernel import StateKernel, _tokens


def _write(root, files):
    for rel, src in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src, encoding="utf-8", newline="\n")
    return root


def _node(kernel, sid, node_id):
    return next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == node_id)


# ---------------------------------------------------------- 1. session freshness


def test_refresh_evicts_archived_sessions_and_reloads_rewritten_ones(kernel, tmp_path):
    _write(tmp_path, {"m.py": "def f(x):\n    return x\n"})
    sid = kernel.init_session(tmp_path)
    assert kernel.refresh_sessions() == {"evicted": [], "reloaded": []}  # its own write

    other = StateKernel()  # a second process landing a commit on the same session
    assert other.commit(sid, "m", "def f(x):\n    return x + 1\n").accepted
    assert kernel.refresh_sessions()["reloaded"] == [sid]
    assert kernel.node_source(sid, "m") == "def f(x):\n    return x + 1\n"

    archive = tmp_path / ".stepcheck" / "sessions_archive"
    archive.mkdir()
    shutil.move(str(tmp_path / ".stepcheck" / "sessions" / f"{sid}.json"), str(archive))
    assert kernel.refresh_sessions()["evicted"] == [sid]
    with pytest.raises(KeyError):
        kernel.checkout(sid, "m")


def test_gateway_stops_serving_a_session_archived_on_disk(project):
    import server

    with TestClient(server.app) as client:
        sid = client.post("/v1/step/init", json={"project_root": str(project)}).json()["session_id"]
        body = {"session_id": sid, "node_id": "billing", "focus": []}
        assert client.post("/v1/step/checkout", json=body).status_code == 200
        archive = project / ".stepcheck" / "sessions_archive"
        archive.mkdir()
        shutil.move(str(project / ".stepcheck" / "sessions" / f"{sid}.json"), str(archive))
        assert client.post("/v1/step/checkout", json=body).status_code == 404


# ------------------------------------------------- 1b. locked-module re-verification


def test_locked_module_dirtied_upstream_reverifies_with_its_locked_bytes(kernel, tmp_path):
    _write(tmp_path, {"base.py": "def f(x):\n    return x\n",
                      "user.py": "from base import f\n\n\ndef g():\n    return f(1)\n"})
    sid = kernel.init_session(tmp_path)
    kernel.lock_node(sid, "user")
    v = kernel.commit(sid, "base", "def f(x, y=0):\n    return x + y\n")
    assert v.accepted and v.dirtied == ["user"]
    assert kernel.omission_report(sid)["can_finalize"] is False

    same = kernel.commit(sid, "user", kernel.node_source(sid, "user"))
    assert same.accepted, same.error
    assert _node(kernel, sid, "user")["status"] == "LOCKED"
    assert kernel.omission_report(sid) == {"dirty": [], "can_finalize": True}

    mutated = kernel.commit(sid, "user", kernel.node_source(sid, "user") + "\nX = 1\n")
    assert not mutated.accepted and mutated.gate == "A" and "LOCKED" in str(mutated.error)


# ------------------------------------------------------ 2. zero-inflation pragma


def test_tiny_module_covered_by_focus_is_served_as_pragma_plus_raw_source(kernel, tmp_path):
    src = "def add(a, b):\n    if a is None:\n        raise ValueError('a')\n    return a + b\n"
    _write(tmp_path, {"tiny.py": src})
    sid = kernel.init_session(tmp_path)
    p = kernel.checkout(sid, "tiny", focus=["add"])
    head, body = p.frame_markdown.split("\n", 1)
    assert head.startswith("# [stepcheck: tiny | ") and "invariants: " in head
    assert body == src and p.rendered() == p.frame_markdown
    assert p.token_count == _tokens.count(p.frame_markdown)
    assert p.token_count <= _tokens.count(src) + _tokens.count(head) + 1
    assert p.token_count < kernel.checkout(sid, "tiny").token_count


# ------------------------------------------- 3. computed early returns, .get defaults

GUARDED = (
    "def scale(x, k):\n    if k == 0:\n        return x * 2\n    return x * k\n\n\n"
    "def port(cfg):\n    return cfg.get('port', 8080)\n"
)


def _replace(kernel, sid, name, code, **kw):
    return kernel.commit(sid, "m", patch=[{"op": "replace_symbol", "name": name, "code": code}], **kw)


def test_computed_early_return_guards_the_condition_not_the_expression(kernel, tmp_path):
    _write(tmp_path, {"m.py": GUARDED})
    sid = kernel.init_session(tmp_path)
    assert "guard:scale:if k == 0 returns early" in _node(kernel, sid, "m")["invariants_auto_mined"]
    refactor = _replace(kernel, sid, "scale", "def scale(x, k):\n    if k == 0:\n        return 2 * x\n    return x * k\n")
    assert refactor.accepted, refactor.error
    weakened = _replace(kernel, sid, "scale", "def scale(x, k):\n    if k is None:\n        return 2 * x\n    return x * k\n")
    assert not weakened.accepted and weakened.gate == "C" and "returns early" in str(weakened.error)


def test_get_with_literal_default_is_not_downgraded_to_a_bare_subscript(kernel, tmp_path):
    _write(tmp_path, {"m.py": GUARDED})
    sid = kernel.init_session(tmp_path)
    assert "guard:port:cfg.get('port') has default" in _node(kernel, sid, "m")["invariants_auto_mined"]
    assert _replace(kernel, sid, "port", "def port(cfg):\n    return cfg.get('port', 9090)\n").accepted
    bare = "def port(cfg):\n    return cfg['port']\n"
    v = _replace(kernel, sid, "port", bare)
    assert not v.accepted and v.gate == "C" and "has default" in str(v.error)
    assert _replace(kernel, sid, "port", bare, allow_deletion=True).accepted


# ---------------------------------------------- 4. contract-aware reverify beyond Python

TS_STORE = (
    "export function normalize(value: string): string {\n  return value.trim();\n}\n\n"
    "export function audit(target: unknown): void {\n  console.log(String(target));\n}\n"
)
TS_API = 'import { normalize } from "./store";\n\nexport function charge(account: string): string {\n  return normalize(account);\n}\n'


def test_ts_importer_is_dirtied_only_by_a_change_to_a_name_it_imports(kernel, tmp_path):
    _write(tmp_path, {"src/store.ts": TS_STORE, "src/api.ts": TS_API})
    sid = kernel.init_session(tmp_path)
    s1 = TS_STORE + "\nfunction pad(v: string): string {\n  return ` ${v}`;\n}\n"
    s2 = s1 + "\nexport function shout(v: string): string {\n  return v.toUpperCase();\n}\n"
    s3 = s2.replace("audit(target: unknown): void", "audit(target: unknown, tag: string): void")
    s4 = s3.replace("normalize(value: string): string", "normalize(value: string, lower: boolean): string")
    v = kernel.commit(sid, "store", s1)  # private helper: nothing the importer sees
    assert v.accepted and v.dirtied == [] and v.reverified == []
    for added_or_unimported in (s2, s3):
        v = kernel.commit(sid, "store", added_or_unimported)
        assert v.accepted and v.dirtied == [] and v.reverified == ["api"]
    v = kernel.commit(sid, "store", s4)  # the imported signature moved
    assert v.accepted and v.dirtied == ["api"]
    assert _node(kernel, sid, "api")["status"] == "DIRTY_OMISSION_RISK"


GO_LEDGER = 'package ledger\n\n// Open opens.\nfunc Open(owner string) string {\n\treturn owner\n}\n'
GO_API = 'package api\n\nimport "example.com/demo/ledger"\n\n// Run runs.\nfunc Run() string {\n\treturn ledger.Open("x")\n}\n'


def test_go_single_line_package_import_tracks_the_names_it_reads(kernel, tmp_path):
    _write(tmp_path, {"ledger/account.go": GO_LEDGER, "api/server.go": GO_API})
    sid = kernel.init_session(tmp_path)
    added = GO_LEDGER + '\n// Close closes.\nfunc Close(owner string) string {\n\treturn ""\n}\n'
    v = kernel.commit(sid, "account", added)
    assert v.accepted and v.dirtied == [] and v.reverified == ["server"]
    gone = 'package ledger\n\n// Close closes.\nfunc Close(owner string) string {\n\treturn ""\n}\n'
    v = kernel.commit(sid, "account", gone, allow_deletion=True)
    assert not v.accepted and v.gate == "A" and "'Open'" in str(v.error)
