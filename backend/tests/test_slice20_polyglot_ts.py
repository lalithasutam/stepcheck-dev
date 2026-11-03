"""Slice 20 — polyglot OKF: TypeScript / JavaScript modules are indexed, sliced,
patched and gated like Python ones (relative-import edges, `focus=` skeletons
with brace-body elision, byte-exact patch splicing, Gates A/B, dirtying,
DSSE attestations, `stepcheck ci`), including StepCheck's own frontend and
VS Code extension (Seam 1 + CLI seam)."""
import hashlib
import re
import shutil
from pathlib import Path

import pytest

import cli
from kernel import MechanicalError, OmissionError

REPO = Path(__file__).resolve().parents[2]


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return root


def _node(kernel, sid, nid) -> dict:
    return next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == nid)


def _ids(kernel, sid) -> set[str]:
    return {n["node_id"] for n in kernel.graph(sid)["nodes"]}


def _replace(name: str, code: str) -> list[dict]:
    return [{"op": "replace_symbol", "name": name, "code": code}]


TS_TYPES = '''\
export interface Item {
  account: string;
  amount: number;
  status: "charged" | "refunded";
}

export type Status = Item["status"];

export enum Kind {
  Debit = "debit",
  Credit = "credit",
}
'''

TS_STORE = '''\
import type { Item } from "./types";

const LIMIT = 10;

/** Lower-case, trimmed account key. */
export function normalize(value: string): string {
  return value.trim().toLowerCase();
}

export function audit(target: unknown): void {
  console.log(`audit ${String(target)} / ${LIMIT}`);
}

export class Repo {
  private items: Item[] = [];

  add(item: Item): void {
    this.items.push(item);
  }

  total(): number {
    return this.items.reduce((sum, item) => sum + item.amount, 0);
  }
}
'''

TS_API = '''\
import { Repo, normalize } from "./store";
import type { Item } from "./types";

export function charge(account: string, amount: number): Item {
  const repo = new Repo();
  if (amount <= 0) {
    throw new Error("amount must be positive");
  }
  repo.add({ account, amount, status: "charged" });
  return { account: normalize(account), amount, status: "charged" };
}

export const refund = (account: string, amount: number): Item => {
  return { account, amount: -amount, status: "refunded" };
};
'''

TS_UI = '''\
import { charge } from "./api";
import { Kind } from "./types";

export default function Panel(): string {
  const item = charge("acct", 5);
  return `${item.account}: ${Kind.Debit}`;
}
'''

TS_SERVICE = '''\
function sealed(ctor: Function): void {
  Object.seal(ctor);
}

@sealed
export class Service {
  run(): number {
    return 1;
  }
}
'''


@pytest.fixture()
def ts_project(tmp_path) -> Path:
    _write(tmp_path, {
        "types.ts": TS_TYPES, "store.ts": TS_STORE, "api.ts": TS_API, "ui.tsx": TS_UI, "service.ts": TS_SERVICE,
        "global.d.ts": "declare const __DEV__: boolean;\n",
        "node_modules/left-pad/index.ts": "export function pad(s: string): string { return s; }\n",
        "dist/bundle.js": "var x = 1;\n",
    })
    return tmp_path


# ------------------------------------------------------ indexing and edges


def test_ts_modules_are_indexed_with_relative_import_edges(kernel, ts_project):
    sid = kernel.init_session(ts_project)
    assert _ids(kernel, sid) == {"types", "store", "api", "ui", "service"}  # no .d.ts, node_modules, dist
    assert _node(kernel, sid, "api")["deps"] == ["store", "types"]
    assert _node(kernel, sid, "ui")["deps"] == ["api", "types"]
    assert _node(kernel, sid, "store")["deps"] == ["types"]
    exports = _node(kernel, sid, "store")["exports"]
    assert any(e.startswith("function normalize(value: string): string") for e in exports), exports
    assert "class Repo" in exports
    assert {"interface Item", "enum Kind"} <= set(_node(kernel, sid, "types")["exports"])
    assert {"function normalize", "function audit", "class Repo", "const LIMIT"} <= set(_node(kernel, sid, "store")["preserved_symbols"])


def test_focus_checkout_renders_a_ts_skeleton_with_bodies_elided(kernel, ts_project):
    sid = kernel.init_session(ts_project)
    whole = kernel.checkout(sid, "store", focus=None)
    sliced = kernel.checkout(sid, "store", focus=["normalize"])
    body = sliced.rendered().split("```ts\n", 1)[1]
    assert 'import type { Item } from "./types";' in body
    assert "return value.trim().toLowerCase();" in body  # focused, verbatim
    assert "export class Repo { ... }" in body and "reduce" not in body
    assert "export function audit(target: unknown): void { ... }" in body and "console.log" not in body
    assert sliced.token_count < whole.token_count
    skeleton = kernel.checkout(sid, "store", focus=[]).rendered().split("```ts\n", 1)[1]
    assert "toLowerCase" not in skeleton and "export function normalize(value: string): string { ... }" in skeleton
    # dependency interfaces ride along as signatures only
    assert "interface Item { ... }" in kernel.checkout(sid, "api", focus=["charge"]).rendered()


# ----------------------------------------------------------- patch folding


def test_patch_ops_splice_exact_line_spans_and_attest_the_bytes(kernel, ts_project):
    sid = kernel.init_session(ts_project)
    v = kernel.commit(sid, "store", patch=_replace(
        "normalize",
        "/** Lower-case, trimmed account key. */\n"
        "export function normalize(value: string): string {\n"
        "  return value.trim().toLowerCase().replace(/\\s+/g, \"-\");\n"
        "}\n",
    ))
    assert v.accepted, v.error
    source = (ts_project / "store.ts").read_text(encoding="utf-8")
    assert 'replace(/\\s+/g, "-")' in source
    assert hashlib.sha256((ts_project / "store.ts").read_bytes()).hexdigest() == v.attestation["payload"]["sha256"]
    for untouched in ("const LIMIT = 10;\n", "export function audit(target: unknown): void {\n  console.log(`audit ${String(target)} / ${LIMIT}`);\n}\n",
                      "  total(): number {\n    return this.items.reduce((sum, item) => sum + item.amount, 0);\n  }\n"):
        assert untouched in source

    gone = kernel.commit(sid, "store", patch=[{"op": "delete_symbol", "name": "audit"}], allow_deletion=True)
    assert gone.accepted, gone.error
    source = (ts_project / "store.ts").read_text(encoding="utf-8")
    assert "function audit" not in source and "export class Repo {" in source

    added = kernel.commit(sid, "store", patch=[{"op": "append", "code": "export const VERSION = 2;\n"}])
    assert added.accepted, added.error
    assert (ts_project / "store.ts").read_text(encoding="utf-8").endswith("export const VERSION = 2;\n")
    assert "const VERSION" in _node(kernel, sid, "store")["preserved_symbols"]


# ----------------------------------------------------------------- Gate A


def test_gate_a_rejects_unbalanced_delimiters_locked_modules_and_dropped_exports(kernel, ts_project):
    sid = kernel.init_session(ts_project)
    broken = kernel.commit(sid, "store", patch=_replace(
        "normalize", "export function normalize(value: string): string {\n  return value.trim();\n"
    ))
    assert not broken.accepted and broken.gate == "A" and isinstance(broken.error, MechanicalError)
    assert "unclosed" in str(broken.error) or "unbalanced" in str(broken.error).lower()

    kernel.lock_node(sid, "types")
    locked = kernel.commit(sid, "types", patch=[{"op": "append", "code": "export const X = 1;\n"}])
    assert not locked.accepted and locked.gate == "A" and "LOCKED" in str(locked.error)

    dropped = kernel.commit(sid, "store", patch=[{"op": "delete_symbol", "name": "Repo"}], allow_deletion=True)
    assert not dropped.accepted and dropped.gate == "A"
    assert "export 'Repo' of 'store' is required by dependent 'api'" in str(dropped.error)


# ----------------------------------------------------------------- Gate B


def test_gate_b_conserves_decorators_and_constants(kernel, ts_project):
    sid = kernel.init_session(ts_project)
    preserved = _node(kernel, sid, "service")["preserved_symbols"]
    assert "@sealed" in preserved and "@sealed on Service" in preserved
    bare = kernel.commit(sid, "service", patch=_replace(
        "Service", "export class Service {\n  run(): number {\n    return 2;\n  }\n}\n"
    ))
    assert not bare.accepted and bare.gate == "B", bare.error
    assert isinstance(bare.error, OmissionError) and bare.error.subtype == "INTRA_NODE_SYMBOL_DROPPED"
    assert "sealed" in str(bare.error)

    no_const = kernel.commit(sid, "store", patch=[{"op": "delete_symbol", "name": "LIMIT"}])
    assert not no_const.accepted and no_const.gate == "B" and "const LIMIT" in str(no_const.error)


# ------------------------------------------------- signature change dirtying


def test_exported_signature_change_dirties_importers_until_reverified(kernel, ts_project):
    sid = kernel.init_session(ts_project)
    v = kernel.commit(sid, "api", patch=_replace(
        "charge",
        "export function charge(account: string, amount: number, currency: string): Item {\n"
        "  const repo = new Repo();\n"
        "  if (amount <= 0) {\n    throw new Error(\"amount must be positive\");\n  }\n"
        "  repo.add({ account, amount, status: \"charged\" });\n"
        "  return { account: normalize(account) + currency, amount, status: \"charged\" };\n}\n",
    ))
    assert v.accepted, v.error
    assert v.dirtied == ["ui"]
    assert _node(kernel, sid, "ui")["status"] == "DIRTY_OMISSION_RISK"
    assert _node(kernel, sid, "types")["status"] != "DIRTY_OMISSION_RISK"
    with pytest.raises(OmissionError, match="DIRTY_OMISSION_RISK"):
        kernel.finalize_session(sid)
    fixed = kernel.commit(sid, "ui", patch=_replace(
        "Panel", "export default function Panel(): string {\n  const item = charge(\"acct\", 5, \"usd\");\n"
                 "  return `${item.account}: ${Kind.Debit}`;\n}\n"
    ))
    assert fixed.accepted and kernel.finalize_session(sid) is True


# -------------------------------------------------------------- CLI seam


def test_stepcheck_ci_verifies_a_typescript_project(ts_project, capsys):
    rc = cli.main(["ci", str(ts_project)])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "api" in out and "store" in out and "ui" in out and "5 modules verified" in out


def test_stepcheck_ci_reports_an_unbalanced_typescript_file(ts_project, capsys):
    (ts_project / "store.ts").write_text(TS_STORE.replace("  }\n}\n", "  }\n"), encoding="utf-8", newline="\n")
    rc = cli.main(["ci", str(ts_project)])
    out = capsys.readouterr().out
    assert rc == 1 and "store.ts" in out and "parse" in out


# ---------------------------------------------- self-hosted frontend + extension


_EXPORT_RE = re.compile(
    r"^export\s+(?:default\s+)?(?:declare\s+)?(?:async\s+)?(?:abstract\s+)?"
    r"(?:function\*?|class|interface|type|enum|const|let|var)\s+([A-Za-z_$][\w$]*)", re.M,
)


def test_self_hosted_frontend_and_extension_compact_and_keep_every_export(kernel, tmp_path):
    for sub in ("frontend/src", "extension/src"):
        shutil.copytree(REPO / sub, tmp_path / sub, ignore=shutil.ignore_patterns("node_modules", "dist", "out"))
    sources = {p: p.read_text(encoding="utf-8") for p in tmp_path.rglob("*") if p.suffix in (".ts", ".tsx") and not p.name.endswith(".d.ts")}
    assert len(sources) >= 10

    sid = kernel.init_session(tmp_path)
    nodes = {n["path"].replace("\\", "/"): n for n in kernel.graph(sid)["nodes"]}
    assert set(nodes) == {str(p.relative_to(tmp_path)).replace("\\", "/") for p in sources}

    raw_total = compacted_total = 0
    for rel, node in nodes.items():
        before = kernel.get_telemetry(sid)
        payload = kernel.checkout(sid, node["node_id"], focus=[])
        after = kernel.get_telemetry(sid)
        raw_total += after.raw_bloated_tokens - before.raw_bloated_tokens
        compacted_total += payload.token_count
        rendered = payload.rendered()
        for name in _EXPORT_RE.findall(sources[tmp_path / rel]):
            assert name in rendered, (rel, name)  # 100% export recall in the skeleton
        assert "```ts\n" in rendered
    assert 100 * (raw_total - compacted_total) / raw_total >= 50, (raw_total, compacted_total)
    assert "App" in _node(kernel, sid, "main")["deps"] or any("App" in d for d in _node(kernel, sid, "main")["deps"])
