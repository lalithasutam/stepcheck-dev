"""Slice 23 — polyglot parity for the enterprise tier: TypeScript / JavaScript
gain dotted `Class.method` focus and patch ops plus zero-config structural
guard mining (`guard:<symbol>:<cond> throws <Error>`, enforced at Gate C
without executing anything); Go, Rust and Java modules are indexed, sliced,
patched and gated (A: balanced delimiters / locked / export conservation,
B: attribute and annotation conservation + signature-change dirtying,
C: leading-guard conservation) with the same DSSE attestations
(Seam 1 + CLI seam)."""
import hashlib
from pathlib import Path

import pytest

import cli
from kernel import LogicalError, MechanicalError, OmissionError


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return root


def _node(kernel, sid, nid) -> dict:
    return next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == nid)


def _replace(name: str, code: str) -> list[dict]:
    return [{"op": "replace_symbol", "name": name, "code": code}]


def _body(payload) -> str:
    return payload.rendered().split("```", 1)[1].split("\n", 1)[1]


# ===================================================== TypeScript parity

TS_SVC = '''\
import type { Item } from "./types";

function log(target: unknown, key?: string): void {
  console.log(String(target), key);
}

export function charge(account: string, amount: number): Item {
  if (amount <= 0) {
    throw new RangeError("amount must be positive");
  }
  if (!account) throw new Error("account required");
  return { account, amount, status: "charged" };
}

export const refund = (account: string, amount: number): Item => {
  if (amount <= 0) throw new RangeError("amount must be positive");
  return { account, amount: -amount, status: "refunded" };
};

export class Repo {
  private items: Item[] = [];

  constructor(private readonly limit: number = 10) {}

  @log
  add(item: Item): void {
    if (!item) {
      throw new TypeError("item required");
    }
    this.items.push(item);
  }

  total(): number {
    return this.items.reduce((sum, item) => sum + item.amount, 0);
  }

  get size(): number {
    return this.items.length;
  }
}
'''

TS_TYPES = '''\
export interface Item {
  account: string;
  amount: number;
  status: "charged" | "refunded";
}
'''


@pytest.fixture()
def ts_project(tmp_path) -> Path:
    return _write(tmp_path, {"types.ts": TS_TYPES, "svc.ts": TS_SVC})


def test_ts_dotted_member_focus_renders_the_method_inside_a_class_skeleton(kernel, ts_project):
    sid = kernel.init_session(ts_project)
    sliced = kernel.checkout(sid, "svc", focus=["Repo.add"])
    body = _body(sliced)
    assert "export class Repo {" in body and "this.items.push(item);" in body  # the member, verbatim
    assert "  total(): number { ... }" in body and "reduce" not in body  # sibling: signature only
    assert "  private items: Item[] = [];" in body and "  get size(): number { ... }" in body
    assert "export function charge(account: string, amount: number): Item { ... }" in body
    whole = kernel.checkout(sid, "svc", focus=["Repo"])
    assert sliced.token_count < whole.token_count
    assert {"@log on Repo.add", "class Repo", "function charge", "const refund"} <= set(_node(kernel, sid, "svc")["preserved_symbols"])


def test_ts_dotted_patch_ops_splice_only_the_member(kernel, ts_project):
    sid = kernel.init_session(ts_project)
    v = kernel.commit(sid, "svc", patch=_replace(
        "Repo.add",
        "@log\nadd(item: Item): void {\n  if (!item) {\n    throw new TypeError(\"item required\");\n  }\n"
        "  if (this.items.length >= this.limit) throw new RangeError(\"full\");\n  this.items.push(item);\n}\n",
    ))
    assert v.accepted, v.error
    source = (ts_project / "svc.ts").read_text(encoding="utf-8")
    assert '    if (this.items.length >= this.limit) throw new RangeError("full");\n' in source  # re-indented
    for untouched in ("  total(): number {\n    return this.items.reduce((sum, item) => sum + item.amount, 0);\n  }\n",
                      "  constructor(private readonly limit: number = 10) {}\n", "export const refund = (account: string, amount: number): Item => {\n"):
        assert untouched in source
    assert hashlib.sha256((ts_project / "svc.ts").read_bytes()).hexdigest() == v.attestation["payload"]["sha256"]

    gone = kernel.commit(sid, "svc", patch=[{"op": "delete_symbol", "name": "Repo.total"}])
    assert gone.accepted, gone.error
    source = (ts_project / "svc.ts").read_text(encoding="utf-8")
    assert "total()" not in source and "  get size(): number {" in source


def test_ts_leading_throw_guards_are_mined_as_structural_invariants(kernel, ts_project):
    sid = kernel.init_session(ts_project)
    mined = _node(kernel, sid, "svc")["invariants_auto_mined"]
    assert mined == [
        "guard:charge:amount<=0 throws RangeError",
        'guard:charge:!account throws Error',
        "guard:refund:amount<=0 throws RangeError",
        "guard:Repo.add:!item throws TypeError",
    ]
    assert _node(kernel, sid, "svc")["invariants"] == mined


def test_ts_gate_c_rejects_a_removed_or_weakened_guard_and_accepts_equivalents(kernel, ts_project):
    sid = kernel.init_session(ts_project)
    removed = kernel.commit(sid, "svc", patch=_replace(
        "charge",
        "export function charge(account: string, amount: number): Item {\n"
        "  if (!account) throw new Error(\"account required\");\n"
        "  return { account, amount: Math.abs(amount), status: \"charged\" };\n}\n",
    ))
    assert not removed.accepted and removed.gate == "C" and isinstance(removed.error, LogicalError), removed.error
    assert "guard:charge:amount<=0 throws RangeError" in str(removed.error)

    weakened = kernel.commit(sid, "svc", patch=_replace(
        "charge",
        "export function charge(account: string, amount: number): Item {\n"
        "  if (amount < 0) {\n    throw new RangeError(\"amount must be positive\");\n  }\n"
        "  if (!account) throw new Error(\"account required\");\n"
        "  return { account, amount, status: \"charged\" };\n}\n",
    ))
    assert not weakened.accepted and weakened.gate == "C"

    equivalent = kernel.commit(sid, "svc", patch=_replace(
        "charge",
        "export function charge(account: string, amount: number): Item {\n"
        "  const trimmed = account.trim();\n"
        "  if ( amount  <=  0 ) { throw new RangeError('non-positive amount'); }\n"  # moved deeper, re-spaced, re-worded message
        "  if (!account) throw new Error(\"account required\");\n"
        "  return { account: trimmed, amount, status: \"charged\" };\n}\n",
    ))
    assert equivalent.accepted, equivalent.error

    declared = kernel.commit(sid, "svc", patch=_replace(
        "charge", "export function charge(account: string, amount: number): Item {\n  return { account, amount, status: \"charged\" };\n}\n"
    ), allow_deletion=True)
    assert declared.accepted, declared.error

    bare = kernel.commit(sid, "svc", patch=_replace("Repo.add", "add(item: Item): void {\n  if (!item) {\n    throw new TypeError(\"item required\");\n  }\n  this.items.push(item);\n}\n"))
    assert not bare.accepted and bare.gate == "B" and isinstance(bare.error, OmissionError)
    assert "@log on Repo.add" in str(bare.error)


# ================================================================= Go

GO_LEDGER = '''\
package ledger

import "fmt"

// Account keeps a balance.
type Account struct {
	owner   string
	balance int64
}

// Open returns an account for owner.
func Open(owner string) (*Account, error) {
	if owner == "" {
		return nil, fmt.Errorf("owner required")
	}
	return &Account{owner: owner}, nil
}

// Credit adds cents.
func (a *Account) Credit(cents int64) error {
	if cents <= 0 {
		return fmt.Errorf("credit must be positive, got %d", cents)
	}
	a.balance += cents
	return nil
}

// Balance reports the balance.
func (a *Account) Balance() int64 {
	return a.balance
}

//go:noinline
func Format(cents int64) string {
	raw := `{ not a brace }`
	_ = raw
	return fmt.Sprintf("%d.%02d {%s}", cents/100, cents%100, "USD")
}
'''

GO_API = '''\
package api

import (
	"net/http"

	"example.com/demo/ledger"
)

// Server wraps one account.
type Server struct {
	account *ledger.Account
}

// NewServer opens the account.
func NewServer(owner string) (*Server, error) {
	acct, err := ledger.Open(owner)
	if err != nil {
		return nil, err
	}
	return &Server{account: acct}, nil
}

// Balance writes the formatted balance.
func (s *Server) Balance(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(ledger.Format(s.account.Balance())))
}
'''


@pytest.fixture()
def go_project(tmp_path) -> Path:
    return _write(tmp_path, {"ledger/account.go": GO_LEDGER, "api/server.go": GO_API, "vendor/x/x.go": "package x\n"})


def test_go_modules_index_with_package_edges_methods_and_guards(kernel, go_project):
    sid = kernel.init_session(go_project)
    assert {n["node_id"] for n in kernel.graph(sid)["nodes"]} == {"account", "server"}  # vendor/ skipped
    assert _node(kernel, sid, "server")["deps"] == ["account"]
    acct = _node(kernel, sid, "account")
    assert {"type Account", "func Open", "func Format", "method Account.Credit", "//go:noinline on Format"} <= set(acct["preserved_symbols"])
    assert any(e.startswith("func Open(owner string) (*Account, error)") for e in acct["exports"])
    assert sorted(acct["invariants_auto_mined"]) == sorted(['guard:Open:owner=="" returns', "guard:Account.Credit:cents<=0 returns"])
    body = _body(kernel.checkout(sid, "account", focus=["Account.Credit"]))
    assert "a.balance += cents" in body and "func (a *Account) Balance() int64 { ... }" in body
    assert "func Format(cents int64) string { ... }" in body and "Sprintf" not in body
    assert "```go\n" in kernel.checkout(sid, "account", focus=[]).rendered()


def test_go_patch_ops_gates_and_attestation(kernel, go_project):
    sid = kernel.init_session(go_project)
    v = kernel.commit(sid, "account", patch=_replace(
        "Account.Credit",
        "// Credit adds cents.\nfunc (a *Account) Credit(cents int64) error {\n\tif cents <= 0 {\n\t\treturn fmt.Errorf(\"credit must be positive, got %d\", cents)\n\t}\n"
        "\ta.balance += cents * 1\n\treturn nil\n}\n",
    ))
    assert v.accepted, v.error
    source = (go_project / "ledger" / "account.go").read_text(encoding="utf-8")
    assert "a.balance += cents * 1" in source and "//go:noinline\nfunc Format" in source
    assert hashlib.sha256((go_project / "ledger" / "account.go").read_bytes()).hexdigest() == v.attestation["payload"]["sha256"]

    unbalanced = kernel.commit(sid, "account", patch=_replace("Format", "func Format(cents int64) string {\n\treturn \"x\"\n"))
    assert not unbalanced.accepted and unbalanced.gate == "A" and "unclosed" in str(unbalanced.error)

    dropped = kernel.commit(sid, "account", patch=[{"op": "delete_symbol", "name": "Open"}], allow_deletion=True)
    assert not dropped.accepted and dropped.gate == "A" and "export 'Open' of 'account' is required by dependent 'server'" in str(dropped.error)

    no_directive = kernel.commit(sid, "account", patch=_replace("Format", "func Format(cents int64) string {\n\treturn fmt.Sprintf(\"%d\", cents)\n}\n"))
    assert not no_directive.accepted and no_directive.gate == "B" and "//go:noinline on Format" in str(no_directive.error)

    guard_gone = kernel.commit(sid, "account", patch=_replace("Open", "func Open(owner string) (*Account, error) {\n\treturn &Account{owner: owner}, nil\n}\n"))
    assert not guard_gone.accepted and guard_gone.gate == "C" and 'guard:Open:owner=="" returns' in str(guard_gone.error)

    sig = kernel.commit(sid, "account", patch=_replace("Format", "//go:noinline\nfunc Format(cents int64, currency string) string {\n\treturn fmt.Sprintf(\"%d %s\", cents, currency)\n}\n"))
    assert sig.accepted and sig.dirtied == ["server"], sig.error
    with pytest.raises(OmissionError, match="DIRTY_OMISSION_RISK"):
        kernel.finalize_session(sid)
    kernel.lock_node(sid, "account")
    assert kernel.commit(sid, "account", patch=[{"op": "append", "code": "var V = 1\n"}]).gate == "A"


def test_stepcheck_ci_verifies_a_go_project(go_project, capsys):
    rc = cli.main(["ci", str(go_project)])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "account" in out and "server" in out and "2 modules verified" in out and "2 invariants executed" in out


# =============================================================== Rust

RS_LIB = '''\
//! Ledger crate.

pub mod util;

use crate::util::normalize;

/// A balance.
#[derive(Debug, Default)]
pub struct Account {
    owner: String,
    balance: i64,
}

impl Account {
    /// Open an account.
    pub fn open(owner: &str) -> Result<Self, String> {
        if owner.is_empty() {
            return Err("owner required".to_string());
        }
        Ok(Self { owner: normalize(owner), balance: 0 })
    }

    pub fn credit(&mut self, cents: i64) -> i64 {
        if cents <= 0 {
            panic!("credit must be positive, got {cents}");
        }
        let brace = '{';
        let _ = (brace, r#"raw { brace }"#);
        self.balance += cents;
        self.balance
    }

    pub fn balance(&self) -> i64 {
        self.balance
    }
}

pub fn total<'a>(values: &'a [i64]) -> i64 {
    if values.is_empty() {
        return 0;
    }
    values.iter().sum()
}
'''

RS_UTIL = '''\
/// Lower-case, trimmed.
pub fn normalize(name: &str) -> String {
    if name.is_empty() {
        panic!("empty name");
    }
    name.trim().to_lowercase()
}
'''


@pytest.fixture()
def rs_project(tmp_path) -> Path:
    return _write(tmp_path, {"src/lib.rs": RS_LIB, "src/util.rs": RS_UTIL, "target/debug/x.rs": "fn x() {}\n"})


def test_rust_modules_index_with_use_edges_attributes_and_guards(kernel, rs_project):
    sid = kernel.init_session(rs_project)
    assert {n["node_id"] for n in kernel.graph(sid)["nodes"]} == {"lib", "util"}  # target/ skipped
    assert _node(kernel, sid, "lib")["deps"] == ["util"]
    lib = _node(kernel, sid, "lib")
    assert {"struct Account", "#[derive]", "#[derive] on Account", "method Account.credit", "fn total"} <= set(lib["preserved_symbols"])
    assert lib["invariants_auto_mined"] == [
        "guard:Account.open:owner.is_empty() returns Err",
        "guard:Account.credit:cents<=0 panics",
        "guard:total:values.is_empty() returns",
    ]
    body = _body(kernel.checkout(sid, "lib", focus=["Account.credit"]))
    assert "self.balance += cents;" in body and "    pub fn balance(&self) -> i64 { ... }" in body and "to_lowercase" not in body
    assert "```rust\n" in kernel.checkout(sid, "lib", focus=[]).rendered()
    assert "pub fn normalize(name: &str) -> String { ... }" in kernel.checkout(sid, "lib", focus=["total"]).rendered()


def test_rust_patch_ops_gates_and_dirtying(kernel, rs_project):
    sid = kernel.init_session(rs_project)
    v = kernel.commit(sid, "lib", patch=_replace(
        "Account.credit",
        "pub fn credit(&mut self, cents: i64) -> i64 {\n    if cents <= 0 {\n        panic!(\"credit must be positive, got {cents}\");\n    }\n"
        "    self.balance += cents;\n    self.balance\n}\n",
    ))
    assert v.accepted, v.error
    source = (rs_project / "src" / "lib.rs").read_text(encoding="utf-8")
    assert "        self.balance += cents;\n        self.balance\n    }\n" in source and "raw { brace }" not in source
    assert "    pub fn balance(&self) -> i64 {\n        self.balance\n    }\n" in source
    assert hashlib.sha256((rs_project / "src" / "lib.rs").read_bytes()).hexdigest() == v.attestation["payload"]["sha256"]

    no_attr = kernel.commit(sid, "lib", patch=_replace("Account", "pub struct Account {\n    owner: String,\n    balance: i64,\n}\n"))
    assert not no_attr.accepted and no_attr.gate == "B" and "#[derive] on Account" in str(no_attr.error)

    guard_gone = kernel.commit(sid, "lib", patch=_replace(
        "Account.credit", "pub fn credit(&mut self, cents: i64) -> i64 {\n    self.balance += cents.max(0);\n    self.balance\n}\n"
    ))
    assert not guard_gone.accepted and guard_gone.gate == "C" and "guard:Account.credit:cents<=0 panics" in str(guard_gone.error)

    dropped = kernel.commit(sid, "util", patch=[{"op": "delete_symbol", "name": "normalize"}], allow_deletion=True)
    assert not dropped.accepted and dropped.gate == "A" and "export 'normalize' of 'util' is required by dependent 'lib'" in str(dropped.error)

    sig = kernel.commit(sid, "util", patch=_replace(
        "normalize", "pub fn normalize(name: &str, max: usize) -> String {\n    if name.is_empty() {\n        panic!(\"empty name\");\n    }\n    name.trim().to_lowercase().chars().take(max).collect()\n}\n"
    ))
    assert sig.accepted and sig.dirtied == ["lib"], sig.error
    with pytest.raises(OmissionError, match="DIRTY_OMISSION_RISK"):
        kernel.finalize_session(sid)


def test_stepcheck_ci_verifies_a_rust_project(rs_project, capsys):
    rc = cli.main(["ci", str(rs_project)])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "lib" in out and "util" in out and "2 modules verified" in out


# =============================================================== Java

JAVA_STRINGS = '''\
package com.acme.util;

/** String helpers. */
public final class Strings {
    private Strings() {
    }

    public static String normalize(String value) {
        if (value == null) {
            throw new IllegalArgumentException("value required");
        }
        return value.trim().toLowerCase();
    }
}
'''

JAVA_ACCOUNT = '''\
package com.acme.ledger;

import java.util.Objects;

import com.acme.util.Strings;

/** A balance. */
public class Account {
    private final String owner;
    private long balance;

    public Account(String owner) {
        if (owner == null || owner.isBlank()) {
            throw new IllegalArgumentException("owner required");
        }
        this.owner = Strings.normalize(owner);
    }

    /** Adds cents. */
    public long credit(long cents) {
        if (cents <= 0) throw new IllegalArgumentException("credit must be positive");
        String text = """
            { not a brace }
            """;
        balance += cents;
        return balance;
    }

    @Override
    public String toString() {
        return "Account{" + owner + "}";
    }

    @Override
    public int hashCode() {
        return Objects.hash(owner);
    }
}
'''


@pytest.fixture()
def java_project(tmp_path) -> Path:
    return _write(tmp_path, {"com/acme/util/Strings.java": JAVA_STRINGS, "com/acme/ledger/Account.java": JAVA_ACCOUNT,
                             "build/Generated.java": "public class Generated {}\n"})


def test_java_modules_index_with_import_edges_annotations_and_guards(kernel, java_project):
    sid = kernel.init_session(java_project)
    assert {n["node_id"] for n in kernel.graph(sid)["nodes"]} == {"Strings", "Account"}  # build/ skipped
    assert _node(kernel, sid, "Account")["deps"] == ["Strings"]
    acct = _node(kernel, sid, "Account")
    assert {"class Account", "method Account.credit", "@Override", "@Override on Account.toString"} <= set(acct["preserved_symbols"])
    assert acct["invariants_auto_mined"] == [
        "guard:Account.Account:owner==null||owner.isBlank() throws IllegalArgumentException",
        "guard:Account.credit:cents<=0 throws IllegalArgumentException",
    ]
    body = _body(kernel.checkout(sid, "Account", focus=["Account.credit"]))
    assert "balance += cents;" in body and "    public String toString() { ... }" in body and "Objects.hash" not in body
    assert "```java\n" in kernel.checkout(sid, "Account", focus=[]).rendered()
    assert "public static String normalize(String value) { ... }" in kernel.checkout(sid, "Account", focus=["Account.credit"]).rendered()


def test_java_patch_ops_gates_and_dirtying(kernel, java_project):
    sid = kernel.init_session(java_project)
    v = kernel.commit(sid, "Account", patch=_replace(
        "Account.credit",
        "/** Adds cents. */\npublic long credit(long cents) {\n    if (cents <= 0) throw new IllegalArgumentException(\"credit must be positive\");\n"
        "    balance += cents;\n    return balance;\n}\n",
    ))
    assert v.accepted, v.error
    source = (java_project / "com" / "acme" / "ledger" / "Account.java").read_text(encoding="utf-8")
    assert "        balance += cents;\n        return balance;\n    }\n" in source and "not a brace" not in source
    assert "    @Override\n    public int hashCode() {\n        return Objects.hash(owner);\n    }\n" in source
    assert hashlib.sha256((java_project / "com" / "acme" / "ledger" / "Account.java").read_bytes()).hexdigest() == v.attestation["payload"]["sha256"]

    no_override = kernel.commit(sid, "Account", patch=_replace("Account.toString", "public String toString() {\n    return owner;\n}\n"))
    assert not no_override.accepted and no_override.gate == "B" and "@Override on Account.toString" in str(no_override.error)

    guard_gone = kernel.commit(sid, "Account", patch=_replace(
        "Account.credit", "public long credit(long cents) {\n    balance += Math.max(cents, 0);\n    return balance;\n}\n"
    ))
    assert not guard_gone.accepted and guard_gone.gate == "C" and "guard:Account.credit:cents<=0 throws IllegalArgumentException" in str(guard_gone.error)

    dropped = kernel.commit(sid, "Strings", patch=[{"op": "delete_symbol", "name": "Strings"}], allow_deletion=True)
    assert not dropped.accepted and dropped.gate == "A" and "export 'Strings' of 'Strings' is required by dependent 'Account'" in str(dropped.error)

    sig = kernel.commit(sid, "Strings", patch=_replace(
        "Strings.normalize", "public static String normalize(String value, int max) {\n    if (value == null) {\n        throw new IllegalArgumentException(\"value required\");\n    }\n"
                            "    return value.trim().toLowerCase().substring(0, Math.min(max, value.length()));\n}\n"
    ))
    assert sig.accepted and sig.dirtied == ["Account"], sig.error
    with pytest.raises(OmissionError, match="DIRTY_OMISSION_RISK"):
        kernel.finalize_session(sid)


def test_stepcheck_ci_verifies_a_java_project(java_project, capsys):
    rc = cli.main(["ci", str(java_project)])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "Account" in out and "Strings" in out and "2 modules verified" in out


def test_stepcheck_ci_reports_an_unbalanced_go_file(go_project, capsys):
    (go_project / "api" / "server.go").write_text(GO_API.replace("\treturn &Server{account: acct}, nil\n}\n", "\treturn &Server{account: acct}, nil\n"), encoding="utf-8", newline="\n")
    rc = cli.main(["ci", str(go_project)])
    out = capsys.readouterr().out
    assert rc == 1 and "server.go" in out and "parse" in out
