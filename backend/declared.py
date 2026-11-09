"""Human-sovereign allowances for the native-tool hook workflow (`stepcheck allow`).

A PreToolUse Edit / Write / MultiEdit that drops a guard or a preserved symbol is denied
by Gate B / C. When a human asked for exactly that contract change, they declare it once:

    stepcheck allow <file> [symbol] --reason "<why>"

The declaration is one line in `<repo>/.stepcheck/declared.jsonl`, bound to the file's
repo-relative path, the optional symbol and the sha256 of the file *as it is before the
edit*. The hook then lets the first matching edit through as a declared deletion
(`allow_deletion=True`), adopts the written bytes the same way, and marks the allowance
used — the next edit to that file is gated strictly again. A command that invokes
`stepcheck allow` or touches `declared.jsonl` from inside the agent's own Bash tool is
answered `permissionDecision: "ask"`, so the human approves the agent's request instead of
an agent rubber-stamping its own guard drop.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from pathlib import Path

DECLARED = Path(".stepcheck") / "declared.jsonl"
_TAMPER = re.compile(r"(?:^|[\s;&|(`])stepcheck(?:\.exe)?\s+allow\b|declared\.jsonl", re.I)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def relpath(root: Path, path: str | Path) -> str:
    p = Path(path)
    try:
        return str(p.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(p).replace("\\", "/")


def entries(root: Path) -> list[dict]:
    f = root / DECLARED
    out: list[dict] = []
    if not f.is_file():
        return out
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and e.get("path"):
            out.append(e)
    return out


def _write(root: Path, rows: list[dict]) -> None:
    f = root / DECLARED
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8", newline="\n")


def record(root: Path, path: str | Path, symbol: str | None, reason: str) -> dict:
    """Append an allowance for the next edit of `path` (optionally only of `symbol`),
    bound to the file's current bytes. Returns the entry."""
    rel = relpath(root, path)
    target = root / rel
    current = target.read_bytes().decode("utf-8", "replace") if target.is_file() else ""
    entry = {"at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "path": rel,
             "symbol": symbol or None, "sha256": sha256_text(current), "reason": reason, "used": False}
    rows = entries(root)
    rows.append(entry)
    _write(root, rows)
    return entry


def find(root: Path, path: str | Path, current_text: str, changed_symbols: list[str] | None = None) -> dict | None:
    """The unused allowance that matches the file as it is now (`current_text`, the bytes
    the edit starts from) — and, when it names a symbol, an edit that changes that symbol
    (or nothing else). None when there is none."""
    rel = relpath(root, path)
    sha = sha256_text(current_text)
    for e in entries(root):
        if e.get("used") or e.get("path") != rel or e.get("sha256") != sha:
            continue
        sym = e.get("symbol")
        if sym and changed_symbols is not None and changed_symbols and sym not in changed_symbols \
                and not any(c == sym or c.startswith(sym + ".") or sym.startswith(c + ".") for c in changed_symbols):
            continue
        return e


def consume(root: Path, entry: dict, staged_text: str) -> None:
    """Mark the allowance used by the edit that produced `staged_text`; the bytes of that
    text are what the PostToolUse adoption recognises as the declared write."""
    rows = entries(root)
    for r in rows:
        if r.get("at") == entry.get("at") and r.get("path") == entry.get("path") and r.get("sha256") == entry.get("sha256") and not r.get("used"):
            r["used"] = True
            r["used_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
            r["result_sha256"] = sha256_text(staged_text)
            break
    _write(root, rows)


def declared_result(root: Path, path: str | Path, text: str) -> dict | None:
    """The used allowance whose declared edit produced exactly `text` (so a sync may adopt
    the bytes as the declared deletion they are), or None."""
    rel = relpath(root, path)
    sha = sha256_text(text)
    for e in entries(root):
        if e.get("used") and e.get("path") == rel and e.get("result_sha256") == sha:
            return e
    return None


def is_tampering_command(command: str) -> bool:
    """Whether a shell command declares an allowance or edits the allowance file."""
    return bool(command) and bool(_TAMPER.search(command))


def hint(path: str, symbol: str | None = None) -> str:
    sym = f" {symbol}" if symbol and symbol != "module" else ""
    return f'If this contract change was explicitly requested, declare it with: stepcheck allow {path}{sym} --reason "..."'


def cmd_allow(args) -> int:
    """`stepcheck allow <file> [symbol] --reason "<why>"` — the CLI entry point."""
    root = Path(args.root).resolve() if getattr(args, "root", None) else _repo_root(Path(args.file))
    target = Path(args.file)
    if not target.is_absolute():
        target = Path.cwd() / target
    if not target.is_file():
        print(f"stepcheck allow: {target} is not a file")
        return 2
    entry = record(root, target, args.symbol, args.reason)
    where = (root / DECLARED).relative_to(root)
    print(f"stepcheck allow: the next edit of {entry['path']}" + (f" ({entry['symbol']})" if entry["symbol"] else "")
          + f" may drop a preserved symbol or a mined guard — declared in {where}")
    print(f"  reason : {entry['reason']}")
    print(f"  bound to the file's current bytes (sha256 {entry['sha256'][:12]}…); consumed by the first accepted edit")
    return 0


def _repo_root(path: Path) -> Path:
    """The nearest ancestor holding `.stepcheck/` or `.git/`, else the file's directory."""
    cur = path.resolve()
    if cur.is_file():
        cur = cur.parent
    for cand in (cur, *cur.parents):
        if (cand / ".stepcheck").is_dir() or (cand / ".git").exists():
            return cand
    return cur
