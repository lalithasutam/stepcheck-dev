"""Editor-agnostic wiring for `stepcheck connect` / `disconnect`: a git `pre-commit` hook
that runs `stepcheck diff --staged` (so edits from Cursor, Windsurf, Copilot, Aider or a
plain editor are gated at `git commit` time), and the Cursor MCP server entry.

The pre-commit script exits in a few milliseconds of shell when no supported source file
is staged, chains a pre-existing user hook (moved to `pre-commit.stepcheck-chained`) and
is removed cleanly — the chained hook restored — by `stepcheck disconnect`.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

MARK_BEGIN = "# >>> stepcheck pre-commit >>>"
MARK_END = "# <<< stepcheck pre-commit <<<"
CHAINED = "pre-commit.stepcheck-chained"
SOURCE_SUFFIXES = ("py", "pyi", "ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts", "go", "rs", "java")
# one git call with pathspecs decides whether anything is worth gating: no pipes, no grep
SOURCE_PATHSPECS = " ".join(f"':(glob)**/*.{s}' ':(glob)*.{s}'" for s in SOURCE_SUFFIXES)


def _git_dir(root: Path) -> Path | None:
    dot = root / ".git"
    if dot.is_dir():
        return dot
    if dot.is_file():  # a worktree or submodule: `gitdir: <path>`
        try:
            line = dot.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if line.startswith("gitdir:"):
            target = Path(line.split(":", 1)[1].strip())
            return (root / target).resolve() if not target.is_absolute() else target
    return None


def _cli_path() -> str:
    import cli

    return Path(cli.__file__).resolve().as_posix()


def pre_commit_script(python: str | None = None) -> str:
    py = (python or sys.executable).replace("\\", "/")
    return f"""#!/bin/sh
{MARK_BEGIN}
# Installed by `stepcheck connect`: staged source files go through Gates A/B/C before the
# commit lands, whatever editor or agent wrote them. `stepcheck disconnect` removes it.
hook_dir=$(dirname "$0")
if [ -x "$hook_dir/{CHAINED}" ]; then
  "$hook_dir/{CHAINED}" "$@" || exit $?
fi
if [ -n "$(git diff --cached --name-only --diff-filter=AM -- {SOURCE_PATHSPECS})" ]; then
  if command -v stepcheck >/dev/null 2>&1; then
    stepcheck diff --staged "$(git rev-parse --show-toplevel)" || exit 1
  else
    "{py}" "{_cli_path()}" diff --staged "$(git rev-parse --show-toplevel)" || exit 1
  fi
fi
{MARK_END}
"""


def install_pre_commit(root: Path) -> str:
    """Write the hook; a pre-existing non-StepCheck hook is kept and chained."""
    gd = _git_dir(root)
    if gd is None:
        return "no git repository: pre-commit hook not installed"
    hooks = gd / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    target = hooks / "pre-commit"
    note = "installed"
    if target.exists():
        existing = target.read_text(encoding="utf-8", errors="replace")
        if MARK_BEGIN in existing:
            note = "already installed (refreshed)"
        else:
            chained = hooks / CHAINED
            chained.write_bytes(target.read_bytes())
            try:
                os.chmod(chained, 0o755)
            except OSError:
                pass
            note = f"installed; your existing hook is chained as {CHAINED}"
    target.write_text(pre_commit_script(), encoding="utf-8", newline="\n")
    try:
        os.chmod(target, 0o755)
    except OSError:
        pass
    return note


def remove_pre_commit(root: Path) -> str:
    gd = _git_dir(root)
    if gd is None:
        return "no git repository"
    target = gd / "hooks" / "pre-commit"
    if not target.exists():
        return "no pre-commit hook"
    text = target.read_text(encoding="utf-8", errors="replace")
    if MARK_BEGIN not in text:
        return "pre-commit hook is not StepCheck's: left alone"
    chained = gd / "hooks" / CHAINED
    if chained.exists():
        target.write_bytes(chained.read_bytes())
        chained.unlink()
        return f"removed; your original hook restored from {CHAINED}"
    target.unlink()
    return "removed"


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except ValueError:
        data = {}
    return data if isinstance(data, dict) else {}


def write_cursor_mcp(root: Path, base_url: str) -> str:
    """Merge the StepCheck server into `.cursor/mcp.json` (Cursor's `url` form)."""
    path = root / ".cursor" / "mcp.json"
    data = _read_json(path)
    servers = data.setdefault("mcpServers", {})
    servers["stepcheck"] = {"url": f"{base_url}/mcp/"}
    rendered = json.dumps(data, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_text(encoding="utf-8") != rendered:
        path.write_text(rendered, encoding="utf-8", newline="\n")
        return f"wired stepcheck -> {base_url}/mcp/"
    return "already wired (no change)"


def remove_cursor_mcp(root: Path) -> str:
    path = root / ".cursor" / "mcp.json"
    if not path.exists():
        return "no .cursor/mcp.json"
    data = _read_json(path)
    servers = data.get("mcpServers") if isinstance(data.get("mcpServers"), dict) else None
    if not servers or "stepcheck" not in servers:
        return "stepcheck not present"
    del servers["stepcheck"]
    if not servers:
        del data["mcpServers"]
    if data:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
        return "removed the stepcheck entry"
    path.unlink()
    return "removed the stepcheck entry (file was only ours: deleted)"


def remove_mcp_json(root: Path) -> str:
    path = root / ".mcp.json"
    if not path.exists():
        return "no .mcp.json"
    data = _read_json(path)
    servers = data.get("mcpServers") if isinstance(data.get("mcpServers"), dict) else None
    if not servers or "stepcheck" not in servers:
        return "stepcheck not present"
    del servers["stepcheck"]
    if not servers:
        del data["mcpServers"]
    if data:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
    else:
        path.unlink()
    return "removed the stepcheck entry"


def remove_claude_hooks(root: Path) -> str:
    """Drop StepCheck's entries from `.claude/settings.json` and its hook script."""
    settings = root / ".claude" / "settings.json"
    changed = False
    data = _read_json(settings)
    hooks_cfg = data.get("hooks") if isinstance(data.get("hooks"), dict) else None
    if hooks_cfg:
        for event, entries in list(hooks_cfg.items()):
            if not isinstance(entries, list):
                continue
            kept = []
            for e in entries:
                hs = [h for h in e.get("hooks", []) if "stepcheck_hook.py" not in str(h.get("command"))]
                if len(hs) != len(e.get("hooks", [])):
                    changed = True
                if hs:
                    e["hooks"] = hs
                    kept.append(e)
            if kept:
                hooks_cfg[event] = kept
            else:
                del hooks_cfg[event]
        if not hooks_cfg:
            del data["hooks"]
        if changed:
            if data:
                settings.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
            else:
                settings.unlink()
    script = root / ".claude" / "hooks" / "stepcheck_hook.py"
    if script.exists():
        script.unlink()
        changed = True
    return "removed" if changed else "nothing to remove"
