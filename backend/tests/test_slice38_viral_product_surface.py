"""Slice 38 — the viral product surface: the gates over git history and working trees, a
human-sovereign escape hatch for the native-tool hooks, and editor-agnostic wiring.

1. `stepcheck retro`: the last N commits through Gates B/C. Tier 1 (silent regressions:
   guard flips, stubbed bodies) shown by default; Tier 2 (structural removals) counted and
   listed with --all; test files skipped unless --all; valid --json.
2. `stepcheck diff` (working tree / --staged / --base) with a PR-comment --markdown table,
   exit 1 on a silent regression.
3. `stepcheck allow <file> [symbol] --reason`: a native PreToolUse Edit dropping a guard is
   denied with the hint; after the declaration the same edit passes once, the written bytes
   are adopted as a declared deletion, and the next edit is gated strictly again. The
   agent's own `Bash` invoking `stepcheck allow` or touching `declared.jsonl` is answered
   `permissionDecision: "ask"`.
4. `stepcheck connect` installs a git pre-commit gate that chains an existing user hook and
   writes `.cursor/mcp.json`; a staged guard drop is refused at `git commit`; `disconnect`
   restores the user hook and removes the entries.
5. Seam 1: `StateKernel.judge_transition` judges a before -> after pair in memory.
"""
from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path

import pytest

import cli
import hooks
from kernel import StateKernel

CORE = textwrap.dedent('''\
    def limit(x):
        if x <= 10:
            raise ValueError(x)
        return x


    def helper(y):
        if y is None:
            raise TypeError(y)
        return y * 2


    def body(z):
        if z < 0:
            raise ValueError(z)
        return z + helper(z)
    ''')

TEST_FILE = textwrap.dedent('''\
    def check(v):
        if v < 0:
            raise ValueError(v)
        return v
    ''')


def _git(root: Path, *args: str) -> str:
    done = subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "user.email=t@t", "-c", "user.name=t",
                           "-c", "commit.gpgsign=false", *args], cwd=root, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=300)
    if done.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {done.stderr[-400:]}")
    return done.stdout


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")


def _commit(root: Path, msg: str) -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", msg)
    return _git(root, "rev-parse", "--short=7", "HEAD").strip()


@pytest.fixture()
def history(tmp_path: Path) -> dict:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _write(root, "pkg/__init__.py", "")
    _write(root, "pkg/core.py", CORE)
    _write(root, "tests/test_core.py", TEST_FILE)
    shas = {"initial": _commit(root, "initial")}
    _write(root, "pkg/core.py", CORE.replace("if x <= 10:", "if x < 10:"))
    shas["flip"] = _commit(root, "tighten the limit boundary")
    flipped = CORE.replace("if x <= 10:", "if x < 10:")
    without_helper = flipped.replace("def helper(y):\n    if y is None:\n        raise TypeError(y)\n    return y * 2\n\n\n", "")
    _write(root, "pkg/core.py", without_helper)  # `body` still calls helper: a structural removal, not a dead-symbol refactor
    shas["delete_helper"] = _commit(root, "remove helper")
    _write(root, "pkg/core.py", without_helper.replace("    if z < 0:\n        raise ValueError(z)\n    return z + helper(z)\n", "    ...\n"))
    shas["stub"] = _commit(root, "simplify body")
    _write(root, "tests/test_core.py", TEST_FILE.replace("    if v < 0:\n        raise ValueError(v)\n", ""))
    shas["test_guard"] = _commit(root, "loosen test helper")
    current = (root / "pkg" / "core.py").read_text(encoding="utf-8")
    _write(root, "pkg/core.py", current + "\n\ndef extra(q):\n    return q\n")
    shas["clean"] = _commit(root, "add extra")
    return {"root": root, "shas": shas}


# ------------------------------------------------------------- 1. retro


def test_retro_shows_silent_regressions_hides_structural_removals_and_test_files_by_default(history, capsys):
    root = history["root"]
    assert cli.main(["retro", str(root), "--commits", "50", "--json"]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["commits_scanned"] == 6 and r["seconds"] < 20
    tier1 = {(f["short"], f["gate"], f["symbol"]) for f in r["tier1"]}
    assert (history["shas"]["flip"], "C", "limit") in tier1
    assert (history["shas"]["stub"], "B", "body") in tier1
    assert len(r["tier1"]) == 2, tier1
    assert [f["short"] for f in r["tier2"]] == [history["shas"]["delete_helper"]]
    assert r["skipped"]["tests"] == 1  # the test file's modifying commit was not judged (its creation is not a transition)
    flip = next(f for f in r["tier1"] if f["short"] == history["shas"]["flip"])
    # structural mode shows the boundary itself: `if x <= 10 raises` went, `if x < 10 raises` came
    assert any("guard:limit:" in g and "x <= 10" in g for g in flip["guards_removed"]), flip["guards_removed"]
    assert any("guard:limit:" in g and "x < 10" in g for g in flip["guards_added"]), flip["guards_added"]
    assert flip["when"]

    assert cli.main(["retro", str(root)]) == 0
    text = capsys.readouterr().out
    assert "Tier 1 — silent regressions (2)" in text and "pkg/core.py :: limit" in text and "Gate C" in text
    assert "helper" not in text.split("Tier 1")[1].split("structural")[0]  # Tier 2 detail is not listed
    assert "1 structural removal(s) hidden" in text and "test file(s) skipped" in text and "guards audited" in text


def test_retro_all_lists_structural_removals_and_judges_test_files(history, capsys):
    root = history["root"]
    assert cli.main(["retro", str(root), "--all", "--json"]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["skipped"]["tests"] == 0
    assert {f["short"] for f in r["tier1"]} == {history["shas"]["flip"], history["shas"]["stub"], history["shas"]["test_guard"]}
    assert [f["symbol"] for f in r["tier2"]] == ["helper"] and r["tier2"][0]["subtype"] == "INTRA_NODE_SYMBOL_DROPPED"
    assert cli.main(["retro", str(root), "--all"]) == 0
    assert "Tier 2 — structural removals (1)" in capsys.readouterr().out


def test_retro_is_structural_by_default_and_probes_opt_into_the_sandbox(history, capsys):
    root = history["root"]
    loads0 = StateKernel().perf_stats()["gate_c_sandbox_loads"]
    assert cli.main(["retro", str(root), "--jobs", "1", "--json"]) == 0  # in-process, so the counters are this process's
    fast = json.loads(capsys.readouterr().out)
    assert fast["run_probes"] is False and StateKernel().perf_stats()["gate_c_sandbox_loads"] == loads0  # no sandbox at all
    assert {(f["short"], f["gate"]) for f in fast["tier1"]} == {(history["shas"]["flip"], "C"), (history["shas"]["stub"], "B")}
    assert cli.main(["retro", str(root), "--probes", "--jobs", "1", "--json"]) == 0
    probed = json.loads(capsys.readouterr().out)
    assert probed["run_probes"] is True and StateKernel().perf_stats()["gate_c_sandbox_loads"] > loads0
    assert {(f["short"], f["gate"]) for f in probed["tier1"]} == {(f["short"], f["gate"]) for f in fast["tier1"]}
    flip = next(f for f in probed["tier1"] if f["short"] == history["shas"]["flip"])
    assert any(g.startswith("call:limit(") for g in flip["guards_removed"])  # the runtime probe form, with --probes


def test_retro_outside_a_repository_is_a_clear_error(tmp_path, capsys):
    assert cli.main(["retro", str(tmp_path)]) == 2


# ------------------------------------------------------------- 2. diff


def test_diff_judges_the_working_tree_and_the_index_with_a_markdown_verdict(history, capsys):
    root = history["root"]
    clean_src = (root / "pkg" / "core.py").read_text(encoding="utf-8")
    assert cli.main(["diff", str(root), "--markdown"]) == 0
    assert "✅ clean" in capsys.readouterr().out
    _write(root, "pkg/core.py", clean_src.replace("    if x < 10:\n        raise ValueError(x)\n", ""))
    assert cli.main(["diff", str(root), "--markdown"]) == 1
    md = capsys.readouterr().out
    assert "❌ 1 silent regression(s)" in md and "`pkg/core.py` :: `limit`" in md and "Gate C" in md and "stepcheck allow" in md
    assert cli.main(["diff", str(root), "--staged"]) == 0  # nothing staged yet
    capsys.readouterr()
    _git(root, "add", "pkg/core.py")
    assert cli.main(["diff", str(root), "--staged", "--json"]) == 1
    r = json.loads(capsys.readouterr().out)
    assert r["staged"] and r["tier1"][0]["symbol"] == "limit"
    _git(root, "checkout", "--", "pkg/core.py")
    _git(root, "reset", "-q")
    # `A...B` resolves to the merge base. HEAD against the initial commit: one finding per file (the gates
    # stop at the first violation — Gate B's stub in core.py before Gate C's flip) and, unlike retro,
    # `diff` judges test files too
    assert cli.main(["diff", str(root), "--base", f"{history['shas']['initial']}...HEAD", "--json"]) == 1
    r = json.loads(capsys.readouterr().out)
    assert r["base"].startswith(history["shas"]["initial"]) and {f["symbol"] for f in r["tier1"]} == {"body", "check"}


# ------------------------------------------------------------- 3. allow


GUARDED = "def f(x):\n    if x < 0:\n        raise ValueError(x)\n    return x + 1\n\n\ndef g(y):\n    return y\n"
DROPPED = "def f(x):\n    return x + 1\n\n\ndef g(y):\n    return y\n"


def _edit_event(root: Path, sid: str, path: Path, old: str, new: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(root), "stepcheck_session_id": sid,
            "tool_input": {"file_path": str(path), "old_string": old, "new_string": new}}


def test_allow_lets_one_declared_guard_drop_through_the_native_hook_then_expires(tmp_path, capsys):
    root = tmp_path / "proj"
    _write(root, "mod.py", GUARDED)
    kernel = StateKernel()
    sid = kernel.init_session(root)
    path = root / "mod.py"
    guard = "    if x < 0:\n        raise ValueError(x)\n"
    event = _edit_event(root, sid, path, guard, "")
    denied = hooks.decide(event, kernel)["hookSpecificOutput"]
    assert denied["permissionDecision"] == "deny" and "Gate C" in denied["permissionDecisionReason"]
    assert 'stepcheck allow mod.py f --reason "..."' in denied["permissionDecisionReason"]

    assert cli.main(["allow", str(path), "f", "--reason", "the caller validates x now", "--root", str(root)]) == 0
    assert "declared in" in capsys.readouterr().out
    rows = [json.loads(ln) for ln in (root / ".stepcheck" / "declared.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows[0]["path"] == "mod.py" and rows[0]["symbol"] == "f" and rows[0]["used"] is False

    allowed = hooks.decide(event, kernel)["hookSpecificOutput"]
    assert allowed["permissionDecision"] == "allow" and "the caller validates x now" in allowed["additionalContext"]
    rows = [json.loads(ln) for ln in (root / ".stepcheck" / "declared.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows[0]["used"] is True

    path.write_text(DROPPED, encoding="utf-8", newline="\n")  # the tool writes what the hook approved
    post = hooks.decide({**event, "hook_event_name": "PostToolUse"}, kernel)
    assert "adopted the declared contract change" in post["hookSpecificOutput"]["additionalContext"]
    assert kernel.omission_report(sid) == {"dirty": [], "rejected": [], "can_finalize": True}
    assert kernel.node_source(sid, "mod") == DROPPED

    assert kernel.commit(sid, "mod", source=GUARDED).accepted  # the guard comes back through the gates
    again = hooks.decide(event, kernel)["hookSpecificOutput"]
    assert again["permissionDecision"] == "deny"  # the allowance was consumed: strict again


def test_allow_scoped_to_another_symbol_does_not_cover_the_edit(tmp_path, capsys):
    root = tmp_path / "proj"
    _write(root, "mod.py", GUARDED)
    kernel = StateKernel()
    sid = kernel.init_session(root)
    path = root / "mod.py"
    assert cli.main(["allow", str(path), "g", "--reason", "g is being retired", "--root", str(root)]) == 0
    event = _edit_event(root, sid, path, "    if x < 0:\n        raise ValueError(x)\n", "")
    assert hooks.decide(event, kernel)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_an_agent_declaring_its_own_allowance_from_bash_must_be_approved_by_the_human(tmp_path):
    kernel = StateKernel()
    for command in ('stepcheck allow mod.py f --reason "trust me"', "python -m cli allow x.py --reason y && stepcheck allow z.py --reason w",
                    "echo '{\"path\": \"mod.py\"}' >> .stepcheck/declared.jsonl", "rm .stepcheck/declared.jsonl"):
        out = hooks.decide({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(tmp_path),
                            "tool_input": {"command": command}}, kernel)["hookSpecificOutput"]
        assert out["permissionDecision"] == "ask" and "Approve only if you asked for it" in out["permissionDecisionReason"], command
    assert hooks.decide({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(tmp_path),
                         "tool_input": {"command": "git status && stepcheck retro ."}}, kernel) == {}


# ------------------------------------------------------------- 4. connect / disconnect


def test_connect_installs_a_chained_pre_commit_gate_and_cursor_mcp_and_disconnect_restores(tmp_path, capsys, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _write(root, "mod.py", GUARDED)
    _commit(root, "initial")
    hooks_dir = root / ".git" / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    user_hook = "#!/bin/sh\necho user-hook-ran > user-hook.txt\n"
    (hooks_dir / "pre-commit").write_text(user_hook, encoding="utf-8", newline="\n")
    os.chmod(hooks_dir / "pre-commit", 0o755)
    (root / ".cursor").mkdir()

    assert cli.main(["connect", str(root), "--no-retro"]) == 0
    out = capsys.readouterr().out
    assert "git hook : installed; your existing hook is chained" in out and ".cursor  : wired stepcheck" in out
    hook_text = (hooks_dir / "pre-commit").read_text(encoding="utf-8")
    assert "stepcheck pre-commit" in hook_text and "diff --staged" in hook_text and "pre-commit.stepcheck-chained" in hook_text
    assert (hooks_dir / "pre-commit.stepcheck-chained").read_text(encoding="utf-8") == user_hook
    cursor = json.loads((root / ".cursor" / "mcp.json").read_text(encoding="utf-8"))
    entry = cursor["mcpServers"]["stepcheck"]  # Slice 39: stdio, so a cold boot never meets a refused port
    assert entry["args"][-1] == "mcp" and Path(entry["command"]).is_file() and "url" not in entry

    # a staged guard drop is refused at commit time, whatever wrote it; the user hook still ran
    _write(root, "mod.py", DROPPED)
    _git(root, "add", "mod.py")
    done = subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "drop"],
                          cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    assert done.returncode != 0, done.stdout + done.stderr
    assert "silent regressions" in done.stdout + done.stderr and "mod.py :: f" in done.stdout + done.stderr
    assert (root / "user-hook.txt").read_text(encoding="utf-8").strip() == "user-hook-ran"
    assert _git(root, "rev-list", "--count", "HEAD").strip() == "1"
    # a clean edit commits
    _write(root, "mod.py", GUARDED + "\n\ndef h(z):\n    return z\n")
    _git(root, "add", "mod.py")
    assert _commit(root, "add h") and _git(root, "rev-list", "--count", "HEAD").strip() == "2"

    assert cli.main(["disconnect", str(root)]) == 0
    out = capsys.readouterr().out
    assert "your original hook restored" in out
    assert (hooks_dir / "pre-commit").read_text(encoding="utf-8") == user_hook and not (hooks_dir / "pre-commit.stepcheck-chained").exists()
    assert not (root / ".cursor" / "mcp.json").exists()
    assert "stepcheck" not in (root / ".mcp.json").read_text(encoding="utf-8") if (root / ".mcp.json").exists() else True
    settings = root / ".claude" / "settings.json"
    assert not settings.exists() or "stepcheck_hook.py" not in settings.read_text(encoding="utf-8")


def test_connect_without_a_cursor_directory_writes_nothing_for_cursor_unless_asked(tmp_path, capsys):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _write(root, "mod.py", GUARDED)
    _commit(root, "initial")
    assert cli.main(["connect", str(root), "--no-git-hook", "--no-retro"]) == 0
    assert not (root / ".cursor").exists() and not (root / ".git" / "hooks" / "pre-commit").exists()
    assert cli.main(["connect", str(root), "--cursor", "--no-git-hook", "--no-retro"]) == 0
    assert (root / ".cursor" / "mcp.json").exists()
    capsys.readouterr()


def test_connect_teaser_names_a_silent_regression_in_history(history, capsys):
    assert cli.main(["connect", str(history["root"]), "--no-git-hook"]) == 0
    out = capsys.readouterr().out
    assert "retro    :" in out and "silent regression" in out and "stepcheck retro" in out


def test_action_yml_gates_pull_requests_with_diff_and_pushes_with_ci():
    import yaml

    spec = yaml.safe_load((Path(__file__).resolve().parents[2] / "action.yml").read_text(encoding="utf-8"))
    inputs = spec["inputs"]
    assert inputs["base"]["default"] == "${{ github.event.pull_request.base.sha }}"
    assert inputs["fail-on-catch"]["default"] == "true" and inputs["report-path"]["default"] == "stepcheck-report.md"
    runs = "\n".join(s.get("run", "") for s in spec["runs"]["steps"])
    assert 'stepcheck diff "$STEPCHECK_PATH" --base "$STEPCHECK_BASE" --markdown' in runs
    assert 'stepcheck ci "$STEPCHECK_PATH" --report --report-out "$STEPCHECK_REPORT"' in runs  # the push path is kept
    assert '>> "$GITHUB_STEP_SUMMARY"' in runs and 'exit "$status"' in runs


# ------------------------------------------------------------- 5. Seam 1


def test_judge_transition_runs_the_gates_on_a_pair_in_memory(tmp_path):
    kernel = StateKernel()
    rejected = kernel.judge_transition("pkg/core.py", CORE, CORE.replace("if x <= 10:", "if x < 10:"), root=tmp_path)
    assert not rejected.accepted and rejected.gate == "C"
    assert kernel.judge_transition("pkg/core.py", CORE, CORE + "\n\ndef extra(q):\n    return q\n", root=tmp_path).accepted
    declared_ok = kernel.judge_transition("pkg/core.py", CORE, CORE.replace("if x <= 10:", "if x < 10:"), allow_deletion=True, root=tmp_path)
    assert declared_ok.accepted
    assert not (tmp_path / ".stepcheck").exists()  # nothing written anywhere
    assert any("limit" in inv for inv in kernel.mined_invariants("pkg/core.py", CORE, root=tmp_path))
