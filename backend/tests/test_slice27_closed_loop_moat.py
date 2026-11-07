"""Slice 27 — closing the read-only compression blind spots (Seam 1, Seam 2 and the
installed hook script; zero mocks).

1. A focused checkout renders the same-file helpers the focus calls (transitively,
   `self.` / `cls.` methods included, cycles safe) verbatim instead of `...`.
2. Deterministic value-returning branches (`if <param> == <literal>: return …`,
   `in (<literals>)`) are mined into executable `call:<expr> == <literal>`
   invariants, for the helper and for every pure same-file caller that passes
   the parameter through; Gate C executes them on every commit.
3. A cache-cliff fold of the middle band keeps natural-language user constraints
   verbatim while still dropping the raw tool output around them.
4. With the gateway down, the installed hook decides Edit / Write in-process and
   blocks a gate violation (exit 2, structured deny) before bytes land, and starts
   a detached local gateway so the following hook calls are answered warm.
5. The causal cone reaches past `ast.Call`: bare same-file decorators, the module
   constants the cone reads, and a focused method's `__init__` / `__post_init__`
   and class-level attributes are rendered verbatim.

The head-to-head test emulates signature-only compression (every body reduced to
`...`, the view Repomix `--compress` / LeanCTX `signatures` give a model) with the
standard library; it does not run those tools.
"""
import ast
import json
import os
import signal
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import cli
from kernel import StateKernel

BACKEND = Path(__file__).resolve().parents[1]

BILLING = textwrap.dedent('''\
    """Billing: amounts arrive in major units; the ledger stores minor units."""


    def _normalize_amount(amount: int, currency: str) -> int:
        """Minor units for the ledger."""
        if currency == "JPY":
            return amount
        return amount * 100


    def charge(user: str, amount: int, currency: str) -> dict:
        if amount <= 0:
            raise ValueError("amount must be positive")
        return {"user": user, "charged": _normalize_amount(amount, currency)}


    def refund(user: str, amount: int) -> dict:
        return {"user": user, "refunded": amount, "note": "REFUND_BODY_MARKER"}
    ''')

# The refactor a model makes when it only sees `def _normalize_amount(...) -> int: ...`:
# inline the conversion, multiply everything by 100, and lose the JPY rule.
INLINE_REFACTOR = textwrap.dedent('''\
    def charge(user: str, amount: int, currency: str) -> dict:
        if amount <= 0:
            raise ValueError("amount must be positive")
        cents = amount * 100
        return {"user": user, "charged": cents}
    ''')

JPY_TIMES_100 = textwrap.dedent('''\
    def _normalize_amount(amount: int, currency: str) -> int:
        """Minor units for the ledger."""
        if currency == "JPY":
            return amount * 100
        return amount * 100
    ''')

JPY_INVARIANT = "call:_normalize_amount(amount=100, currency='JPY') == 100"
CHARGE_INVARIANT = "call:charge(user='x', amount=100, currency='JPY') == {'user': 'x', 'charged': 100}"


@pytest.fixture()
def billing_project(tmp_path: Path) -> Path:
    root = tmp_path / "shop"
    root.mkdir()
    (root / "billing.py").write_text(BILLING, encoding="utf-8", newline="\n")
    return root


def signature_only(source: str) -> str:
    """Signature-only compression: every function body becomes `...`."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node.body = [ast.Expr(ast.Constant(...))]
    return ast.unparse(tree)


def _replace_def(source: str, name: str, new_def: str) -> str:
    tree = ast.parse(source)
    fn = next(s for s in tree.body if isinstance(s, ast.FunctionDef) and s.name == name)
    lines = source.splitlines(keepends=True)
    return "".join(lines[: fn.lineno - 1]) + new_def + "".join(lines[fn.end_lineno:])


# --------------------------------------------------------------- head to head


def test_jpy_billing_stepcheck_vs_signature_only_competitors(billing_project):
    # (a) Signature-only view: the helper is `...`, the JPY rule is invisible, and the
    # broken refactor compiles with every signature unchanged — nothing to catch it.
    view = signature_only(BILLING)
    assert "def _normalize_amount(amount: int, currency: str) -> int:\n    ..." in view
    assert "JPY" not in view
    broken = _replace_def(BILLING, "charge", INLINE_REFACTOR)
    compile(broken, "billing.py", "exec")
    assert signature_only(broken) == view  # identical to the model and to a signature check
    ns: dict = {}
    exec(compile(broken, "billing.py", "exec"), ns)  # noqa: S102 — and it is wrong
    assert ns["charge"]("x", 100, "JPY") == {"user": "x", "charged": 10000}

    # (b) StepCheck: the focused frame carries the helper verbatim plus the mined rule.
    kernel = StateKernel()
    sid = kernel.init_session(billing_project)
    node = next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == "billing")
    assert JPY_INVARIANT in node["invariants_auto_mined"]
    assert CHARGE_INVARIANT in node["invariants_auto_mined"]

    payload = kernel.checkout(sid, "billing", focus=["charge"])
    rendered = payload.rendered()
    assert 'if currency == "JPY":\n        return amount\n    return amount * 100' in rendered
    assert "REFUND_BODY_MARKER" not in rendered  # unrelated bodies stay elided
    locked = rendered.split("## Locked invariants", 1)[1]
    assert JPY_INVARIANT in locked and CHARGE_INVARIANT in locked
    assert JPY_INVARIANT in payload.locked_invariants

    for name, code in (("charge", INLINE_REFACTOR), ("_normalize_amount", JPY_TIMES_100)):
        timings = []
        for _ in range(3):
            started = time.perf_counter()
            verdict = kernel.commit(sid, "billing", patch=[{"op": "replace_symbol", "name": name, "code": code}])
            timings.append((time.perf_counter() - started) * 1000)
            assert verdict.accepted is False and verdict.gate == "C", verdict.error
        assert "JPY" in str(verdict.error)
        assert min(timings) < 50, timings
    assert (billing_project / "billing.py").read_text(encoding="utf-8") == BILLING  # nothing landed


# ------------------------------------------------- 1. transitive callee expansion

CART = textwrap.dedent('''\
    TAX = 7


    def _tax(cents: int) -> int:
        return cents * TAX // 100 + _round(cents)


    def _round(cents: int) -> int:
        if cents > 10:
            return _round(cents // 10)  # self-recursion must not loop the resolver
        return cents


    def _ping(n: int) -> int:
        return _pong(n - 1) if n > 0 else 0


    def _pong(n: int) -> int:
        return _ping(n - 1) if n > 0 else 1


    def _unused() -> str:
        return "UNUSED_BODY_MARKER"


    class Cart:
        def total(self, cents: int) -> int:
            return cents + self._fees(cents) + _ping(3)

        def _fees(self, cents: int) -> int:
            return Cart._shipping() + _tax(cents)

        @classmethod
        def _shipping(cls) -> int:
            return cls._base() + 1

        @classmethod
        def _base(cls) -> int:
            return 499

        def describe(self) -> str:
            return "DESCRIBE_BODY_MARKER"


    def checkout(cart: Cart, cents: int) -> int:
        return cart.total(cents)
    ''')


def test_focus_expands_same_file_callees_transitively_through_methods_and_cycles(kernel, tmp_path):
    (tmp_path / "cart.py").write_text(CART, encoding="utf-8", newline="\n")
    sid = kernel.init_session(tmp_path)
    frame = kernel.checkout(sid, "cart", focus=["Cart.total"]).frame_markdown
    for body in ("return cents + self._fees(cents) + _ping(3)",       # the focus
                 "return Cart._shipping() + _tax(cents)",              # self.method
                 "return cls._base() + 1", "return 499",               # Class.method / cls.method
                 "return cents * TAX // 100 + _round(cents)",          # module function from a method
                 "return _round(cents // 10)",                         # its recursive callee
                 "return _pong(n - 1) if n > 0 else 0", "return _ping(n - 1) if n > 0 else 1"):  # a cycle
        assert body in frame, body
    assert "UNUSED_BODY_MARKER" not in frame and "DESCRIBE_BODY_MARKER" not in frame
    assert "callees" in frame.lower()  # the frame says which bodies were pulled in and why

    plain = kernel.checkout(sid, "cart", focus=["checkout"]).frame_markdown
    assert "return cart.total(cents)" in plain
    assert "return 499" not in plain  # `cart.total` is not self/cls: no guessing at receivers


# --------------------------------------------- 2. deep branch-literal mining

RATES = textwrap.dedent('''\
    from fx import live_rate

    LIMIT = 3


    def _zero_decimal(currency: str) -> bool:
        if currency in ("JPY", "KRW"):
            return True
        return False


    def scale(amount: int, currency: str) -> int:
        if _zero_decimal(currency):
            return amount
        return amount * 100


    def tier(plan: str) -> str:
        if plan == "free":
            return "FREE_TIER"
        return "paid"


    def convert(amount: int, currency: str) -> float:
        if currency == "EUR":
            return amount * live_rate(currency)  # impure: never characterized
        return float(amount)
    ''')


def test_branch_literals_are_mined_for_helpers_and_pure_callers_only(kernel, tmp_path):
    (tmp_path / "fx.py").write_text("def live_rate(c: str) -> float:\n    return 1.1\n", encoding="utf-8", newline="\n")
    (tmp_path / "rates.py").write_text(RATES, encoding="utf-8", newline="\n")
    sid = kernel.init_session(tmp_path)
    node = next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == "rates")
    mined = node["invariants_auto_mined"]
    assert "call:_zero_decimal(currency='JPY') == True" in mined
    assert "call:_zero_decimal(currency='KRW') == True" in mined
    assert "call:scale(amount=100, currency='JPY') == 100" in mined  # caller of the helper
    assert "call:tier(plan='free') == 'FREE_TIER'" in mined
    assert not any(inv.startswith("call:convert(") for inv in mined)  # calls an import
    assert set(mined) <= set(node["invariants"])

    ok = kernel.commit(sid, "rates", patch=[{"op": "replace_symbol", "name": "tier", "code":
                                             'def tier(plan: str) -> str:\n    if plan == "free":\n'
                                             '        return "FREE_TIER"\n    return "paid-v2"\n'}])
    assert ok.accepted, ok.error  # behaviour outside the mined branch is free to change
    bad = kernel.commit(sid, "rates", patch=[{"op": "replace_symbol", "name": "_zero_decimal", "code":
                                              'def _zero_decimal(currency: str) -> bool:\n'
                                              '    if currency in ("JPY",):\n        return True\n    return False\n'}])
    assert bad.accepted is False and bad.gate == "C" and "KRW" in str(bad.error)
    waived = kernel.commit(sid, "rates", allow_deletion=True, patch=[{"op": "replace_symbol", "name": "_zero_decimal", "code":
                                                                     'def _zero_decimal(currency: str) -> bool:\n'
                                                                     '    if currency in ("JPY",):\n        return True\n    return False\n'}])
    assert waived.accepted, waived.error  # a declared behaviour change waives mined rules, as for guards


# --------------------------------------------- 3. middle-band constraint pinning

RULE = "CRITICAL RULE: All timestamps in events.py are Unix milliseconds (ms), NEVER seconds."
STACK = "Traceback (most recent call last):\n" + "".join(
    f'  File "events.py", line {i}, in handler_{i}\n    payload = decode(raw_{i})\n' for i in range(120)
) + "ValueError: DEAD_END_TRACE_MARKER\n"


def test_cache_cliff_fold_pins_user_constraints_and_drops_tool_noise(project):
    import server

    with TestClient(server.app) as client:
        sid = client.post("/v1/step/init", json={"project_root": str(project)}).json()["session_id"]
        step = "```stepcheck-patch\n" + json.dumps([{"op": "append", "code": "def _h() -> int:\n    return 1\n"}]) + "\n```"
        msgs = [
            {"role": "user", "content": RULE},
            {"role": "assistant", "content": "Running the suite:\n" + step},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": STACK}]},
            {"role": "user", "content": "Here is the log again, keep going:\n" + STACK},
            {"role": "assistant", "content": "Applying:\n" + step},
            {"role": "user", "content": "ok"},
            {"role": "assistant", "content": "Applying:\n" + step},
            {"role": "user", "content": "Verify and finish."},
        ]
        r = client.post("/v1/chat/completions", json={"model": "gpt-x", "messages": msgs},
                        headers={"x-stepcheck-session": sid, "x-stepcheck-node": "billing",
                                 "x-stepcheck-last-turn-at": str(time.time() - 400)})
        assert r.status_code == 200, r.text
        fw = r.json()["stepcheck"]
    comp = fw["compaction"]
    assert comp["cache_cliff"] is True and comp["folded_messages"] >= 3
    assert comp["pinned_constraints"] == 1
    [fold] = [m for m in fw["sent_messages"] if m["role"] != "system"][:-4]
    assert "StepCheck session state" in fold["content"]
    assert RULE in fold["content"]  # verbatim
    assert "DEAD_END_TRACE_MARKER" not in fold["content"] and "handler_5" not in fold["content"]


# ------------------------------- 4a. verify before the write, adopt after it


def test_dry_run_commit_verifies_without_writing_and_sync_adopts_the_tools_bytes(kernel, project):
    sid = kernel.init_session(project)
    billing = project / "billing.py"
    original = billing.read_text(encoding="utf-8")
    widened = original.replace("def charge(user: str, amount_cents: int) -> dict:",
                               'def charge(user: str, amount_cents: int, currency: str = "USD") -> dict:')

    ok = kernel.commit(sid, "billing", source=widened, dry_run=True)
    assert ok.accepted and ok.attestation is None and ok.dirtied == []
    assert billing.read_text(encoding="utf-8") == original  # nothing landed
    assert kernel.locate(sid, billing)["status"] != "VERIFIED"  # no node state changed

    bad = kernel.commit(sid, "billing", source=original.replace("@require_auth\n", ""), dry_run=True)
    assert bad.accepted is False and bad.gate == "B"
    assert kernel.locate(sid, billing)["status"] != "REJECTED"  # the edit never happened
    assert kernel.get_telemetry(sid).omissions_blocked == 1  # but the block is on the record

    billing.write_text(widened, encoding="utf-8", newline="\n")  # the agent's Edit tool writes
    assert kernel.sync(sid) == {"synced": ["billing"], "rejected": {}}
    assert kernel.node_source(sid, "billing") == widened
    assert kernel.omission_report(sid)["dirty"] == ["reports"]  # the signature change propagated
    assert next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == "billing")["attestation"]  # attested
    assert kernel.sync(sid) == {"synced": [], "rejected": {}}  # idempotent

    # Bytes written behind the session that break a gate are refused once, left on
    # disk, and do not block the next edit's dry-run check.
    broken = widened.replace('    if amount_cents <= 0:\n        raise ValueError("amount must be positive")\n', "")
    billing.write_text(broken, encoding="utf-8", newline="\n")
    first = kernel.sync(sid)
    assert first["synced"] == [] and first["rejected"]["billing"].startswith("C:")
    blocked = kernel.get_telemetry(sid).omissions_blocked
    assert kernel.sync(sid)["rejected"] == {} and kernel.get_telemetry(sid).omissions_blocked == blocked
    assert billing.read_text(encoding="utf-8") == broken
    assert kernel.commit(sid, "billing", source=widened, dry_run=True).accepted  # restoring the guard is fine


# ------------------------------------------- 4b. fail-closed in-process hook


def _dead_url() -> str:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}/v1/step/hook"  # nothing listens: connection refused


def _run_hook(script: Path, event: dict, *, backend: Path | None = BACKEND, python: str = sys.executable):
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PROJECT_DIR", "STEPCHECK_BACKEND")}
    env.update(STEPCHECK_HOOK_URL=_dead_url(), PYTHONUTF8="1")
    if backend is not None:
        env["STEPCHECK_BACKEND"] = str(backend)
    argv = [python, "-S", str(script)]  # as installed: `python -S`
    return subprocess.run(argv, input=json.dumps(event), capture_output=True, text=True, env=env, timeout=60)


def test_gate_b_rejects_a_rewrite_that_stubs_an_unfocused_body(kernel, billing_project):
    sid = kernel.init_session(billing_project)
    rendered = kernel.checkout(sid, "billing", focus=["charge"]).rendered()
    copied = rendered.split("```python\n", 1)[1].split("```", 1)[0]  # the frame's code, refund elided to `...`
    assert "def refund(user: str, amount: int) -> dict:\n    ...\n" in copied

    verdict = kernel.commit(sid, "billing", source=copied)
    assert not verdict.accepted and verdict.gate == "B"
    assert ("symbol 'refund' body was replaced with skeleton stub '...' "
            "(preserve original implementation or use patch replace_symbol)") in str(verdict.error)

    for stub in ('    pass\n', '    """Refund."""\n'):  # `pass` and docstring-only bodies are stubs too
        wiped = _replace_def(BILLING, "refund", "def refund(user: str, amount: int) -> dict:\n" + stub)
        assert kernel.commit(sid, "billing", source=wiped).gate == "B"
    patched = kernel.commit(sid, "billing", patch=[{"op": "replace_symbol", "name": "refund",
                                                    "code": "def refund(user: str, amount: int) -> dict:\n    ...\n"}])
    assert patched.gate == "B" and "'refund'" in str(patched.error)
    assert (billing_project / "billing.py").read_text(encoding="utf-8") == BILLING

    import server  # the native Write tool is held to the same rule (Seam 2)

    with TestClient(server.app) as client:
        out = client.post("/v1/step/hook", json={
            "hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": str(billing_project),
            "tool_input": {"file_path": str(billing_project / "billing.py"), "content": copied}}).json()
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny" and "Gate B" in hso["permissionDecisionReason"]
    assert "skeleton stub" in hso["permissionDecisionReason"]

    # A real body change is fine, and allow_deletion still declares an intended stub.
    assert kernel.commit(sid, "billing", patch=[{"op": "replace_symbol", "name": "refund", "code":
                         "def refund(user: str, amount: int) -> dict:\n    return {'user': user, 'refunded': -amount}\n"}]).accepted
    assert kernel.commit(sid, "billing", source=copied, allow_deletion=True).accepted


def test_post_tool_use_adopts_the_written_file_so_ci_is_green_at_once(billing_project, capsys):
    assert cli.main(["hooks", str(billing_project)]) == 0
    settings = json.loads((billing_project / ".claude" / "settings.json").read_text(encoding="utf-8"))
    post = settings["hooks"]["PostToolUse"]
    assert len(post) == 1 and {"Edit", "Write"} <= set(post[0]["matcher"].split("|"))
    commands = {h["command"] for e in settings["hooks"].values() for m in e for h in m["hooks"]}
    assert commands == {'python -S "$CLAUDE_PROJECT_DIR/.claude/hooks/stepcheck_hook.py"'}
    kernel = StateKernel()
    sid = kernel.init_session(billing_project)
    assert kernel.commit(sid, "billing", patch=[{"op": "append", "code": "def audit() -> int:\n    return 1\n"}]).accepted
    target = billing_project / "billing.py"
    written = target.read_text(encoding="utf-8").replace('"REFUND_BODY_MARKER"', '"REFUND_BODY_MARKER", "v": 2')
    target.write_text(written, encoding="utf-8", newline="\n")  # the Edit tool wrote it
    capsys.readouterr()
    assert cli.main(["ci", str(billing_project)]) != 0  # drift until the session adopts the bytes

    script = billing_project / ".claude" / "hooks" / "stepcheck_hook.py"
    event = {"hook_event_name": "PostToolUse", "tool_name": "Edit", "cwd": str(billing_project),
             "tool_input": {"file_path": str(target)}, "tool_response": {"filePath": str(target)}}
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PROJECT_DIR", "STEPCHECK_BACKEND")}
    env.update(STEPCHECK_HOOK_URL=_dead_url(), PYTHONUTF8="1", STEPCHECK_BACKEND=str(BACKEND))
    done = subprocess.run([sys.executable, "-S", str(script)], input=json.dumps(event), capture_output=True,
                          text=True, env=env, timeout=60)  # installed as `python -S`, gateway down: in-process
    assert done.returncode == 0 and done.stdout == "", (done.stdout, done.stderr)
    assert StateKernel().node_source(sid, "billing") == written
    capsys.readouterr()
    assert cli.main(["ci", str(billing_project)]) == 0

    # Re-running `stepcheck hooks` over an older install migrates its command: no duplicates.
    old = 'python "$CLAUDE_PROJECT_DIR/.claude/hooks/stepcheck_hook.py"'
    stale = {"hooks": {"PreToolUse": [{"matcher": "Read|Edit", "hooks": [{"type": "command", "command": old}]}],
                       "Stop": [{"hooks": [{"type": "command", "command": old}, {"type": "command", "command": "echo bye"}]}]}}
    (billing_project / ".claude" / "settings.json").write_text(json.dumps(stale), encoding="utf-8")
    assert cli.main(["hooks", str(billing_project)]) == 0
    migrated = json.loads((billing_project / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    ours = [h["command"] for e in migrated.values() for m in e for h in m["hooks"] if "stepcheck_hook.py" in h["command"]]
    assert sorted(ours) == sorted([commands.pop()] * 3)
    assert any(h["command"] == "echo bye" for m in migrated["Stop"] for h in m["hooks"])


def test_installed_hook_is_the_cli_template(tmp_path):
    shipped = (BACKEND.parent / ".claude" / "hooks" / "stepcheck_hook.py").read_text(encoding="utf-8")
    assert shipped == cli._HOOK_SCRIPT.replace("__STEPCHECK_HOOK_URL__", "http://127.0.0.1:8420/v1/step/hook")


def test_gateway_down_hook_blocks_a_gate_c_violation_in_process(billing_project, capsys):
    assert cli.main(["hooks", str(billing_project)]) == 0
    capsys.readouterr()
    script = billing_project / ".claude" / "hooks" / "stepcheck_hook.py"
    target = billing_project / "billing.py"
    edit = {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(billing_project),
            "tool_input": {"file_path": str(target),
                           "old_string": 'if currency == "JPY":\n        return amount\n',
                           "new_string": 'if currency == "JPY":\n        return amount * 100\n'}}
    denied = _run_hook(script, edit)
    assert denied.returncode == 2, (denied.stdout, denied.stderr)
    hso = json.loads(denied.stdout)["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny" and "Gate C" in hso["permissionDecisionReason"]
    assert "JPY" in hso["permissionDecisionReason"] and "Gate C" in denied.stderr
    assert target.read_text(encoding="utf-8") == BILLING  # blocked before any byte landed

    write = {"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": str(billing_project),
             "tool_input": {"file_path": str(target), "content": "def unrelated() -> int:\n    return 1\n"}}
    denied_b = _run_hook(script, write)  # no dependents here, so Gate B (dropped `def charge`) speaks
    assert denied_b.returncode == 2 and "Gate B" in json.loads(denied_b.stdout)["hookSpecificOutput"]["permissionDecisionReason"]

    fine = dict(edit, tool_input={"file_path": str(target), "old_string": '"REFUND_BODY_MARKER"',
                                  "new_string": '"REFUND_BODY_MARKER", "v": 2'})
    allowed = _run_hook(script, fine)
    assert allowed.returncode == 0 and allowed.stdout == "", (allowed.stdout, allowed.stderr)
    assert target.read_text(encoding="utf-8") == BILLING  # the hook verifies; the tool writes

    read = {"hook_event_name": "PreToolUse", "tool_name": "Read", "cwd": str(billing_project),
            "tool_input": {"file_path": str(target)}}
    offline_read = _run_hook(script, read)
    assert offline_read.returncode == 0 and offline_read.stdout == ""  # Read stays fail-open offline


def _listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
            return True
    except OSError:
        return False


def test_gateway_down_hook_warms_a_detached_gateway(billing_project, capsys):
    assert cli.main(["hooks", str(billing_project)]) == 0
    capsys.readouterr()
    script = billing_project / ".claude" / "hooks" / "stepcheck_hook.py"
    target = billing_project / "billing.py"
    url = _dead_url()
    port = int(url.split(":")[2].split("/")[0])
    home = Path(os.environ["STEPCHECK_HOME"])
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PROJECT_DIR", "STEPCHECK_BACKEND")}
    env.update(STEPCHECK_HOOK_URL=url, PYTHONUTF8="1", STEPCHECK_BACKEND=str(BACKEND), STEPCHECK_HOOK_AUTOSTART="1")

    def run(event: dict):
        return subprocess.run([sys.executable, str(script)], input=json.dumps(event), capture_output=True,
                              text=True, env=env, timeout=60)  # would hang if the daemon kept our pipes

    edit = {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(billing_project),
            "tool_input": {"file_path": str(target),
                           "old_string": 'if currency == "JPY":\n        return amount\n',
                           "new_string": 'if currency == "JPY":\n        return amount * 100\n'}}
    read = {"hook_event_name": "PreToolUse", "tool_name": "Read", "cwd": str(billing_project),
            "tool_input": {"file_path": str(target)}}
    state = home / f"gateway-{port}.json"
    try:
        cold = run(edit)  # decided in-process at once; the daemon only warms in the background
        assert cold.returncode == 2 and "Gate C" in cold.stderr, (cold.stdout, cold.stderr)
        deadline = time.monotonic() + 90
        while not _listening(port) and time.monotonic() < deadline:
            time.sleep(0.2)
        log = home / f"gateway-{port}.log"
        assert _listening(port), log.read_text(encoding="utf-8", errors="replace") if log.exists() else "no log"
        warm = run(edit)
        assert warm.returncode == 2 and "Gate C" in warm.stderr
        assert target.read_text(encoding="utf-8") == BILLING
        online_read = run(read)
        assert online_read.returncode == 0 and "offline" not in online_read.stderr  # answered by the gateway
    finally:
        if state.exists():
            os.kill(json.loads(state.read_text(encoding="utf-8"))["pid"], signal.SIGTERM)


def test_gateway_down_hook_without_a_stepcheck_install_fails_open(billing_project, tmp_path, capsys):
    assert cli.main(["hooks", str(billing_project)]) == 0
    capsys.readouterr()
    script = billing_project / ".claude" / "hooks" / "stepcheck_hook.py"
    edit = {"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": str(billing_project),
            "tool_input": {"file_path": str(billing_project / "billing.py"), "content": "x = 1\n"}}
    bare = tmp_path / "bare-venv"  # an interpreter with nothing installed: no StepCheck anywhere
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(bare)], check=True, timeout=120)
    python = bare / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    out = _run_hook(script, edit, backend=None, python=str(python))
    assert out.returncode == 0 and out.stdout == ""
    assert "allowing" in out.stderr


# ------------------------------- 5. the causal cone beyond `ast.Call`

LEDGER = textwrap.dedent('''\
    """Ledger: same-file decorators, module constants and class state."""
    import functools
    from dataclasses import dataclass, field

    ZERO_DECIMAL = {"JPY", "KRW"}
    UNUSED_CONST = "UNUSED_CONST_MARKER"
    LOG_PREFIX = "AUDIT_PREFIX_MARKER"


    def audited(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            print(LOG_PREFIX, fn.__name__)
            return fn(*args, **kwargs)
        return wrapper


    @audited
    def minor_units(amount: int, currency: str) -> int:
        if currency in ZERO_DECIMAL:
            return amount
        return amount * 100


    class Account:
        kind = "ACCOUNT_KIND_MARKER"
        limit: int = 5000

        def __init__(self, owner: str) -> None:
            self.owner = owner
            self.balance_minor = 0

        def deposit(self, minor: int) -> int:
            self.balance_minor += minor
            return self.balance_minor

        def describe(self) -> str:
            return "DESCRIBE_MARKER"


    @dataclass
    class Invoice:
        currency: str = "USD"
        lines: list = field(default_factory=list)

        def __post_init__(self) -> None:
            self.lines = list(self.lines)

        def total(self) -> int:
            return sum(self.lines)
    ''')


def test_focus_keeps_decorators_constants_and_class_state_in_the_cone(kernel, tmp_path):
    (tmp_path / "ledger.py").write_text(LEDGER, encoding="utf-8", newline="\n")
    sid = kernel.init_session(tmp_path)

    # (a) + (b): a bare same-file decorator and the constants the cone reads, verbatim.
    frame = kernel.checkout(sid, "ledger", focus=["minor_units"]).frame_markdown
    assert 'ZERO_DECIMAL = {"JPY", "KRW"}' in frame          # read by the focus
    assert "print(LOG_PREFIX, fn.__name__)" in frame         # `@audited` body (not an ast.Call)
    assert 'LOG_PREFIX = "AUDIT_PREFIX_MARKER"' in frame     # read by the decorator, transitively
    assert "UNUSED_CONST_MARKER" not in frame                # unreferenced constants still fold
    assert "DESCRIBE_MARKER" not in frame

    # (c): a focused method keeps its class's __init__ body and class-level attributes.
    acct = kernel.checkout(sid, "ledger", focus=["Account.deposit"]).frame_markdown
    assert "self.balance_minor += minor" in acct
    assert "self.balance_minor = 0" in acct and "self.owner = owner" in acct
    assert 'kind = "ACCOUNT_KIND_MARKER"' in acct and "limit: int = 5000" in acct
    assert "DESCRIBE_MARKER" not in acct                     # siblings stay signatures

    # (c): dataclass fields and __post_init__ for a focused dataclass method.
    inv = kernel.checkout(sid, "ledger", focus=["Invoice.total"]).frame_markdown
    assert 'currency: str = "USD"' in inv and "lines: list = field(default_factory=list)" in inv
    assert "self.lines = list(self.lines)" in inv
    assert "ZERO_DECIMAL = {" not in inv                     # not in this cone
