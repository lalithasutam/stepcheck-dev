"""Slice 32 — the open gaps of the d19271d snapshot (Seams 1 and 2).

Guard mining stopped at the leading run and at literal `.get` defaults; focused
payloads of small modules outweighed the file; a dead-symbol refactor and an
assert turned into a raise failed strict Gate B / C; the offline hook paid the
kernel import for a Read; Java same-package references were not edges.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import cli
from kernel import _tokens


def _write(root, files):
    for rel, src in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src, encoding="utf-8", newline="\n")
    return root


def _node(kernel, sid, node_id):
    return next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == node_id)


def _replace(name, code):
    return [{"op": "replace_symbol", "name": name, "code": code}]


# ------------------------------------------------ 1. guard idioms beyond the leading run

EARLY = (
    "def find_best(module, names):\n"
    "    from json import loads\n"
    "    for name in names:\n"
    "        app = getattr(module, name, None)\n"
    "        if app is not None:\n"
    "            return app\n"
    "    matches = [n for n in names if n.startswith('app')]\n"
    "    if len(matches) == 1:\n"
    "        return matches[0]\n"
    "    elif len(matches) > 1:\n"
    "        raise RuntimeError('ambiguous')\n"
    "    return loads('null')\n\n\n"
    "class Quiz:\n"
    "    def check(self, i, answer, answers, proxies):\n"
    "        if answers[i] == answer:\n"
    "            self.score = 1\n"
    "            return self.score\n"
    "        return proxies.get(answer, proxies.get('all'))\n"
)
EVAL = ("def ev(op, a, b):\n    left, right = a, b\n    if op == '+':\n        return left + right\n"
        "    elif op == '-':\n        return left - right\n    else:\n        raise ValueError(op)\n")


def test_early_returns_are_mined_from_direct_branches_not_loop_bodies(kernel, tmp_path):
    _write(tmp_path, {"m.py": EARLY})
    sid = kernel.init_session(tmp_path)
    mined = set(_node(kernel, sid, "m")["invariants_auto_mined"])
    assert "guard:find_best:if len(matches) == 1 returns early" in mined  # after a loop and an assignment
    assert "guard:find_best:if len(matches) > 1 raises RuntimeError" in mined
    assert not any("app is not None" in g for g in mined)  # a return inside the loop is control flow
    assert "guard:Quiz.check:if answers[i] == answer returns early" in mined  # a two-statement branch
    assert "guard:Quiz.check:proxies.get(answer) has default" in mined  # a name key, a call default
    assert not any("proxies.get('all')" in g for g in mined)  # one argument: nothing to downgrade

    refactored = kernel.commit(sid, "m", source=EARLY.replace("return matches[0]", "return str(matches[0])"))
    assert refactored.accepted, refactored.error  # the expression may change, the condition is held
    weakened = kernel.commit(sid, "m", source=EARLY.replace("if len(matches) == 1:", "if len(matches) >= 1:"))
    assert not weakened.accepted and weakened.gate == "C" and "returns early" in str(weakened.error)
    bare = kernel.commit(sid, "m", source=EARLY.replace("proxies.get(answer, proxies.get('all'))", "proxies[answer]"))
    assert not bare.accepted and bare.gate == "C" and "has default" in str(bare.error)
    assert kernel.commit(sid, "m", source=EARLY.replace("proxies.get('all')", "None")).accepted  # another default
    assert kernel.commit(sid, "m", source=EARLY.replace("proxies.get(answer, proxies.get('all'))", "proxies[answer]"),
                         allow_deletion=True).accepted


def test_an_if_elif_chain_ending_in_else_raise_is_one_guard_that_survives_new_branches(kernel, tmp_path):
    _write(tmp_path, {"e.py": EVAL})
    sid = kernel.init_session(tmp_path)
    mined = _node(kernel, sid, "e")["invariants_auto_mined"]
    assert "guard:ev:else raises ValueError" in mined and "guard:ev:if op == '+' returns early" in mined
    grown = kernel.commit(sid, "e", source=EVAL.replace("    else:\n", "    elif op == '*':\n        return left * right\n    else:\n"))
    assert grown.accepted, grown.error  # appending a branch keeps the chain's final raise
    neutered = kernel.commit(sid, "e", source=EVAL.replace("raise ValueError(op)", "return None"))
    assert not neutered.accepted and neutered.gate == "C" and "else raises ValueError" in str(neutered.error)


# ------------------------------------------------------------- 2. the zero-bloat floor

UTIL = ("def helper(x):\n    if x is None:\n        raise ValueError('x')\n    return x\n\n\n"
        "def unused(y):\n    if y is None:\n        return 'UNUSED_BODY_MARKER'\n    return y\n")
TINY = "from util import helper\n\n\ndef add(a, b):\n    if a is None:\n        raise ValueError('a')\n    return helper(a + b)\n"


def test_focused_payloads_never_outweigh_a_covered_module_and_never_expand_a_partial_focus(kernel, tmp_path):
    rows = "".join(f"CONFIG_ROW_{i} = '{'c' * 48}'\n" for i in range(40))
    _write(tmp_path, {"tiny.py": TINY, "util.py": UTIL, "big.py": UTIL + "\n\n" + rows})
    sid = kernel.init_session(tmp_path)

    covered = kernel.checkout(sid, "tiny", focus=["add"])  # the focus and its cone are the whole module
    assert covered.pragma and covered.rendered() == TINY and covered.token_count == _tokens.count(TINY)
    assert any(e.startswith("helper(") for e in covered.dependency_signatures["util"])  # the interface is a field
    assert any(i.startswith(("guard:add:", "call:add(")) for i in covered.locked_invariants)

    partial = kernel.checkout(sid, "util", focus=["helper"])
    head, rest = partial.frame_markdown.split("\n", 1)
    assert head.startswith("# [stepcheck: util | ACTIVE | invariants: ") and rest.startswith("```python\n")
    assert "def unused(y):" in rest and "UNUSED_BODY_MARKER" not in rest  # sliced, never expanded to the file
    listed = partial.rendered().split("## Locked invariants", 1)[1]  # the focus's own guard, still in the text
    assert "helper" in listed and "unused" not in listed  # the sibling's guard is counted, not listed
    assert partial.token_count < kernel.checkout(sid, "util").token_count

    skeleton = kernel.checkout(sid, "util", focus=[])
    assert skeleton.frame_markdown.startswith("# [stepcheck: util | ") and skeleton.token_count <= partial.token_count
    assert "UNUSED_BODY_MARKER" not in skeleton.rendered()

    fits = kernel.checkout(sid, "big", focus=["helper"])  # the frame is cheaper than this file: frontmatter stays
    assert fits.frame_markdown.startswith("---\nnode_id: big\n") and fits.token_count < _tokens.count(UTIL + rows)
    assert kernel.checkout(sid, "big").frame_markdown.startswith("---\n")  # the full frame is never floored


# ------------------------------------- 3. strict Gate B / C: dead symbols, assert waivers

OLD = 'def process_message(message, message_type):\n    if message_type == "text":\n        return f"text {message}"\n    return "unknown"\n'
NEW = ("from abc import ABC, abstractmethod\n\n\nclass Message(ABC):\n    def __init__(self, content):\n        self.content = content\n\n"
       "    @abstractmethod\n    def process(self):\n        pass\n\n\nclass TextMessage(Message):\n    def process(self):\n"
       "        return f\"text {self.content}\"\n")


def test_strict_gate_b_passes_a_refactor_that_removes_a_symbol_nothing_refers_to(kernel, tmp_path):
    _write(tmp_path, {"oop.py": OLD, "grp.py": "class C4:\n    def size(self):\n        return 4\n"})
    sid = kernel.init_session(tmp_path)
    v = kernel.commit(sid, "oop", source=NEW)  # the function's guard goes with it: Gate C does not ask for it
    assert v.accepted, v.error
    assert kernel.commit(sid, "grp", source="class C8:\n    def size(self):\n        return 8\n").accepted  # a rename
    _write(tmp_path, {"m.py": "def helper(x):\n    return x + 1\n\n\ndef api(x):\n    return helper(x) * 2\n",
                      "user.py": "from m import helper\n\n\ndef g():\n    return helper(1)\n",
                      "d.py": "def audit(f):\n    return f\n\n\n@audit\ndef charge(x):\n    return x\n",
                      "only.py": "def only():\n    return 1\n"})
    sid = kernel.init_session(tmp_path)
    imported = kernel.commit(sid, "m", source="def api(x):\n    return x\n")  # `user` imports helper: Gate A first
    assert not imported.accepted and imported.gate == "A" and "'helper'" in str(imported.error)
    bare = kernel.commit(sid, "user", source="def g():\n    return 1\n")  # drops the `call:helper` fingerprint
    assert not bare.accepted and bare.gate == "B" and "call:helper" in str(bare.error)  # internal calls are never dead
    assert kernel.commit(sid, "user", source="def g():\n    return 1\n", allow_deletion=True).accepted
    still = kernel.commit(sid, "m", source="def api(x):\n    return helper(x) * 2\n")
    assert not still.accepted and still.gate == "B" and "def helper" in str(still.error)  # a reference survives
    gone = kernel.commit(sid, "m", source="def helper(x):\n    return x + 1\n\n\ndef total(x):\n    return helper(x) * 2\n")
    assert gone.accepted, gone.error  # `api` replaced by `total`: nothing refers to the old name any more
    dec = kernel.commit(sid, "d", source="def audit(f):\n    return f\n\n\ndef charge(x):\n    return x\n")
    assert not dec.accepted and dec.gate == "B" and "@audit on charge" in str(dec.error)  # decorators are never dead
    last = kernel.commit(sid, "only", source="X = 1\n")
    assert not last.accepted and last.gate == "B"  # a module emptied of exports is an omission, not a refactor


ASSERTS = "LIMIT = 10\n\n\ndef credit(cents, owner):\n    assert cents > 0\n    assert owner\n    assert cents < LIMIT\n    return cents\n"


def test_strict_gate_c_waives_an_assert_only_when_its_variable_is_gone_or_it_became_a_raise(kernel, tmp_path):
    _write(tmp_path, {"a.py": ASSERTS, "b.py": ASSERTS, "c.py": ASSERTS})  # one module per scenario
    sid = kernel.init_session(tmp_path)
    assert "guard:credit:assert cents > 0" in _node(kernel, sid, "a")["invariants_auto_mined"]
    as_raise = kernel.commit(sid, "a", source=ASSERTS.replace("    assert cents > 0\n", "    if cents <= 0:\n        raise ValueError('cents')\n"))
    assert as_raise.accepted, as_raise.error
    renamed = kernel.commit(sid, "b", source=ASSERTS.replace("cents", "amount"))
    assert renamed.accepted, renamed.error
    for broken, clause in ((ASSERTS.replace("    assert cents > 0\n", ""), "assert cents > 0"),
                           (ASSERTS.replace("assert cents > 0", "assert cents >= 0"), "assert cents > 0"),
                           (ASSERTS.replace("    assert cents < LIMIT\n", ""), "assert cents < LIMIT")):  # LIMIT still exists
        v = kernel.commit(sid, "c", source=broken)
        assert not v.accepted and v.gate == "C" and clause in str(v.error), (broken, v.error)


# ----------------------------------------------------- 4. the offline hook fast path (Seam 2)


def test_offline_hook_answers_a_read_without_the_kernel_and_still_gates_an_edit(project):
    assert cli.main(["hooks", str(project)]) == 0
    script = project / ".claude" / "hooks" / "stepcheck_hook.py"
    env = {**os.environ, "STEPCHECK_HOOK_URL": "http://127.0.0.1:8461/v1/step/hook", "STEPCHECK_HOOK_AUTOSTART": "0",
           "STEPCHECK_HOOK_TRACE": "1", "STEPCHECK_BACKEND": str(Path(cli.__file__).resolve().parent)}
    read = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read",
                       "tool_input": {"file_path": str(project / "billing.py")}, "cwd": str(project)})
    in_hook = []
    for _ in range(6):
        done = subprocess.run([sys.executable, "-S", "-I", str(script)], input=read, capture_output=True, text=True,
                              env=env, timeout=60)
        assert done.returncode == 0 and done.stdout == "" and "allowing the Read" in done.stderr, done.stderr
        in_hook.append(float(re.search(r"([\d.]+) ms in hook", done.stderr).group(1)))
    assert max(in_hook) < 150, in_hook  # ~25-40 ms locally; CI runners are slower, the receipt records the real p95
    traced = subprocess.run([sys.executable, "-S", "-I", "-X", "importtime", str(script)], input=read,
                            capture_output=True, text=True, env=env, timeout=60)
    imported = {line.rsplit("|", 1)[1].strip() for line in traced.stderr.splitlines() if line.startswith("import time:")}
    assert not imported & {"kernel", "hooks", "yaml", "site", "subprocess", "importlib.util"}, sorted(imported)

    edit = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(project),
                       "tool_input": {"file_path": str(project / "billing.py"), "old_string": "def charge(", "new_string": "def charge(("}})
    done = subprocess.run([sys.executable, "-S", "-I", str(script)], input=edit, capture_output=True, text=True, env=env, timeout=180)
    assert done.returncode == 2 and "Gate A" in done.stderr, done.stderr  # the in-process gates still run offline
    assert "def charge((" not in (project / "billing.py").read_text(encoding="utf-8")


# -------------------------------------------------------- 5. Java same-package dependencies

JAVA_ACCOUNT = ('package com.acme.ledger;\n\n/** Account. */\npublic class Account {\n    private long balance;\n\n'
                '    public Account(String owner) {\n        if (owner == null) {\n            throw new IllegalArgumentException("owner");\n        }\n    }\n\n'
                '    public long credit(long cents) {\n        balance += cents;\n        return balance;\n    }\n}\n')
JAVA_LEDGER = ('package com.acme.ledger;\n\n/** Ledger. */\npublic class Ledger {\n    private final Account account;\n\n'
               '    public Ledger(String owner) {\n        this.account = new Account(owner);\n    }\n\n'
               '    public long total() {\n        return account.credit(1);\n    }\n}\n')
JAVA_THING = 'package com.acme.other;\n\npublic class Thing {\n    public int size() {\n        return 1;\n    }\n}\n'


def test_java_same_package_references_are_edges_with_the_usual_contract(kernel, tmp_path):
    _write(tmp_path, {"com/acme/ledger/Account.java": JAVA_ACCOUNT, "com/acme/ledger/Ledger.java": JAVA_LEDGER,
                      "com/acme/other/Thing.java": JAVA_THING})
    sid = kernel.init_session(tmp_path)
    assert {n["node_id"]: n["deps"] for n in kernel.graph(sid)["nodes"]} == {"Account": [], "Ledger": ["Account"], "Thing": []}
    signed_src = JAVA_ACCOUNT.replace("credit(long cents)", "credit(long cents, String memo)")
    signed = kernel.commit(sid, "Account", source=signed_src)
    assert signed.accepted and signed.dirtied == ["Ledger"]  # the member Ledger reads changed shape
    assert _node(kernel, sid, "Ledger")["status"] == "DIRTY_OMISSION_RISK"
    removed = kernel.commit(sid, "Account", source=signed_src.replace("class Account", "class Wallet").replace("Account(String", "Wallet(String"),
                            allow_deletion=True)
    assert not removed.accepted and removed.gate == "A" and "'Account'" in str(removed.error) and "Ledger" in str(removed.error)
    private = kernel.commit(sid, "Account", source=signed_src.replace("}\n}\n", "}\n\n    private long twice(long c) {\n        return c * 2;\n    }\n}\n"))
    assert private.accepted and private.dirtied == [] and private.reverified == []  # nothing the package sees moved
