"""Slice 22 — Door 1 compaction of what real Claude Code sessions actually carry:
`tool_result` blocks (Anthropic) and `role: "tool"` messages (OpenAI) holding
`cat -n` line-numbered file reads (`<n>\\u2192` / `<n>\\t`), fenced or not, in
Python and TypeScript; pytest / git-diff logs over the log threshold keep their
head, failure lines and tail. Seam 2 against the real ASGI app, zero mocks."""
import ast
import json
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
AUDIT_SRC = (BACKEND / "audit.py").read_text(encoding="utf-8")

TS_SRC = '''\
import { useEffect, useState } from "react";
import type { GraphNode, Verdict } from "./types";

export interface SessionView {
  sessionId: string;
  nodes: GraphNode[];
  verdicts: Verdict[];
}

export function statusColour(status: string): string {
  if (status === "LOCKED") {
    return "#5b6b8c";
  }
  if (status === "DIRTY_OMISSION_RISK") {
    return "#d9a400";
  }
  return status === "VERIFIED" ? "#2e9e5b" : "#8a8f98";
}

export async function fetchGraph(base: string, sessionId: string): Promise<SessionView> {
  const res = await fetch(`${base}/v1/step/graph/${sessionId}`);
  if (!res.ok) {
    throw new Error(`graph ${res.status}`);
  }
  const body = await res.json();
  return { sessionId, nodes: body.nodes, verdicts: body.verdicts ?? [] };
}

export const useGraph = (base: string, sessionId: string | null) => {
  const [view, setView] = useState<SessionView | null>(null);
  useEffect(() => {
    if (!sessionId) return;
    fetchGraph(base, sessionId).then(setView).catch(() => setView(null));
  }, [base, sessionId]);
  return view;
};

export class VerdictFeed {
  private items: Verdict[] = [];

  push(v: Verdict): void {
    this.items = [v, ...this.items].slice(0, 50);
  }

  latest(): Verdict | undefined {
    return this.items[0];
  }
}
'''


def _numbered(source: str, sep: str = "→") -> str:
    """Claude Code's Read-tool rendering: `<lineno><sep><line>` (arrow or tab)."""
    return "\n".join(f"{i:6d}{sep}{ln}" for i, ln in enumerate(source.splitlines(), 1))


def _pytest_log(n: int = 600) -> str:
    lines = ["============================= test session starts =============================",
             "platform win32 -- Python 3.12.3, pytest-9.2.0", "collected 598 items", ""]
    for i in range(n - 60):
        lines.append(f"tests/test_module_{i // 20}.py::test_case_{i} PASSED                       [{100 * i // n:3d}%]")
    lines += ["tests/test_billing.py::test_charge_rejects_zero FAILED", "", "=================================== FAILURES ===================================",
              "___________________________ test_charge_rejects_zero ___________________________", "",
              "    def test_charge_rejects_zero():", ">       assert charge('u', 0)['status'] == 'rejected'",
              "E       AssertionError: assert 'charged' == 'rejected'", "", "Traceback (most recent call last):",
              "  File \"tests/test_billing.py\", line 12, in test_charge_rejects_zero"]
    while len(lines) < n:
        lines.append(f"tests/test_tail_{len(lines)}.py::test_tail PASSED")
    lines.append("=========================== 1 failed, 597 passed in 41.02s ===========================")
    return "\n".join(lines)


def _git_diff() -> str:
    out = ["diff --git a/backend/audit.py b/backend/audit.py", "index 3f2a1b0..9c8d7e6 100644", "--- a/backend/audit.py", "+++ b/backend/audit.py"]
    for i in range(1, 140):
        out.append(f"@@ -{i * 3},6 +{i * 3},7 @@ def helper_{i}(x):")
        out.append(f"     value = x + {i}")
        out.append(f"-    return value")
        out.append(f"+    return value * 2  # line {i}")
    return "\n".join(out)


KEEP_CHARGE = [{"op": "replace_symbol", "name": "charge", "code":
                "@require_auth\ndef charge(user: str, amount_cents: int) -> dict:\n"
                '    # okf-invariant: "amount_cents <= 0" in src and "raise ValueError" in src\n'
                "    if amount_cents <= 0:\n        raise ValueError(\"amount must be positive\")\n"
                "    if not check_permission(user, \"charge\"):\n        raise PermissionError(user)\n"
                '    return {"user": user, "amount_cents": amount_cents, "status": "charged", "v": 2}\n'}]


def _step(ops: list[dict]) -> str:
    return f"```stepcheck-patch\n{json.dumps(ops)}\n```"


def _helper(i: int) -> list[dict]:
    return [{"op": "append", "code": f"def _h{i}() -> int:\n    return {i}\n"}]


TOOL_IDS = ["toolu_01read_py", "toolu_02read_ts", "toolu_03pytest", "toolu_04diff"]


def anthropic_conversation() -> list[dict]:
    """15 messages. Older user turns carry tool_result blocks the way Claude Code
    stores them; assistant turns carry steps so they survive dead-end pruning.
    The last four messages are the recent band."""
    py_read = _numbered(AUDIT_SRC)
    ts_read = "frontend/src/graph.ts:\n" + _numbered(TS_SRC, sep="\t")
    return [
        {"role": "user", "content": "Read audit.py and graph.ts, run the suite, then harden charge()."},            # 1
        {"role": "assistant", "content": "Reading audit.py first.\n" + _step(_helper(1))},                           # 2
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": TOOL_IDS[0], "content": py_read}]},     # 3
        {"role": "assistant", "content": "Now the frontend module.\n" + _step(_helper(2))},                          # 4
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": TOOL_IDS[1],
                                      "content": [{"type": "text", "text": ts_read}]}]},                            # 5
        {"role": "assistant", "content": "Running the suite.\n" + _step(_helper(3))},                               # 6
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": TOOL_IDS[2], "content": _pytest_log()}]},  # 7
        {"role": "assistant", "content": "One failure; checking the diff.\n" + _step(_helper(4))},                  # 8
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": TOOL_IDS[3], "content": _git_diff()}]},  # 9
        {"role": "assistant", "content": "I see the cause.\n" + _step(_helper(5))},                                 # 10
        {"role": "user", "content": "Good. Now fix charge()."},                                                    # 11
        {"role": "assistant", "content": "Preparing the fix.\n" + _step(_helper(6))},                               # 12
        {"role": "user", "content": "Apply the fix now."},                                                         # 13
        {"role": "assistant", "content": "Applying:\n" + _step(KEEP_CHARGE)},                                       # 14
        {"role": "user", "content": "Verify and finish."},                                                         # 15
    ]


def openai_conversation() -> list[dict]:
    msgs = [{"role": "system", "content": "You are a careful coding agent."}]
    for m in anthropic_conversation():
        if isinstance(m["content"], list):
            block = m["content"][0]
            text = block["content"] if isinstance(block["content"], str) else block["content"][0]["text"]
            msgs.append({"role": "tool", "tool_call_id": block["tool_use_id"], "content": text})
        else:
            msgs.append(m)
    return msgs


@pytest.fixture()
def client(project):
    import server

    with TestClient(server.app) as c:
        yield c


def _init(client, project) -> str:
    r = client.post("/v1/step/init", json={"project_root": str(project)})
    assert r.status_code == 200, r.text
    return r.json()["session_id"]


def _post(client, sid, api: str, msgs: list[dict], **extra_headers):
    headers = {"x-stepcheck-session": sid, "x-stepcheck-node": "billing", **extra_headers}
    if api == "anthropic":
        r = client.post("/v1/messages", json={"model": "claude-x", "max_tokens": 64, "system": "Be careful.", "messages": msgs}, headers=headers)
    else:
        r = client.post("/v1/chat/completions", json={"model": "gpt-x", "messages": msgs}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["stepcheck"]


def _text(message: dict) -> str:
    c = message["content"]
    if isinstance(c, str):
        return c
    parts = []
    for b in c:
        if isinstance(b.get("content"), str):
            parts.append(b["content"])
        elif isinstance(b.get("content"), list):
            parts.extend(x.get("text", "") for x in b["content"])
        elif isinstance(b.get("text"), str):
            parts.append(b["text"])
    return "\n".join(parts)


def _assert_log_elided(text: str, original: str, must_keep: list[str]) -> None:
    orig_lines = original.splitlines()
    out_lines = text.splitlines()
    assert out_lines[:15] == orig_lines[:15]                    # head kept
    assert out_lines[-20:] == orig_lines[-20:]                  # tail kept
    for needle in must_keep:
        assert any(needle in ln for ln in out_lines), needle    # failure lines kept
    elisions = [ln for ln in out_lines if "lines elided by StepCheck accordion" in ln]
    assert elisions, "no elision line"
    elided = sum(int(re.search(r"\[(\d+) lines elided", ln).group(1)) for ln in elisions)
    assert elided + len(out_lines) - len(elisions) == len(orig_lines)  # nothing lost, nothing invented


def _assert_compacted(fw: dict, msgs: list[dict], api: str) -> None:
    convo = [m for m in msgs if m["role"] != "system"]
    sent = [m for m in fw["sent_messages"] if m["role"] != "system"]
    assert sent[-4:] == convo[-4:]  # recent band byte-identical (messages 12-15)
    middle = sent[:-4]
    assert len(middle) == 11, [m["role"] for m in middle]

    py_msg, ts_msg, log_msg, diff_msg = middle[2], middle[4], middle[6], middle[8]
    if api == "anthropic":
        for m, tid in zip((py_msg, ts_msg, log_msg, diff_msg), TOOL_IDS):
            [block] = m["content"]
            assert block["type"] == "tool_result" and block["tool_use_id"] == tid  # structure kept
        assert isinstance(ts_msg["content"][0]["content"], list)  # nested text blocks kept as blocks
    else:
        for m, tid in zip((py_msg, ts_msg, log_msg, diff_msg), TOOL_IDS):
            assert m["role"] == "tool" and m["tool_call_id"] == tid

    py_sk = _text(py_msg)
    ast.parse(py_sk)  # a valid module: line numbers stripped, bodies elided
    assert "def audit_session(" in py_sk and "def html_receipt(" in py_sk
    assert "→" not in py_sk and "line = line.strip()" not in py_sk and len(py_sk) < len(AUDIT_SRC) / 2

    ts_sk = _text(ts_msg)
    assert "\t" not in ts_sk.replace("frontend/src/graph.ts", "")
    for sig in ("function statusColour(status: string): string", "function fetchGraph(base: string, sessionId: string)",
                "interface SessionView", "class VerdictFeed", "const useGraph"):
        assert sig in ts_sk, sig
    assert "{ ... }" in ts_sk and "return status === \"VERIFIED\"" not in ts_sk and "this.items = [v, ...this.items]" not in ts_sk
    assert len(ts_sk) < len(TS_SRC) / 2

    _assert_log_elided(_text(log_msg), _pytest_log(), ["FAILED", "AssertionError", "Traceback (most recent call last)"])
    _assert_log_elided(_text(diff_msg), _git_diff(), [])

    comp = fw["compaction"]
    assert comp["pruned_messages"] == 0 and comp["cache_cliff"] is False
    assert comp["blocks_skeletonized"] == 2 and comp["logs_elided"] == 2
    assert comp["languages"] == {"python": 1, "typescript": 1}
    assert comp["line_prefixes_stripped"] == len(AUDIT_SRC.splitlines()) + len(TS_SRC.splitlines())
    bands = comp["bands"]
    assert comp["tokens_after"] == bands["recent"]["tokens_after"] + bands["middle"]["tokens_after"]
    assert comp["tokens_before"] == bands["recent"]["tokens_before"] + bands["middle"]["tokens_before"] + bands["pruned"]["tokens_before"]
    assert bands["middle"]["tokens_after"] < bands["middle"]["tokens_before"]
    assert comp["saved_pct"] >= 60, comp
    assert fw["commit"]["accepted"] is True  # the final step still lands through the gates


def test_anthropic_tool_results_are_skeletonized_and_logs_elided(client, project):
    sid = _init(client, project)
    msgs = anthropic_conversation()
    fw = _post(client, sid, "anthropic", msgs)
    _assert_compacted(fw, msgs, "anthropic")
    assert fw["raw_tokens"] > fw["sent_tokens"]
    assert fw["raw_tokens"] > 20_000  # the tool_result text is counted (was invisible to the old reader)


def test_openai_tool_messages_are_compacted_the_same_way(client, project):
    sid = _init(client, project)
    msgs = openai_conversation()
    fw = _post(client, sid, "openai", msgs)
    _assert_compacted(fw, msgs, "openai")
    assert fw["sent_messages"][0] == {"role": "system", "content": "You are a careful coding agent."}


def test_a_tool_result_in_the_recent_band_is_never_touched(client, project):
    sid = _init(client, project)
    msgs = anthropic_conversation()
    # Move the pytest log into the recent band: it must come back verbatim there.
    msgs[-2] = {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_recent", "content": _pytest_log()}]}
    msgs[-1] = {"role": "assistant", "content": "Applying:\n" + _step(KEEP_CHARGE)}
    fw = _post(client, sid, "anthropic", msgs)
    sent = [m for m in fw["sent_messages"] if m["role"] != "system"]
    assert sent[-4:] == msgs[-4:]
    assert sent[-2]["content"][0]["content"] == _pytest_log()  # verbatim in the recent band
    assert fw["compaction"]["logs_elided"] == 2  # the two older logs (messages 7 and 9), not the recent copy
    assert "lines elided by StepCheck accordion" in _text(sent[6])  # the middle-band copy of the same log was


def test_fenced_and_tab_numbered_reads_inside_tool_results(client, project):
    sid = _init(client, project)
    msgs = anthropic_conversation()
    msgs[2] = {"role": "user", "content": [{"type": "tool_result", "tool_use_id": TOOL_IDS[0],
                                             "content": f"Result of Read backend/audit.py:\n```\n{_numbered(AUDIT_SRC, chr(9))}\n```"}]}
    fw = _post(client, sid, "anthropic", msgs)
    sent = [m for m in fw["sent_messages"] if m["role"] != "system"]
    [fence] = re.findall(r"```\n(.*?)```", sent[2]["content"][0]["content"], re.S)
    ast.parse(fence)
    assert "def audit_session(" in fence and "\t" not in fence and "line = line.strip()" not in fence
    assert fw["compaction"]["languages"]["python"] == 1


def test_compaction_report_counts_tool_result_tokens_and_runs_fast(client, project):
    sid = _init(client, project)
    msgs = anthropic_conversation()
    elapsed = []
    for _ in range(20):
        fw = _post(client, sid, "anthropic", msgs)
        elapsed.append(fw["compaction"]["elapsed_ms"])
    p95 = sorted(elapsed)[int(round(0.95 * (len(elapsed) - 1)))]
    assert p95 < 50, elapsed
    assert fw["compaction"]["tokens_before"] >= 20_000  # the four tool outputs dominate the conversation


def test_unknown_language_tool_output_is_kept_until_its_skeletonizer_lands(client, project):
    sid = _init(client, project)
    msgs = anthropic_conversation()
    go_src = "package main\n\nimport \"fmt\"\n\n" + "\n".join(
        f"func handler{i}(w http.ResponseWriter, r *http.Request) {{\n\tfmt.Fprintf(w, \"ok {i}\")\n}}\n" for i in range(40))
    msgs[2] = {"role": "user", "content": [{"type": "tool_result", "tool_use_id": TOOL_IDS[0], "content": _numbered(go_src)}]}
    fw = _post(client, sid, "anthropic", msgs)
    sent = [m for m in fw["sent_messages"] if m["role"] != "system"]
    assert sent[2]["content"][0]["content"] == _numbered(go_src)  # intact: no Go skeletonizer registered yet
    assert fw["compaction"]["languages"].get("go") == 1 and fw["compaction"]["blocks_skeletonized"] == 1
