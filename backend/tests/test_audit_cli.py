"""`stepcheck audit` — CLI boundary against the bundled sample transcript (no mocks)."""
import re
from pathlib import Path

import cli

FIXTURE = Path(__file__).resolve().parents[2] / "benchmarks" / "fixtures" / "sample_session.jsonl"


def test_audit_sample_session_numbers_and_receipt(tmp_path, capsys):
    out = tmp_path / "receipt.html"
    rc = cli.main(["audit", str(FIXTURE), "--out", str(out), "--json", str(tmp_path / "r.json")])
    assert rc == 0
    text = capsys.readouterr().out

    import json

    r = json.load(open(tmp_path / "r.json", encoding="utf-8"))["total"]
    # The fixture pauses twice for >5 min (T6, T11): both re-write the prefix at full rate.
    assert r["cache_gap_turns"] == 2
    assert r["gap_rebilled_tokens"] == 18900 + 21300
    # Three full-file Reads of payments.py vs the same file as skeletons.
    assert r["read_calls"] == 3 and r["skeleton_exact"] is True
    assert r["skeleton_tokens"] < 0.35 * r["read_tokens"]
    # One dropped decorator (@audit, 2 retries) and one dropped guard (1 retry).
    assert r["regressions"] == 2 and r["retry_turns"] == 3 and r["failing_results"] >= 2
    assert "dropped decorator @audit" in text and "dropped guard" in text

    html = out.read_text(encoding="utf-8")
    assert "StepCheck audit receipt" in html and "@audit" in html and "if …: raise ValueError" in html
    assert "<script" not in html, "receipt must be a static, self-contained page"


def test_audit_falls_back_to_sample_when_no_logs(tmp_path, capsys):
    empty = tmp_path / "nologs"
    empty.mkdir()
    rc = cli.main(["audit", str(empty), "--out", str(tmp_path / "x.html")])
    assert rc == 0
    assert "bundled sample session" in capsys.readouterr().out


def test_receipt_never_leaks_the_home_directory(tmp_path, monkeypatch, capsys):
    logs = tmp_path / ".claude" / "projects" / "demo"
    logs.mkdir(parents=True)
    (logs / "session.jsonl").write_bytes(FIXTURE.read_bytes())
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    out = tmp_path / "receipt.html"

    assert cli.main(["audit", "--out", str(out)]) == 0

    html = out.read_bytes().decode("utf-8")  # strict: a cp1252 receipt fails here
    terminal = capsys.readouterr().out
    assert "under ~/.claude/projects" in html and "under ~/.claude/projects" in terminal
    for text in (html, terminal):
        assert str(tmp_path) not in text and tmp_path.as_posix() not in text
    assert " · " in html


def test_receipt_never_prints_an_absolute_path_for_an_explicit_target(tmp_path, monkeypatch, capsys):
    """Regression: an explicit log directory outside both the home directory and the
    working directory was printed raw (drive letter, absolute local path) in the page
    subtitle and the terminal. It is shown abbreviated to its last two components."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    logs = tmp_path / "elsewhere" / "transcripts"
    logs.mkdir(parents=True)
    (logs / "session.jsonl").write_bytes(FIXTURE.read_bytes())
    out = tmp_path / "receipt.html"

    assert cli.main(["audit", str(logs), "--out", str(out)]) == 0

    html = out.read_text(encoding="utf-8")
    terminal = capsys.readouterr().out
    for text in (html, terminal):
        assert str(tmp_path) not in text and tmp_path.as_posix() not in text
        assert re.search(r"(?<![A-Za-z])[A-Za-z]:[\\/]|/tmp/|/home/|/Users/", text) is None
        assert "under …/elsewhere/transcripts" in text
