"""Slice 13 — `append` lands before a trailing `if __name__ == "__main__":` guard,
cli.py carries nothing after its guard, README leads with the live CI badge and
audit receipt (Seam 1 + repo files)."""
import ast
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent

TOOL = '''\
"""A script with an entry-point guard."""
import sys


def main() -> int:
    print("x")
    return 0


# entry point: stays glued to the guard
if __name__ == "__main__":
    raise SystemExit(main())
# trailing note
'''

HELPER = "def helper() -> int:\n    return 7\n"
MAIN_USING_HELPER = "def main() -> int:\n    print(helper())\n    return 0\n"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def _is_main_guard(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.If) and "__main__" in ast.unparse(stmt.test)


def test_append_lands_before_a_trailing_main_guard_and_the_script_still_runs(kernel, tmp_path):
    target = tmp_path / "tool.py"
    _write(target, TOOL)
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(
        sid, "tool",
        patch=[
            {"op": "replace_symbol", "name": "main", "code": MAIN_USING_HELPER},
            {"op": "append", "code": HELPER},
        ],
    )

    assert v.accepted, v.error
    text = target.read_text(encoding="utf-8")
    body = ast.parse(text).body
    assert _is_main_guard(body[-1]), "the guard must stay the last statement"
    assert [s.name for s in body if isinstance(s, ast.FunctionDef)] == ["main", "helper"]
    # The guard's attached comment and the trailing note travel untouched.
    assert "\n\n\n# entry point: stays glued to the guard\nif __name__ == \"__main__\":\n" in text
    assert text.endswith("    raise SystemExit(main())\n# trailing note\n")
    assert "\n\n\n\n" not in text

    done = subprocess.run([sys.executable, str(target)], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "7"


def test_append_without_a_trailing_guard_still_goes_to_the_end(kernel, tmp_path):
    src = TOOL.replace('# entry point: stays glued to the guard\nif __name__ == "__main__":\n    raise SystemExit(main())\n# trailing note\n', "")
    middle_guard = 'if __name__ == "__main__":\n    pass\n\n\ndef last() -> int:\n    return 1\n'
    _write(tmp_path / "plain.py", src)
    _write(tmp_path / "mid.py", src + "\n\n" + middle_guard)
    sid = kernel.init_session(tmp_path)

    for nid in ("plain", "mid"):
        v = kernel.commit(sid, nid, patch=[{"op": "append", "code": HELPER}])
        assert v.accepted, v.error
        body = ast.parse((tmp_path / f"{nid}.py").read_text(encoding="utf-8")).body
        assert isinstance(body[-1], ast.FunctionDef) and body[-1].name == "helper"


def test_cli_module_ends_with_its_main_guard():
    text = (BACKEND / "cli.py").read_text(encoding="utf-8")
    body = ast.parse(text).body
    assert _is_main_guard(body[-1])
    tail = text[text.index('if __name__ == "__main__":'):]
    assert tail.strip().splitlines() == ['if __name__ == "__main__":', "    raise SystemExit(main())"]


def test_readme_leads_with_ci_badge_and_live_audit_receipt():
    head = "\n".join((REPO / "README.md").read_text(encoding="utf-8").splitlines()[:6])
    assert "https://github.com/lalithasutam/stepcheck-dev/actions/workflows/ci.yml/badge.svg" in head
    assert "https://lalithasutam.github.io/stepcheck-dev/audit.html" in head
