"""Concrete fixture project used by every Seam 1 test.

No mocks anywhere: tests drive the real StateKernel against a real on-disk
multi-file Python project (GLOSSARY.md, "Testing rules").
"""
import sys
import textwrap
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


AUTH_SRC = textwrap.dedent('''\
    import hashlib


    def require_auth(fn):
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        return wrapper


    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()


    def check_permission(user: str, action: str) -> bool:
        if not user:
            return False
        return action != "forbidden"
    ''')

BILLING_SRC = textwrap.dedent('''\
    from auth import require_auth, check_permission

    _FEES = {"standard": 30, "intl": 50}


    def _audit(user: str, action: str) -> None:
        entry = {"user": user, "action": action}
        entry["ok"] = True
        print(entry)


    @require_auth
    def charge(user: str, amount_cents: int) -> dict:
        # okf-invariant: "amount_cents <= 0" in src and "raise ValueError" in src
        if amount_cents <= 0:
            raise ValueError("amount must be positive")
        if not check_permission(user, "charge"):
            raise PermissionError(user)
        return {"user": user, "amount_cents": amount_cents, "status": "charged"}


    def refund(user: str, amount_cents: int) -> dict:
        return {"user": user, "amount_cents": -amount_cents, "status": "refunded"}
    ''')

ADMIN_SRC = textwrap.dedent('''\
    from auth import check_permission, hash_token


    def admin_panel(user: str) -> str:
        if not check_permission(user, "admin"):
            raise PermissionError(user)
        return hash_token(user)
    ''')

REPORTS_SRC = textwrap.dedent('''\
    from billing import charge


    def monthly_report(user: str) -> list:
        return [charge(user, 100)]
    ''')

SIBLING_SRC = (
    '"""UNRELATED_SIBLING_MARKER — must never leak into a checkout payload."""\n'
    + "\n".join(f'FILLER_{i} = "{"x" * 60}"' for i in range(120))
    + "\n"
)


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    (tmp_path / "auth.py").write_text(AUTH_SRC, encoding="utf-8", newline="\n")
    (tmp_path / "admin.py").write_text(ADMIN_SRC, encoding="utf-8", newline="\n")
    (tmp_path / "billing.py").write_text(BILLING_SRC, encoding="utf-8", newline="\n")
    (tmp_path / "reports.py").write_text(REPORTS_SRC, encoding="utf-8", newline="\n")
    (tmp_path / "unrelated_sibling.py").write_text(SIBLING_SRC, encoding="utf-8", newline="\n")
    return tmp_path


@pytest.fixture()
def kernel():
    from kernel import StateKernel

    return StateKernel()
