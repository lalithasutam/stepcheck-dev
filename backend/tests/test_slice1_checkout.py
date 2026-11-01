"""Slice 1 — OKF graph compilation & bounded stateless checkout (Seam 1)."""
import yaml


def _frontmatter(frame_path):
    text = frame_path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), "frame must open with strict YAML frontmatter"
    fm = text.split("---\n")[1]
    return yaml.safe_load(fm), text


def test_indexing_builds_linked_okf_graph(kernel, project):
    sid = kernel.init_session(project)
    assert sid

    okf = project / ".stepcheck" / "okf"
    assert (okf / "index.md").exists(), "project index.md frame missing"

    meta, _ = _frontmatter(okf / "billing.md")
    assert meta["node_id"] == "billing"
    assert meta["path"] == "billing.py"
    assert meta["deps"] == ["auth"]
    assert meta["status"] == "ACTIVE"
    assert "charge(user: str, amount_cents: int) -> dict" in meta["exports"]
    assert "refund(user: str, amount_cents: int) -> dict" in meta["exports"]

    index_text = (okf / "index.md").read_text(encoding="utf-8")
    for node in ("auth", "billing", "reports", "unrelated_sibling"):
        assert node in index_text
    assert "billing -> auth" in index_text, "index must list dependency edges"


def test_checkout_is_bounded_and_excludes_siblings(kernel, project):
    sid = kernel.init_session(project)
    payload = kernel.checkout(sid, "billing")

    assert payload.node_id == "billing"
    rendered = payload.rendered()

    # Target frame travels whole.
    assert "def charge" in payload.frame_markdown
    assert "def refund" in payload.frame_markdown

    # Immediate dependency travels as verified signatures only, never full source.
    assert payload.dependency_signatures == {
        "auth": [
            "require_auth(fn)",
            "hash_token(token: str) -> str",
            "check_permission(user: str, action: str) -> bool",
        ]
    }
    assert "hashlib.sha256" not in rendered, "dependency source must not leak"

    # Locked invariants that constrain the edit ride along.
    assert any("amount_cents <= 0" in inv for inv in payload.locked_invariants)

    # Unrelated sibling files are excluded outright.
    assert "UNRELATED_SIBLING_MARKER" not in rendered

    # Hard token budget.
    assert 0 < payload.token_count < 4000
