"""Slice 17 — ContextCompactor: import-scoped dependency slicing, two-tier focus
elision, and the hard checkout-token backstop (Seam 1).

The paper-eval receipts showed full payloads larger than the raw files, 125 of
387 unfocused payloads over the budget and `focus=["Class.method"]` saving
little, because every dependency's whole interface (docstrings included) and
every unfocused sibling class rode along. Every assertion here is at Seam 1 on
real fixtures written to disk."""
import shutil
import textwrap
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".stepcheck")
BUDGET = 4000


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).write_text(textwrap.dedent(text), encoding="utf-8", newline="\n")
    return root


def _body(payload) -> str:
    return payload.frame_markdown.split("```python\n", 1)[1].rsplit("```", 1)[0]


def _first_touch(kernel, sid, node, focus):
    before = kernel.get_telemetry(sid)
    payload = kernel.checkout(sid, node, focus=focus)
    after = kernel.get_telemetry(sid)
    return payload, after.raw_bloated_tokens - before.raw_bloated_tokens


# ----------------------------------------- 1. import-scoped dependency slicing

HELPERS = '''\
    """Helpers for the main module."""
    import functools


    def deco(fn):
        return fn


    @deco
    def used(x: int = 1, *, scale: float = 2.0) -> int:
        """Scale x.

        A second paragraph that a dependency interface never needs to carry,
        because the signature already says everything the caller must know.
        """
        return int(x * scale)


    def unused(y: str) -> str:
        """Never imported by main."""
        return y


    def other(z: list) -> list:
        """Reached through the module object: helpers.other(...)."""
        return z


    class Widget:
        """A widget.

        Second paragraph."""

        def __init__(self, size: int) -> None:
            """Build it."""
            self.size = size

        def area(self) -> int:
            """Square it."""
            return self.size ** 2


    class Gadget:
        def spin(self) -> None:
            pass
'''

MAIN = '''\
    from helpers import used, Widget
    import helpers

    DEFAULT = used(2)


    def a(n: int) -> int:
        return used(n) + helpers.other([n])[0]


    def b(size: int) -> Widget:
        return Widget(size)
'''


def test_dependency_skeleton_is_scoped_to_what_the_module_imports(kernel, tmp_path):
    _write(tmp_path, {"helpers.py": HELPERS, "main.py": MAIN})
    sid = kernel.init_session(tmp_path)
    dep = kernel.checkout(sid, "main", focus=[]).dependency_skeletons["helpers"]

    # decorator, annotations, defaults and return type survive (canonical `ast.unparse` spacing)
    assert "@deco\ndef used(x: int=1, *, scale: float=2.0) -> int:" in dep
    assert "class Widget:" in dep and "def area(self) -> int:" in dep and "def __init__(self, size: int) -> None:" in dep
    assert "def other(z: list) -> list:" in dep  # helpers.other(...) attribute reference
    assert "def unused" not in dep and "class Gadget" not in dep and "def deco" not in dep
    assert "# + 3 unimported symbols elided from helpers" in dep
    for docstring in ("Scale x.", "second paragraph", "A widget.", "Build it.", "Square it."):
        assert docstring not in dep  # dependency interfaces carry no docstrings


def test_focus_scopes_dependency_symbols_to_what_the_focused_symbol_or_header_uses(kernel, tmp_path):
    _write(tmp_path, {"helpers.py": HELPERS, "main.py": MAIN})
    sid = kernel.init_session(tmp_path)

    dep_a = kernel.checkout(sid, "main", focus=["a"]).dependency_skeletons["helpers"]
    assert "def used(" in dep_a and "def other(" in dep_a  # referenced by a()
    assert "class Widget" not in dep_a  # only b() uses Widget
    assert "# + 4 unimported symbols elided from helpers" in dep_a

    dep_b = kernel.checkout(sid, "main", focus=["b"]).dependency_skeletons["helpers"]
    assert "class Widget:" in dep_b and "def other(" not in dep_b
    assert "def used(" in dep_b  # the module header (`DEFAULT = used(2)`) references it
    assert "# + 4 unimported symbols elided from helpers" in dep_b


# -------------------------------------------------- 2. two-tier focus elision

SHAPES = '''\
    """Shapes."""


    class Base:
        """Base of everything.

        Second paragraph of the base docstring."""

        def ident(self) -> int:
            """Identity.

            Long explanation."""
            return 0


    class Target(Base):
        """Target class.

        More words about the target."""

        def __init__(self, w: int, h: int) -> None:
            """Store the sides.

            Details."""
            self.w, self.h = w, h

        def area(self) -> int:
            """Area.

            Multiplies the sides."""
            return self.w * self.h

        def perimeter(self) -> int:
            """Perimeter.

            Adds the sides twice."""
            return 2 * (self.w + self.h)

        def scaled(self, k: int) -> "Target":
            """Scaled copy."""
            return Target(self.w * k, self.h * k)


    class Sibling(Base):
        """Unrelated sibling.

        Never used by the focused method."""

        def noise(self, x: int) -> int:
            """Noise."""
            return x


    def helper(v: int) -> int:
        """Helper.

        Second paragraph of the helper docstring."""
        return v
'''


def test_unfocused_frame_keeps_every_public_name_with_first_line_docstrings(kernel, tmp_path):
    _write(tmp_path, {"shapes.py": SHAPES})
    sid = kernel.init_session(tmp_path)
    body = _body(kernel.checkout(sid, "shapes", focus=[]))

    for sig in ("class Base:", "class Target(Base):", "class Sibling(Base):", "def helper(v: int) -> int:",
                "def area(self) -> int:", "def noise(self, x: int) -> int:"):
        assert sig in body
    assert '"""Target class."""' in body and '"""Helper."""' in body and '"""Area."""' in body
    for second in ("More words about the target", "Second paragraph", "Multiplies the sides", "Long explanation"):
        assert second not in body


def test_dotted_focus_emits_the_method_keeps_init_and_stubs_unreferenced_siblings(kernel, tmp_path):
    _write(tmp_path, {"shapes.py": SHAPES})
    sid = kernel.init_session(tmp_path)
    body = _body(kernel.checkout(sid, "shapes", focus=["Target.area"]))

    assert "        return self.w * self.h\n" in body  # focused method verbatim
    assert "Multiplies the sides" in body  # the focused method's own docstring stays intact
    assert "def __init__(self, w: int, h: int) -> None:" in body and "def perimeter(self) -> int:" in body
    assert "Store the sides" not in body and "Adds the sides twice" not in body  # sibling docstrings stripped
    assert "class Sibling(Base): ...\n" in body and "def noise" not in body  # unreferenced sibling: one-line stub
    assert "class Base:" in body and "def ident(self) -> int:" in body  # Target(Base) references Base
    assert "def helper(v: int) -> int:" in body and "return v" not in body


def test_focused_function_stubs_unreferenced_classes_but_keeps_referenced_ones(kernel, tmp_path):
    _write(tmp_path, {"shapes.py": SHAPES + "\n\n    def make(k: int) -> Target:\n        return Target(k, k)\n"})
    sid = kernel.init_session(tmp_path)
    body = _body(kernel.checkout(sid, "shapes", focus=["make"]))
    assert "    return Target(k, k)\n" in body
    assert "class Target(Base):\n" in body and "def area(self) -> int:" in body  # referenced: signatures kept
    assert "class Sibling(Base): ...\n" in body
    assert "class Base: ...\n" in body  # make() never touches Base directly


# ------------------------------------------------- 3. hard 4,000-token backstop


def _overflowing_project(root: Path, *, methods: int, dep_functions: int) -> None:
    deps = []
    for d in range(3):
        funcs = "\n\n".join(f"def f{d}_{i}(x: int, y: int = {i}) -> int:\n    return x + y\n" for i in range(dep_functions))
        (root / f"dep{d}.py").write_text(funcs + "\n", encoding="utf-8", newline="\n")
        deps.append(f"from dep{d} import " + ", ".join(f"f{d}_{i}" for i in range(dep_functions)))
    siblings = "\n\n".join(
        f"    def m{i}(self, a: int, b: int = {i}) -> int:\n        return a + b\n" for i in range(methods)
    )
    (root / "big.py").write_text(
        "\n".join(deps) + "\n\n\nclass Big:\n    def __init__(self) -> None:\n        self.n = 0\n\n"
        "    def run(self, v: int) -> int:\n        return f0_0(v, self.n)\n\n" + siblings + "\n",
        encoding="utf-8", newline="\n",
    )


def test_backstop_brings_a_focused_payload_under_budget_without_touching_the_focus(kernel, tmp_path):
    _overflowing_project(tmp_path, methods=400, dep_functions=120)
    sid = kernel.init_session(tmp_path)
    payload = kernel.checkout(sid, "big", focus=["Big.run"])

    assert payload.token_count < BUDGET and not payload.auto_skeletonized
    assert payload.elided, "the backstop must say what it dropped"
    body = _body(payload)
    assert "    def run(self, v: int) -> int:\n        return f0_0(v, self.n)\n" in body  # never truncated
    assert "def __init__(self) -> None:" in body
    assert "# + " in body and "method signatures elided" in body
    assert "Budget backstop" in payload.frame_markdown
    assert "def f0_0(x: int, y: int=0) -> int:" in payload.dependency_skeletons["dep0"]  # the dependency the focus uses
    assert payload.dependency_skeletons["dep1"].strip() == "# + 120 unimported symbols elided from dep1"


def test_backstop_on_an_unfocused_frame_never_drops_a_public_name(kernel, tmp_path):
    _overflowing_project(tmp_path, methods=400, dep_functions=120)
    extra = "\n\n".join(f"def api_{i}(x: int) -> int:\n    return x\n" for i in range(10))
    big = (tmp_path / "big.py").read_text(encoding="utf-8")
    (tmp_path / "big.py").write_text(big + "\n\n" + extra + "\n", encoding="utf-8", newline="\n")
    sid = kernel.init_session(tmp_path)
    payload = kernel.checkout(sid, "big", focus=[])

    assert payload.token_count < BUDGET and not payload.auto_skeletonized and payload.elided
    body = _body(payload)
    assert "class Big:" in body and all(f"def api_{i}(x: int) -> int:" in body for i in range(10))
    assert "def __init__(self) -> None:" in body
    assert "method signatures elided" in body


def test_small_payloads_are_not_touched_by_the_backstop(kernel, project):
    sid = kernel.init_session(project)
    payload = kernel.checkout(sid, "billing", focus=["charge"])
    assert payload.elided == [] and "Budget backstop" not in payload.frame_markdown
    assert "def require_auth(fn):" in payload.dependency_skeletons["auth"]
    assert "def hash_token" not in payload.dependency_skeletons["auth"]  # billing never imports it
    assert "# + 1 unimported symbols elided from auth" in payload.dependency_skeletons["auth"]


# --------------------------------------------- 4. self-hosted on backend/

# Measured 2026-11-03 on the unpatched kernel (temp copy of backend/, first checkout
# in a fresh session): focus=["StateKernel"] payload 7,627 tokens, focus=["StateKernel.commit"]
# 4,848, server focus=["_build_mcp"] 3,629 tokens against a 5,030-token raw read (27.9%).
PRE_SLICE_WHOLE_CLASS_TOKENS = 7627


@pytest.fixture()
def own_backend(tmp_path) -> Path:
    root = tmp_path / "backend"
    shutil.copytree(BACKEND, root, ignore=IGNORE)
    return root


def test_server_focused_checkout_saves_at_least_45_percent_of_the_raw_read(kernel, own_backend):
    sid = kernel.init_session(own_backend)
    payload, raw = _first_touch(kernel, sid, "server", ["_build_mcp"])
    saved = 100 * (raw - payload.token_count) / raw
    assert "def _build_mcp(" in payload.rendered() and not payload.auto_skeletonized
    assert saved >= 45, (saved, payload.token_count, raw)


def test_method_focus_on_statekernel_is_half_the_pre_slice_class_focus(kernel, own_backend):
    sid = kernel.init_session(own_backend)
    whole = kernel.checkout(sid, "kernel.__init__", focus=["StateKernel"]).token_count
    method = kernel.checkout(sid, "kernel.__init__", focus=["StateKernel.commit"])
    assert "def commit(" in _body(method) and "Gates A" in _body(method)  # the method body itself
    assert method.token_count <= 0.5 * PRE_SLICE_WHOLE_CLASS_TOKENS, method.token_count
    assert method.token_count <= 0.5 * whole, (method.token_count, whole)
    assert method.token_count < BUDGET
