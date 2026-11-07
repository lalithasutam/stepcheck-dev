"""Slice 30 — wild-code blind spots from the external certification (Seam 1).

requests / flask / CanItEdit showed Gate C mining nothing (no method guards, no
external-type `isinstance`, no assert / early-return / except-raise), a lazily
imported function escaping dependency tracking, concise refactors tripping the
mass-deletion rule, and tiny modules paying more header than source.
"""
import yaml

from kernel import LogicalError, OmissionError

COOKIES = '''from http.cookiejar import CookieJar


def merge_cookies(cookiejar, cookies):
    """Add cookies to cookiejar."""
    if not isinstance(cookiejar, CookieJar):
        raise ValueError("You can only merge into CookieJar")
    return cookiejar


class Session:
    def __init__(self, timeout):
        self.timeout = timeout

    def send(self, request):
        """Send a request."""
        if request is None:
            return None
        assert self.timeout > 0, "timeout must be positive"
        prepared = str(request)
        if not prepared.startswith("http"):
            raise ValueError("unsupported scheme")
        try:
            return int(len(prepared) / self.timeout)
        except ZeroDivisionError as exc:
            raise RuntimeError("bad timeout") from exc

    def close(self):
        return self.timeout
'''


def _write(root, files):
    for rel, src in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src, encoding="utf-8")


def _node(kernel, sid, node_id):
    return next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == node_id)


def test_structural_guards_are_mined_from_methods_asserts_early_returns_and_handlers(kernel, tmp_path):
    _write(tmp_path, {"cookies.py": COOKIES})
    sid = kernel.init_session(tmp_path)
    mined = _node(kernel, sid, "cookies")["invariants_auto_mined"]
    assert "guard:merge_cookies:if not isinstance(cookiejar, CookieJar) raises ValueError" in mined
    assert "guard:Session.send:if request is None returns None" in mined
    assert "guard:Session.send:assert self.timeout > 0" in mined
    assert "guard:Session.send:if not prepared.startswith('http') raises ValueError" in mined
    assert "guard:Session.send:except ZeroDivisionError raises RuntimeError" in mined
    assert not any(m.startswith("guard:Session.close:") for m in mined)  # no guard, nothing invented


def test_each_structural_guard_is_enforced_at_gate_c_and_waived_by_a_declared_deletion(kernel, tmp_path):
    _write(tmp_path, {"cookies.py": COOKIES})
    sid = kernel.init_session(tmp_path)
    faults = {
        "external isinstance weakened": COOKIES.replace("if not isinstance(cookiejar, CookieJar):", "if cookiejar is None:"),
        "assert dropped": COOKIES.replace('        assert self.timeout > 0, "timeout must be positive"\n', ""),
        "early return dropped": COOKIES.replace("        if request is None:\n            return None\n", ""),
        "non-leading raise dropped": COOKIES.replace(
            '        if not prepared.startswith("http"):\n            raise ValueError("unsupported scheme")\n', ""),
        "handler stops raising": COOKIES.replace('raise RuntimeError("bad timeout") from exc', "return 0"),
    }
    for label, staged in faults.items():
        v = kernel.commit(sid, "cookies", source=staged)
        assert not v.accepted and v.gate == "C" and isinstance(v.error, LogicalError), label
        assert "guard:" in str(v.error), label
    declared = kernel.commit(sid, "cookies", source=faults["assert dropped"], allow_deletion=True)
    assert declared.accepted, declared.error


def test_guard_matching_ignores_messages_formatting_and_position(kernel, tmp_path):
    _write(tmp_path, {"cookies.py": COOKIES})
    sid = kernel.init_session(tmp_path)
    reworded = (COOKIES.replace('"You can only merge into CookieJar"', "'merge target must be a CookieJar'")
                .replace("if not prepared.startswith(\"http\"):", "if not (prepared.startswith('http')):")
                .replace('        prepared = str(request)\n', '        prepared = str(request)\n        prepared = prepared.strip()\n'))
    v = kernel.commit(sid, "cookies", source=reworded)
    assert v.accepted, v.error


NESTED = '''def attach_error(request):
    """flask.debughelpers shape: the guards live in a class defined in the function."""
    old = request.__class__

    class Patched(old):
        def __getitem__(self, key):
            try:
                return old.__getitem__(self, key)
            except KeyError as e:
                if key not in self:
                    raise
                raise LookupError(key) from e

    request.__class__ = Patched


def convert(value):
    try:
        import ssl
    except ImportError:
        raise RuntimeError("ssl missing") from None
    try:
        import hashlib
    except ImportError:
        raise RuntimeError("ssl missing") from None
    return value, ssl, hashlib
'''


def test_guards_in_nested_scopes_and_repeated_clauses_are_each_held(kernel, tmp_path):
    _write(tmp_path, {"helpers.py": NESTED})
    sid = kernel.init_session(tmp_path)
    mined = _node(kernel, sid, "helpers")["invariants_auto_mined"]
    assert "guard:attach_error.Patched.__getitem__:except KeyError raises LookupError" in mined
    assert "guard:convert:except ImportError raises RuntimeError" in mined
    assert "guard:convert:except ImportError raises RuntimeError #2" in mined

    nested = kernel.commit(sid, "helpers", source=NESTED.replace("raise LookupError(key) from e", "return None"))
    assert nested.gate == "C" and "Patched.__getitem__" in str(nested.error)
    one_copy = NESTED.replace(
        '    try:\n        import hashlib\n    except ImportError:\n        raise RuntimeError("ssl missing") from None\n',
        "    import hashlib\n")
    dup = kernel.commit(sid, "helpers", source=one_copy)
    assert dup.gate == "C" and "#2" in str(dup.error)


def test_focused_checkout_lists_the_focus_guards_and_counts_the_rest(kernel, tmp_path):
    _write(tmp_path, {"cookies.py": COOKIES + "\n\ndef pad():\n    return [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]\n"})
    sid = kernel.init_session(tmp_path)
    p = kernel.checkout(sid, "cookies", focus=["Session.send"])
    guards = [i for i in p.locked_invariants if i.startswith("guard:")]
    assert guards and all(g.startswith("guard:Session.send:") for g in guards)
    front = yaml.safe_load(p.frame_markdown.split("---\n")[1])
    assert front["guard_invariants"] == 5
    assert "## Locked invariants" in p.rendered() and "guard:Session.send:assert self.timeout > 0" in p.rendered()


def test_function_scoped_imports_are_dependencies(kernel, tmp_path):
    _write(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/helpers.py": "def attach_error(app, request):\n    return (app, request)\n",
        "pkg/app.py": (
            "def handle(app, request):\n"
            "    from .helpers import attach_error\n"
            "    return attach_error(app, request)\n"
        ),
    })
    sid = kernel.init_session(tmp_path)
    assert _node(kernel, sid, "app")["deps"] == ["helpers"]

    # The lazily imported name is a contract: dropping it is Gate A, changing its signature dirties app.
    gone = kernel.commit(sid, "helpers", source="def other():\n    return 1\n", allow_deletion=True)
    assert not gone.accepted and gone.gate == "A" and "attach_error" in str(gone.error)
    broke = kernel.commit(sid, "helpers", source="def attach_error(app, request, extra):\n    return (app, request, extra)\n")
    assert broke.accepted and broke.dirtied == ["app"]


BELLMAN = '''def distances(graph, start):
    """Shortest distances."""
    if start not in graph:
        raise KeyError(start)
    dist = {}
    for node in graph:
        dist[node] = float("inf")
    dist[start] = 0
    queue = [start]
    seen = set()
    while queue:
        node = queue.pop(0)
        if node in seen:
            continue
        seen.add(node)
        for nxt, w in graph[node].items():
            if dist[node] + w < dist[nxt]:
                dist[nxt] = dist[node] + w
            queue.append(nxt)
    return dist
'''

BELLMAN_CONCISE = '''def distances(graph, start):
    """Shortest distances."""
    if start not in graph:
        raise KeyError(start)
    dist = {node: float("inf") for node in graph}
    dist[start] = 0
    queue = [start]
    while queue:
        node = queue.pop(0)
        for nxt, w in graph[node].items():
            if dist[node] + w < dist[nxt]:
                dist[nxt] = dist[node] + w
                queue.append(nxt)
    return dist
'''


def test_concise_refactor_is_not_a_mass_deletion_but_dropped_bindings_still_are(kernel, tmp_path):
    _write(tmp_path, {"graph.py": BELLMAN + "\n\nLIMIT = 10\nRETRIES = 2\n\n\ndef _audit(x):\n    return x\n"})
    sid = kernel.init_session(tmp_path)
    source = (tmp_path / "graph.py").read_text(encoding="utf-8")
    concise = source.replace(BELLMAN, BELLMAN_CONCISE)
    v = kernel.commit(sid, "graph", source=concise)
    assert v.accepted, v.error

    lost = concise.replace("LIMIT = 10\nRETRIES = 2\n\n\ndef _audit(x):\n    return x\n", "")
    v = kernel.commit(sid, "graph", source=lost)
    assert not v.accepted and isinstance(v.error, OmissionError)
    assert v.error.subtype == "INTRA_NODE_MASS_DELETION" and "_audit" in str(v.error)

    # The refactor still cannot drop the guard: Gate C holds it.
    unguarded = concise.replace("    if start not in graph:\n        raise KeyError(start)\n", "")
    assert kernel.commit(sid, "graph", source=unguarded).gate == "C"


def test_tiny_module_focus_gets_a_compact_header(kernel, tmp_path):
    src = "def add(a, b):\n    if a is None:\n        raise ValueError('a')\n    return a + b\n"
    _write(tmp_path, {"tiny.py": src})
    sid = kernel.init_session(tmp_path)
    p = kernel.checkout(sid, "tiny", focus=["add"])
    front = yaml.safe_load(p.frame_markdown.split("---\n")[1])
    assert set(front) <= {"node_id", "path", "status", "locked", "deps", "attestation"}
    assert src in p.frame_markdown and "compact header" in p.frame_markdown
    full = kernel.checkout(sid, "tiny")  # the unfocused frame keeps the full header
    assert p.token_count < full.token_count
    assert "guard:add:if a is None raises ValueError" in p.locked_invariants or any(
        i.startswith("call:add(") for i in p.locked_invariants)
