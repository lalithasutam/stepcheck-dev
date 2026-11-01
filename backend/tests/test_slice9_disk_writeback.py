"""Slice 9 — verified commits land on disk, byte-identical to their attestation (Seam 1 + 2)."""
import codecs
import hashlib
import textwrap

import pytest
from fastapi.testclient import TestClient

from kernel import MechanicalError

PAY_SRC = textwrap.dedent('''\
    def audit(fn):
        return fn


    @audit
    def charge(amount_cents: int, currency: str) -> dict:
        if amount_cents <= 0:
            raise ValueError("amount_cents must be positive")
        return {"amount_cents": amount_cents, "currency": currency}
    ''')


def _write(path, text):
    path.write_bytes(text.encode("utf-8"))


def _charge(signature: str, guard: str = "amount_cents <= 0") -> list[dict]:
    code = (
        f"@audit\ndef charge({signature}) -> dict:\n"
        f"    if {guard}:\n"
        f'        raise ValueError("amount_cents must be positive")\n'
        f'    return {{"amount_cents": amount_cents}}\n'
    )
    return [{"op": "replace_symbol", "name": "charge", "code": code}]


def _sha(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ------------------------------------------------------- disk write-back + SHA


def test_accepted_patch_lands_on_disk_and_hashes_to_attested_sha(kernel, tmp_path):
    target = tmp_path / "pay.py"
    _write(target, PAY_SRC)
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(sid, "pay", patch=_charge("amount_cents: int, currency: str"))

    assert v.accepted, v.error
    assert '"currency": currency' not in target.read_text(encoding="utf-8")
    assert _sha(target) == v.attestation["payload"]["sha256"]


def test_crlf_file_keeps_its_line_endings_and_still_matches_attestation(kernel, tmp_path):
    target = tmp_path / "pay.py"
    _write(target, PAY_SRC.replace("\n", "\r\n"))
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(sid, "pay", patch=_charge("amount_cents: int, currency: str"))

    assert v.accepted, v.error
    raw = target.read_bytes()
    assert raw.count(b"\n") == raw.count(b"\r\n"), "no line may lose its CR"
    assert hashlib.sha256(raw).hexdigest() == v.attestation["payload"]["sha256"]


def test_utf8_bom_survives_write_back(kernel, tmp_path):
    target = tmp_path / "pay.py"
    target.write_bytes(codecs.BOM_UTF8 + PAY_SRC.encode("utf-8"))
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(sid, "pay", patch=_charge("amount_cents: int, currency: str"))

    assert v.accepted, v.error
    assert target.read_bytes().startswith(codecs.BOM_UTF8)
    assert _sha(target) == v.attestation["payload"]["sha256"]


@pytest.mark.parametrize(
    "patch, gate",
    [
        ([{"op": "delete_symbol", "name": "charge"}], "B"),
        (_charge("amount_cents: int, currency: str", guard="amount_cents < 0"), "C"),
        ([{"op": "replace_symbol", "name": "nope", "code": "x = 1\n"}], "A"),
    ],
)
def test_rejected_commit_leaves_the_file_untouched(kernel, tmp_path, patch, gate):
    target = tmp_path / "pay.py"
    _write(target, PAY_SRC)
    before = target.read_bytes()
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(sid, "pay", patch=patch)

    assert not v.accepted and v.gate == gate
    assert target.read_bytes() == before


def test_locked_module_is_never_written(kernel, tmp_path):
    target = tmp_path / "pay.py"
    _write(target, PAY_SRC)
    before = target.read_bytes()
    sid = kernel.init_session(tmp_path)
    kernel.lock_node(sid, "pay")

    v = kernel.commit(sid, "pay", patch=_charge("amount_cents: int, currency: str"))

    assert not v.accepted and v.gate == "A"
    assert target.read_bytes() == before


def test_commit_refuses_to_clobber_a_file_edited_since_init(kernel, tmp_path):
    target = tmp_path / "pay.py"
    _write(target, PAY_SRC)
    sid = kernel.init_session(tmp_path)
    human_edit = PAY_SRC + "\n\nHUMAN_EDIT = 1\n"
    _write(target, human_edit)

    v = kernel.commit(sid, "pay", patch=_charge("amount_cents: int, currency: str"))

    assert not v.accepted and v.gate == "A"
    assert isinstance(v.error, MechanicalError)
    assert "changed on disk" in str(v.error)
    assert target.read_bytes().decode("utf-8") == human_edit


def test_consecutive_commits_do_not_trip_the_drift_check(kernel, tmp_path):
    target = tmp_path / "pay.py"
    _write(target, PAY_SRC)
    sid = kernel.init_session(tmp_path)

    first = kernel.commit(sid, "pay", patch=_charge("amount_cents: int, currency: str"))
    second = kernel.commit(sid, "pay", patch=[{"op": "append", "code": "LIMIT = 5\n"}])

    assert first.accepted and second.accepted, second.error
    assert _sha(target) == second.attestation["payload"]["sha256"]


def test_rest_commit_writes_through_the_gateway(tmp_path):
    import server

    target = tmp_path / "pay.py"
    _write(target, PAY_SRC)
    with TestClient(server.app) as client:
        sid = client.post("/v1/step/init", json={"project_root": str(tmp_path)}).json()["session_id"]
        out = client.post(
            "/v1/step/commit",
            json={
                "session_id": sid,
                "node_id": "pay",
                "patch": _charge("amount_cents: int, currency: str"),
            },
        ).json()

    assert out["accepted"], out
    assert _sha(target) == out["attestation"]["payload"]["sha256"]


# ----------------------------------------------------------- Windows UTF-8 safety


def test_non_ascii_source_round_trips_through_kernel_frames_and_disk(kernel, tmp_path):
    # U+201D encodes to e2 80 9d; 0x9d is undefined in cp1252, so a default
    # Windows read crashes. "—" and "→" would otherwise decode as mojibake.
    src = '"""Gateway — routes → “quoted”."""\n' + PAY_SRC
    target = tmp_path / "pay.py"
    _write(target, src)

    sid = kernel.init_session(tmp_path)

    frame = (tmp_path / ".stepcheck" / "okf" / "pay.md").read_text(encoding="utf-8")
    assert "Gateway — routes → “quoted”." in frame
    assert kernel.graph(sid)["nodes"][0]["source"] == src

    v = kernel.commit(sid, "pay", patch=[{"op": "append", "code": "LIMIT = '→'\n"}])
    assert v.accepted, v.error
    text = target.read_bytes().decode("utf-8")
    assert "Gateway — routes → “quoted”." in text and "LIMIT = '→'" in text


def test_undecodable_file_is_left_untracked_instead_of_killing_init(kernel, tmp_path):
    _write(tmp_path / "pay.py", PAY_SRC)
    (tmp_path / "legacy.py").write_bytes("# -*- coding: latin-1 -*-\nNAME = 'caf\xe9'\n".encode("latin-1"))

    sid = kernel.init_session(tmp_path)

    assert [n["node_id"] for n in kernel.graph(sid)["nodes"]] == ["pay"]


# ------------------------------------------- signature evolution in mined guards


def test_new_required_parameter_gets_typed_mock_for_mined_guard(kernel, tmp_path):
    target = tmp_path / "pay.py"
    _write(target, PAY_SRC)
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(
        sid, "pay", patch=_charge("amount_cents: int, currency: str, idempotency_key: str")
    )

    assert v.accepted, v.error
    assert "idempotency_key: str" in target.read_text(encoding="utf-8")
    # The mined guard re-mines against the new signature.
    mined = next(n for n in kernel.graph(sid)["nodes"] if n["node_id"] == "pay")[
        "invariants_auto_mined"
    ]
    assert 'call:charge(amount_cents=0, currency="x", idempotency_key="x") raises ValueError' in mined


@pytest.mark.parametrize(
    "signature",
    [
        "amount_cents: int, currency: str, retries: int",
        "amount_cents: int, currency: str, tags: list[str]",
        "amount_cents: int, currency: str, ctx",
        "amount_cents: int, currency: str, *, key: str",
        "tenant: str, /, amount_cents: int, currency: str",
    ],
)
def test_every_parameter_kind_is_filled_for_the_guard(kernel, tmp_path, signature):
    _write(tmp_path / "pay.py", PAY_SRC)
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(sid, "pay", patch=_charge(signature))

    assert v.accepted, v.error


def test_mock_filled_call_still_enforces_the_guard(kernel, tmp_path):
    target = tmp_path / "pay.py"
    _write(target, PAY_SRC)
    before = target.read_bytes()
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(
        sid,
        "pay",
        patch=_charge("amount_cents: int, currency: str, key: str", guard="amount_cents < 0"),
    )

    assert not v.accepted and v.gate == "C"
    assert "auto-mined" in str(v.error)
    assert target.read_bytes() == before


def test_hand_written_call_invariant_is_not_auto_filled(kernel, tmp_path):
    src = PAY_SRC.replace(
        "@audit\n",
        '# okf-invariant: call:charge(0, "usd") raises ValueError\n@audit\n',
    )
    _write(tmp_path / "pay.py", src)
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(sid, "pay", patch=_charge("amount_cents: int, currency: str, key: str"))

    assert not v.accepted and v.gate == "C"


# --------------------------------------------------------------- Gate C telemetry


def test_gate_c_rejection_counts_as_a_blocked_regression(kernel, tmp_path):
    _write(tmp_path / "pay.py", PAY_SRC)
    sid = kernel.init_session(tmp_path)

    v = kernel.commit(
        sid, "pay", patch=_charge("amount_cents: int, currency: str", guard="amount_cents < 0")
    )

    assert v.gate == "C"
    assert kernel.get_telemetry(sid).omissions_blocked == 1
