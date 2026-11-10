"""Ed25519 provenance: in-toto Statement v1 receipts inside DSSE envelopes.

The local CLI's per-commit envelope carries a SHA-256 digest under a fixed key id, which
anyone can recompute. The cloud service signs instead: the DSSE pre-authentication
encoding of the statement is signed with an Ed25519 private key that only the service
holds, and anyone can verify a receipt against the public key the service publishes at
`/.well-known/stepcheck-pubkey.pem`.

DSSE v1
  PAE(type, body) = "DSSEv1" SP len(type) SP type SP len(body) SP body
  envelope        = {"payloadType", "payload": base64(body), "signatures": [{"keyid", "sig": base64(sig)}]}
The key id is the SHA-256 of the public key's DER SubjectPublicKeyInfo.
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://stepcheck.dev/attestation/v1"


class InvalidEnvelope(ValueError):
    """The envelope is malformed or no signature on it verifies."""


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding: what is actually signed."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def statement(subjects: list[dict], predicate: dict) -> dict:
    """An in-toto Statement v1 with StepCheck's predicate type."""
    if not subjects:
        raise ValueError("an in-toto statement needs at least one subject")
    return {"_type": STATEMENT_TYPE, "subject": subjects, "predicateType": PREDICATE_TYPE, "predicate": predicate}


def _keyid(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey, *, ephemeral: bool = False) -> None:
        self._key = private_key
        self.ephemeral = ephemeral
        self.keyid = _keyid(private_key.public_key())

    @classmethod
    def from_pem(cls, pem: str | None) -> "Signer":
        """The signer for a PKCS#8 PEM Ed25519 private key; without one, a key generated
        for this process only (development and tests: its receipts stop verifying when
        the process ends)."""
        if not pem:
            return cls(Ed25519PrivateKey.generate(), ephemeral=True)
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("STEPCHECK_SIGNING_KEY_PEM must hold an Ed25519 private key")
        return cls(key)

    def public_pem(self) -> str:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

    def sign(self, statement_doc: dict) -> dict:
        """The DSSE envelope over a statement, signed with this key."""
        payload = json.dumps(statement_doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        signature = self._key.sign(pae(PAYLOAD_TYPE, payload))
        return {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [{"keyid": self.keyid, "sig": base64.b64encode(signature).decode("ascii")}],
        }


def receipt_id(envelope: dict) -> str:
    """A receipt's id: the first 32 hex characters of the SHA-256 of its payload."""
    return hashlib.sha256(base64.b64decode(envelope["payload"])).hexdigest()[:32]


def verify_envelope(envelope: dict, public_key_pem: str) -> dict:
    """The statement inside an envelope, once a signature on it verifies against the
    public key; `InvalidEnvelope` otherwise."""
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            raise InvalidEnvelope("the public key is not Ed25519")
        if envelope.get("payloadType") != PAYLOAD_TYPE:
            raise InvalidEnvelope(f"unexpected payloadType {envelope.get('payloadType')!r}")
        payload = base64.b64decode(envelope["payload"], validate=True)
        signatures = envelope["signatures"]
    except InvalidEnvelope:
        raise
    except Exception as exc:  # noqa: BLE001 - any malformed field is the same verdict
        raise InvalidEnvelope(f"malformed envelope: {exc}") from exc
    message = pae(PAYLOAD_TYPE, payload)
    for entry in signatures:
        try:
            key.verify(base64.b64decode(entry["sig"], validate=True), message)
        except (InvalidSignature, KeyError, TypeError, ValueError):
            continue
        return json.loads(payload)
    raise InvalidEnvelope("no signature on the envelope verifies against this key")
