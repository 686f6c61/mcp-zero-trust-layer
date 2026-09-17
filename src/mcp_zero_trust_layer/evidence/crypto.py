from __future__ import annotations

import base64
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from mcp_zero_trust_layer.evidence.canonical import DOMAIN, canonical
from mcp_zero_trust_layer.evidence.models import Protected, Signed, TrustKey, TrustStore


def encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode(data: str) -> bytes:
    result = base64.b64decode(data + "=" * (-len(data) % 4), altchars=b"-_", validate=True)
    if encode(result) != data:
        raise ValueError("noncanonical base64url")
    return result


def signing_bytes(protected: Protected, payload: dict[str, Any]) -> bytes:
    return DOMAIN + b"signature:" + canonical({
        "protected": protected.model_dump(), "payload": payload,
    })


def sign(payload: dict[str, Any], kind: Literal["authorization", "attempt", "receipt"],
         kid: str, private_key: Ed25519PrivateKey) -> Signed:
    header = Protected(version=1, alg="Ed25519", kind=kind, kid=kid)
    return Signed(protected=header, payload=payload,
                  signature=encode(private_key.sign(signing_bytes(header, payload))))


def verify_signature(document: Signed, trust: TrustStore, kind: str) -> TrustKey:
    if document.protected.kind != kind:
        raise ValueError("WRONG_DOCUMENT_KIND")
    key = next((k for k in trust.keys if k.kid == document.protected.kid), None)
    if key is None:
        raise ValueError("UNTRUSTED_KEY")
    if key.status == "revoked":
        raise ValueError("REVOKED_KEY")
    role = "destination" if kind == "receipt" else "gateway"
    if (key.role != role or key.issuer != document.payload.get("issuer") or
            key.audience != document.payload.get("audience") or
            key.tenant != document.payload.get("tenant")):
        raise ValueError("KEY_SCOPE_MISMATCH")
    try:
        Ed25519PublicKey.from_public_bytes(decode(key.public_key)).verify(
            decode(document.signature), signing_bytes(document.protected, document.payload))
    except InvalidSignature as exc:
        raise ValueError("INVALID_SIGNATURE") from exc
    return key
