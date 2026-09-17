from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_zero_trust_layer.config.models import EvidenceConfig
from mcp_zero_trust_layer.core.context import RequestContext
from mcp_zero_trust_layer.evidence.canonical import canonical, digest, loads
from mcp_zero_trust_layer.evidence.crypto import decode, encode, sign
from mcp_zero_trust_layer.evidence.models import (
    Attempt,
    Authorization,
    Bundle,
    Permit,
    Receipt,
    Signed,
    TrustStore,
)
from mcp_zero_trust_layer.evidence.protocol import (
    LOOKUP,
    attach_permit,
    request_payload,
    response_payload,
    split_response,
    validate_client,
)
from mcp_zero_trust_layer.evidence.store import EvidenceStore
from mcp_zero_trust_layer.evidence.verify import verify_bundle, verify_permit
from mcp_zero_trust_layer.protocol import JSONRPCError


def local_path(value: str, base: str | None) -> Path:
    path = Path(value)
    return (Path(base or ".") / path).resolve() if not path.is_absolute() else path


def load_private_key(path: Path) -> Ed25519PrivateKey:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        if os.fstat(handle.fileno()).st_mode & 0o077:
            raise ValueError("private signing key must have mode 0600")
        seed = decode(handle.read(256).decode("ascii").strip())
    return Ed25519PrivateKey.from_private_bytes(seed)


class EvidenceRuntime:
    def __init__(self, config: EvidenceConfig, base: str | None = None):
        self.config = config
        self.key = load_private_key(local_path(config.private_key_file, base))
        self.trust = TrustStore.model_validate(loads(local_path(config.trust_store, base).read_bytes()))
        own = next((k for k in self.trust.keys if k.kid == config.key_id), None)
        if (own is None or own.public_key != encode(self.key.public_key().public_bytes_raw()) or
            own.status != "active" or own.role != "gateway" or
            (own.issuer, own.audience, own.tenant) !=
                (config.issuer, config.destination, config.tenant)):
            raise ValueError("gateway signing key is not configured as trusted")
        if not any(k.role == "destination" and k.status == "active" and
                   (k.issuer, k.audience, k.tenant) ==
                   (config.destination, config.issuer, config.tenant) and config.scope in k.scopes
                   for k in self.trust.keys):
            raise ValueError("no trusted destination key for configured scope")
        self.store = EvidenceStore(local_path(config.store, base))

    def private_digest(self, kind: str, value: Any) -> str:
        return hmac.new(self.store.salt, kind.encode() + b":" + canonical(value),
                        hashlib.sha256).hexdigest()

    def prepare(self, message: dict[str, Any], context: RequestContext,
                consume: Callable[[sqlite3.Connection], bool] | None = None
                ) -> tuple[str, dict[str, Any]]:
        client_key = validate_client(message)
        value = request_payload(message)
        cfg = self.config
        now = int(time.time())
        principal = self.private_digest("principal", {
            "subject": context.identity.subject, "client": context.identity.client_id,
            "agent": context.identity.agent_id, "tenant": cfg.tenant,
            "authority": context.metadata.get("identity_authority"),
        })
        nonce = secrets.token_hex(32)
        auth = Authorization(
            issuer=cfg.issuer, audience=cfg.destination, tenant=cfg.tenant, principal=principal,
            operation_id="op_" + uuid4().hex, authorization_id="auth_" + uuid4().hex,
            approval_id=context.metadata.get("approval_id"), decision="allow", method="tools/call",
            tool=context.capability or "", request_digest=digest("request", value, nonce),
            request_nonce=nonce,
            policy_binding=self.private_digest("policy", context.metadata["request_binding"]),
            issued_at=now, expires_at=now + cfg.ttl_seconds,
        )
        signed_auth = sign(auth.model_dump(), "authorization", cfg.key_id, self.key)
        attempt = Attempt(
            issuer=cfg.issuer, audience=cfg.destination, tenant=cfg.tenant,
            operation_id=auth.operation_id, attempt_id="attempt_" + uuid4().hex,
            authorization_digest=digest("authorization", signed_auth.model_dump()),
            nonce=secrets.token_hex(32),
        )
        permit = Permit(authorization=signed_auth,
                        attempt=sign(attempt.model_dump(), "attempt", cfg.key_id, self.key))
        verify_permit(permit, self.trust, now=now)
        bundle = Bundle(permit=permit)
        scope = self.private_digest("operation", [cfg.tenant, principal, cfg.destination,
                                                  context.capability, client_key or auth.operation_id])
        fingerprint = self.private_digest("request", value)
        previous = self.store.reserve(bundle.model_dump(), scope, fingerprint, consume)
        if previous:
            raise JSONRPCError(-32052, "Operation already reserved; reconcile, do not repeat",
                               {"operation_id": previous, "effect": "unknown"})
        return auth.operation_id, attach_permit(message, permit.model_dump())

    def observe(self, operation: str, response: dict[str, Any]) -> dict[str, Any]:
        clean, raw_receipt = split_response(response)
        bundle = self.store.get(operation, self.config.tenant)
        bundle["receipt"] = raw_receipt
        verdict = verify_bundle(bundle, self.trust, response=response_payload(clean))
        if raw_receipt is None:
            verdict["rejection"] = "MISSING_RECEIPT"
        if (raw_receipt is not None and not verdict["rejection"] and
                Receipt.model_validate(raw_receipt["payload"]).scope != self.config.scope):
            verdict["rejection"] = "UNEXPECTED_EFFECT_SCOPE"
            verdict.update(effect="unknown", claim="none", authority="not_established")
        nonce = secrets.token_hex(32)
        self.store.record(operation, self.config.tenant, {
            "phase": "response_observed", "verdict": verdict,
            "response_digest": digest("response", response_payload(clean), nonce),
            "response_nonce": nonce,
        }, raw_receipt if not verdict["rejection"] else None)
        if verdict["rejection"] and self.config.mode == "required":
            raise ValueError("DESTINATION_EVIDENCE_UNVERIFIED")
        return clean

    def prepared(self, operation: str, response: dict[str, Any]) -> None:
        nonce = secrets.token_hex(32)
        self.store.record(operation, self.config.tenant, {
            "phase": "client_response_prepared", "nonce": nonce,
            "digest": digest("client_response", response_payload(response), nonce),
        })

    def reconcile(self, operation: str,
                  send: Callable[[dict[str, Any]], dict[str, Any] | None]) -> dict[str, Any]:
        bundle = self.store.get(operation, self.config.tenant)
        request = {"jsonrpc": "2.0", "id": "lookup_" + uuid4().hex, "method": LOOKUP,
                   "params": {"permit": bundle["permit"]}}
        response = send(request)
        if response is None or not isinstance(response.get("result"), dict):
            raise ValueError("RECONCILIATION_UNKNOWN")
        receipt = response["result"].get("receipt")
        candidate = {**bundle, "receipt": receipt}
        verdict = verify_bundle(candidate, self.trust)
        if receipt is None or verdict["rejection"]:
            raise ValueError("RECONCILIATION_UNKNOWN")
        parsed = Signed.model_validate(receipt)
        if Receipt.model_validate(parsed.payload).scope != self.config.scope:
            raise ValueError("UNEXPECTED_EFFECT_SCOPE")
        self.store.record(operation, self.config.tenant,
                          {"phase": "reconciled", "verdict": verdict}, receipt)
        return verdict
