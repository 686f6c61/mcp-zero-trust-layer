"""Read-only corroboration. A signed observer report is not a provider signature."""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from mcp_zero_trust_layer.evidence.canonical import MAX_BYTES, canonical, digest, loads
from mcp_zero_trust_layer.evidence.check_models import (
    CheckedBundle,
    Observation,
    ObservationHeader,
    ObserverKey,
    ObserverTrust,
    RefundArguments,
    SignedObservation,
    StripeCheckConfig,
)
from mcp_zero_trust_layer.evidence.crypto import decode, encode
from mcp_zero_trust_layer.evidence.models import Authorization, Bundle, Receipt, TrustStore

DOMAIN = b"mcpzt.evidence.v2:external_observation:"


def observation_bytes(header: ObservationHeader, payload: Observation) -> bytes:
    return DOMAIN + canonical({"protected": header.model_dump(), "payload": payload.model_dump()})


def observation_digest(value: SignedObservation) -> str:
    return hashlib.sha256(DOMAIN + b"chain:" + canonical(value.model_dump())).hexdigest()


def observer_key(document: SignedObservation, trust: ObserverTrust,
                 gateway_trust: TrustStore) -> ObserverKey:
    key = next((k for k in trust.keys if k.kid == document.protected.kid), None)
    if key is None or key.status == "revoked":
        raise ValueError("UNTRUSTED_OBSERVER")
    payload = document.payload
    if any(getattr(key, name) != getattr(payload, name) for name in (
            "issuer", "tenant", "destination", "source", "scope", "account")):
        raise ValueError("OBSERVER_SCOPE_MISMATCH")
    if key.public_key in {k.public_key for k in gateway_trust.keys}:
        raise ValueError("OBSERVER_KEY_NOT_SEPARATE")
    try:
        Ed25519PublicKey.from_public_bytes(decode(key.public_key)).verify(
            decode(document.signature), observation_bytes(document.protected, payload))
    except InvalidSignature as exc:
        raise ValueError("INVALID_OBSERVER_SIGNATURE") from exc
    return key


def verify_checked(raw: Any, trust: TrustStore, observers: ObserverTrust | None,
                   *, request: Any = None, response: Any = None,
                   now: int | None = None) -> dict[str, Any]:
    from mcp_zero_trust_layer.evidence.verify import verify_bundle

    canonical(raw)
    bundle = CheckedBundle.model_validate(raw)
    verdict = verify_bundle(bundle.evidence.model_dump(), trust, request=request, response=response)
    if verdict["rejection"]:
        return verdict
    current = int(time.time()) if now is None else now
    history = []
    previous = None
    evidence_hash = digest("checked_bundle", bundle.evidence.model_dump())
    auth = Authorization.model_validate(bundle.evidence.permit.authorization.payload)
    for item in bundle.observations:
        key = observer_key(item, observers or ObserverTrust(keys=[]), trust)
        payload = item.payload
        if (verdict["claim"] != "destination_commit_attested" or
                bundle.evidence.receipt is None or
                bundle.evidence.receipt.payload.get("scope") != payload.scope):
            raise ValueError("OBSERVATION_EFFECT_SCOPE_MISMATCH")
        if (payload.evidence_digest != evidence_hash or payload.previous_digest != previous or
                payload.tenant != auth.tenant or payload.destination != auth.audience):
            raise ValueError("OBSERVATION_BINDING_MISMATCH")
        fresh = payload.checked_at <= current < payload.expires_at
        history.append({
            "check_id": payload.check_id, "reported_result": payload.result,
            "reason": payload.reason, "source_status": payload.source_status,
            "checked_at": payload.checked_at, "source_recorded_at": payload.source_recorded_at,
            "expires_at": payload.expires_at, "fresh": fresh,
            "source": payload.source, "scope": payload.scope, "account": payload.account,
            "observer": payload.issuer, "administration": key.administration,
            "administration_basis": "operator_configured_not_proven",
        })
        previous = observation_digest(item)
    verdict["external_check"] = {
        "verification": "observer_signature_verified" if history else "not_provided",
        "result": "observer_attested" if history else "unknown",
        "history": history, "provider_signature": "not_provided",
        "independence": "not_proven", "history_completeness": "unknown",
        "current_state": "not_established_offline",
    }
    return verdict


class StripeRefundReader:
    """Fixed HTTPS origin, GET only, no redirects/retries/proxy environment."""

    def __init__(self, api_key: str, account: str, *,
                 transport: httpx.BaseTransport | None = None):
        if not re.fullmatch(r"(?:sk|rk)_test_[A-Za-z0-9]+", api_key):
            raise ValueError("TEST_MODE_KEY_REQUIRED")
        if not re.fullmatch(r"acct_[A-Za-z0-9]{1,250}", account):
            raise ValueError("INVALID_STRIPE_ACCOUNT")
        self.client = httpx.Client(
            base_url="https://api.stripe.com", transport=transport, trust_env=False,
            follow_redirects=False, timeout=httpx.Timeout(10.0),
            headers={"Authorization": "Bearer " + api_key, "Stripe-Account": account,
                     "Stripe-Version": "2024-06-20"},
        )

    def close(self) -> None:
        self.client.close()

    def get(self, path: str) -> tuple[int, Any]:
        # Paths are assembled only by read(); no receipt-supplied URLs.
        with self.client.stream("GET", path) as response:
            if response.status_code != 200:
                return response.status_code, None
            data = bytearray()
            for chunk in response.iter_bytes(chunk_size=65536):
                data.extend(chunk)
                if len(data) > MAX_BYTES:
                    raise ValueError("SOURCE_TOO_LARGE")
            return 200, loads(bytes(data))

    def read(self, refund_id: str) -> tuple[int, Any, Any]:
        if not re.fullmatch(r"re_[A-Za-z0-9]{1,200}", refund_id):
            raise ValueError("INVALID_REFUND_REFERENCE")
        status, account = self.get("/v1/account")
        if status != 200:
            return status, None, None
        status, refund = self.get("/v1/refunds/" + refund_id)
        return status, account, refund


def evaluate_refund(status: int, account: Any, refund: Any, args: RefundArguments,
                    receipt: Receipt, bundle: Bundle) -> dict[str, Any]:
    """Corroborates provider-reported status only, not settlement or causation."""
    result: dict[str, Any] = {"result": "unknown", "reason": "SOURCE_UNAVAILABLE",
                              "source_status": None, "source_recorded_at": None}
    if status != 200:
        if status == 404 and account is not None:
            result["reason"] = "SOURCE_NOT_FOUND"
        return result
    if not isinstance(account, dict) or account.get("id") != args.account:
        return {**result, "reason": "ACCOUNT_MISMATCH"}
    if not isinstance(refund, dict):
        return {**result, "reason": "SOURCE_INVALID"}
    if (refund.get("object") != "refund" or
            type(refund.get("created")) is not int or refund["created"] < 0 or
            type(refund.get("amount")) is not int):
        return {**result, "reason": "SOURCE_INVALID"}
    result["source_recorded_at"] = refund["created"]
    if (refund.get("id"), refund["amount"], refund.get("currency"), refund.get("charge")) != (
            receipt.transaction_ref, args.amount_minor, args.currency, args.charge):
        return {**result, "result": "contradicted", "reason": "FIELD_MISMATCH"}
    auth = bundle.permit.authorization.payload
    metadata = refund.get("metadata")
    expected = {
        "mcpzt_operation_id": auth["operation_id"],
        "mcpzt_authorization_id": auth["authorization_id"],
        "mcpzt_attempt_id": bundle.permit.attempt.payload["attempt_id"],
        "mcpzt_request_digest": auth["request_digest"],
    }
    if not isinstance(metadata, dict) or any(metadata.get(k) != v for k, v in expected.items()):
        return {**result, "reason": "BINDING_MISMATCH"}
    source_status = refund.get("status")
    if source_status not in ("succeeded", "failed", "canceled", "pending", "requires_action"):
        return {**result, "reason": "UNSUPPORTED_STATUS"}
    result["source_status"] = source_status
    if source_status == "succeeded":
        return {**result, "result": "corroborated", "reason": "STATUS_MATCH"}
    if source_status in ("failed", "canceled"):
        return {**result, "result": "contradicted", "reason": "STATUS_CONFLICT"}
    return {**result, "result": "pending", "reason": "SOURCE_PENDING"}


def check_refund(raw: Any, request: Any, trust: TrustStore, config: StripeCheckConfig,
                 observers: ObserverTrust, private_key: Ed25519PrivateKey,
                 reader: StripeRefundReader, *, previous: str | None = None,
                 now: int | None = None) -> SignedObservation:
    from mcp_zero_trust_layer.evidence.verify import verify_bundle

    verdict = verify_bundle(raw, trust, request=request)
    if verdict["rejection"] or verdict["claim"] != "destination_commit_attested":
        raise ValueError("COMMITTED_RECEIPT_REQUIRED")
    bundle = Bundle.model_validate(raw)
    auth = Authorization.model_validate(bundle.permit.authorization.payload)
    receipt = Receipt.model_validate(bundle.receipt.payload)  # type: ignore[union-attr]
    if (auth.tenant, auth.audience, receipt.scope, auth.tool) != (
            config.tenant, config.destination, config.receipt_scope, config.tool):
        raise ValueError("CHECK_SCOPE_MISMATCH")
    if (not isinstance(request, dict) or request.get("method") != "tools/call" or
            not isinstance(request.get("params"), dict) or
            request["params"].get("name") != config.tool):
        raise ValueError("CHECK_TOOL_MISMATCH")
    args = RefundArguments.model_validate(request["params"].get("arguments"))
    if args.account != config.account:
        raise ValueError("CHECK_ACCOUNT_MISMATCH")
    key = next((k for k in observers.keys if k.kid == config.observer_key_id), None)
    if key is None or key.status != "active":
        raise ValueError("ACTIVE_OBSERVER_REQUIRED")
    checked_at = int(time.time()) if now is None else now
    payload = Observation(
        issuer=key.issuer, tenant=auth.tenant, destination=auth.audience,
        source="stripe", scope="stripe.refund.status.v1", account=args.account,
        evidence_digest=digest("checked_bundle", bundle.model_dump()), previous_digest=previous,
        check_id="check_" + uuid4().hex, checked_at=checked_at,
        expires_at=checked_at + config.freshness_seconds, result="unknown",
        reason="SOURCE_UNAVAILABLE", source_status=None, source_digest=None,
        source_nonce=secrets.token_hex(32),
    )
    header = ObservationHeader(kid=key.kid)

    def signed() -> SignedObservation:
        doc = SignedObservation(protected=header, payload=payload,
            signature=encode(private_key.sign(observation_bytes(header, payload))))
        observer_key(doc, observers, trust)
        return doc

    signed()  # Validate signing key and authority BEFORE network access.
    try:
        status, account, refund = reader.read(receipt.transaction_ref or "")
        values = evaluate_refund(status, account, refund, args, receipt, bundle)
        payload = Observation.model_validate({**payload.model_dump(), **values,
            "source_digest": digest("external_source", {"status": status, "account": account,
                                      "refund": refund}, payload.source_nonce)})
    except (httpx.HTTPError, ValueError):
        # No upstream payload, URL, authorization header or exception text escapes.
        payload = Observation.model_validate({**payload.model_dump(), "reason": "SOURCE_UNAVAILABLE"})
    return signed()


def load_observer_private_key(path: Path) -> Ed25519PrivateKey:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        if os.fstat(handle.fileno()).st_mode & 0o077:
            raise ValueError("OBSERVER_KEY_MUST_BE_PRIVATE")
        return Ed25519PrivateKey.from_private_bytes(decode(handle.read(128).decode().strip()))
