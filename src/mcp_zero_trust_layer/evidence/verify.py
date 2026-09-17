from __future__ import annotations

from typing import Any

from mcp_zero_trust_layer.evidence.canonical import canonical, digest
from mcp_zero_trust_layer.evidence.crypto import verify_signature
from mcp_zero_trust_layer.evidence.models import (
    Attempt,
    Authorization,
    Bundle,
    Permit,
    Receipt,
    TrustStore,
)


def verify_permit(permit: Permit, trust: TrustStore, *, now: int | None = None
                  ) -> Authorization:
    auth = Authorization.model_validate(permit.authorization.payload)
    attempt = Attempt.model_validate(permit.attempt.payload)
    auth_key = verify_signature(permit.authorization, trust, "authorization")
    attempt_key = verify_signature(permit.attempt, trust, "attempt")
    if (attempt.issuer, attempt.audience, attempt.tenant, attempt.operation_id) != (
            auth.issuer, auth.audience, auth.tenant, auth.operation_id):
        raise ValueError("PERMIT_BINDING_MISMATCH")
    if attempt.authorization_digest != digest("authorization", permit.authorization.model_dump()):
        raise ValueError("AUTHORIZATION_DIGEST_MISMATCH")
    if now is not None and (auth_key.status != "active" or attempt_key.status != "active" or
                            not auth.issued_at <= now < auth.expires_at):
        raise ValueError("PERMIT_NOT_CURRENT")
    return auth


def verify_bundle(raw: Any, trust: TrustStore, *, request: Any = None, response: Any = None
                  ) -> dict[str, Any]:
    result: dict[str, Any] = {
        "integrity": "unverified", "authority": "unverified", "binding": "unverified",
        "claim": "none", "effect": "unknown", "request_content": "not_provided",
        "response_content": "not_provided", "completeness": "unknown",
        "execution_uniqueness": "not_proven", "trusted_timestamp": False,
        "rejection": None,
    }
    try:
        canonical(raw)
        bundle = Bundle.model_validate(raw)
        auth = verify_permit(bundle.permit, trust)
        result.update(integrity="valid", authority="trusted_gateway", binding="valid",
                      claim="authorization_recorded")
        if request is not None:
            if digest("request", request, auth.request_nonce) != auth.request_digest:
                raise ValueError("REQUEST_MISMATCH")
            result["request_content"] = "verified"
        if bundle.receipt is None:
            return result
        receipt = Receipt.model_validate(bundle.receipt.payload)
        key = verify_signature(bundle.receipt, trust, "receipt")
        attempt = Attempt.model_validate(bundle.permit.attempt.payload)
        if (receipt.issuer, receipt.audience, receipt.tenant, receipt.operation_id,
            receipt.authorization_id, receipt.attempt_id, receipt.request_digest) != (
                auth.audience, auth.issuer, auth.tenant, auth.operation_id,
                auth.authorization_id, attempt.attempt_id, auth.request_digest):
            raise ValueError("RECEIPT_BINDING_MISMATCH")
        if receipt.attempt_digest != digest("attempt", bundle.permit.model_dump()):
            raise ValueError("ATTEMPT_DIGEST_MISMATCH")
        if receipt.scope not in key.scopes:
            raise ValueError("UNTRUSTED_EFFECT_SCOPE")
        if response is not None:
            if digest("response", response, receipt.response_nonce) != receipt.response_digest:
                raise ValueError("RESPONSE_MISMATCH")
            result["response_content"] = "verified"
        result.update(authority="trusted_destination", claim="destination_receipt_verified",
                      effect=receipt.effect)
        if receipt.effect == "committed":
            result["claim"] = "destination_commit_attested"
        return result
    except (ValueError, TypeError, KeyError) as exc:
        # Never echo untrusted payloads, validation inputs or secrets in diagnostics.
        code = str(exc)
        result["rejection"] = code if code.isupper() and len(code) < 80 else "INVALID_EVIDENCE"
        result.update(integrity="not_established", authority="not_established",
                      binding="not_established", effect="unknown", claim="none")
        return result
