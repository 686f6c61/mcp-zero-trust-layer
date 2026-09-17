"""V2 envelopes preserve the v1 wire contract and add observer attestations."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from mcp_zero_trust_layer.evidence.models import Bundle, Hash, StrictModel, Text


class Observation(StrictModel):
    issuer: Text
    tenant: Text
    destination: Text
    source: Literal["stripe"]
    scope: Literal["stripe.refund.status.v1"]
    account: Annotated[str, Field(pattern=r"^acct_[A-Za-z0-9]+$")]
    evidence_digest: Hash
    previous_digest: Hash | None
    check_id: Text
    checked_at: int = Field(ge=0)
    expires_at: int = Field(ge=0)
    source_recorded_at: int | None = Field(default=None, ge=0)
    result: Literal["corroborated", "contradicted", "pending", "unknown"]
    reason: Literal["STATUS_MATCH", "FIELD_MISMATCH", "STATUS_CONFLICT", "SOURCE_PENDING",
                    "SOURCE_UNAVAILABLE", "SOURCE_INVALID", "SOURCE_NOT_FOUND",
                    "ACCOUNT_MISMATCH", "BINDING_MISMATCH", "UNSUPPORTED_STATUS"]
    source_status: Literal["succeeded", "failed", "canceled", "pending", "requires_action"] | None
    source_digest: Hash | None
    source_nonce: Hash

    @model_validator(mode="after")
    def interval(self) -> Observation:
        if not self.checked_at < self.expires_at <= self.checked_at + 3600:
            raise ValueError("INVALID_CHECK_INTERVAL")
        expected = {
            "STATUS_MATCH": "corroborated", "FIELD_MISMATCH": "contradicted",
            "STATUS_CONFLICT": "contradicted", "SOURCE_PENDING": "pending",
        }.get(self.reason, "unknown")
        if self.result != expected:
            raise ValueError("INCONSISTENT_CHECK_RESULT")
        allowed_statuses = {"STATUS_MATCH": {"succeeded"},
                            "STATUS_CONFLICT": {"failed", "canceled"},
                            "SOURCE_PENDING": {"pending", "requires_action"}}
        if self.reason in allowed_statuses and self.source_status not in allowed_statuses[self.reason]:
            raise ValueError("INCONSISTENT_SOURCE_STATUS")
        if self.result != "unknown" and (self.source_digest is None or self.source_recorded_at is None):
            raise ValueError("MISSING_SOURCE_COMMITMENT")
        return self


class ObservationHeader(StrictModel):
    version: Literal[2] = 2
    alg: Literal["Ed25519"] = "Ed25519"
    kind: Literal["external_observation"] = "external_observation"
    kid: Text


class SignedObservation(StrictModel):
    protected: ObservationHeader
    payload: Observation
    signature: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{86}$")]


class CheckedBundle(StrictModel):
    version: Literal[2] = 2
    evidence: Bundle
    observations: list[SignedObservation] = Field(default_factory=list, max_length=256)


class ObserverKey(StrictModel):
    kid: Text
    issuer: Text
    tenant: Text
    destination: Text
    source: Literal["stripe"] = "stripe"
    scope: Literal["stripe.refund.status.v1"] = "stripe.refund.status.v1"
    account: Annotated[str, Field(pattern=r"^acct_[A-Za-z0-9]+$")]
    public_key: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]
    status: Literal["active", "retired", "revoked"] = "active"
    administration: Literal["shared", "separate", "unknown"] = "unknown"


class ObserverTrust(StrictModel):
    version: Literal[1] = 1
    keys: list[ObserverKey] = Field(max_length=1000)

    @model_validator(mode="after")
    def unique(self) -> ObserverTrust:
        if len({k.kid for k in self.keys}) != len(self.keys):
            raise ValueError("DUPLICATE_OBSERVER_KEY")
        return self


class StripeCheckConfig(StrictModel):
    """Operator configuration, never supplied by a receipt or a caller."""

    version: Literal[1] = 1
    adapter: Literal["stripe_refund"] = "stripe_refund"
    tenant: Text
    destination: Text
    receipt_scope: Literal["stripe.refund.status.v1"] = "stripe.refund.status.v1"
    tool: Text
    account: Annotated[str, Field(pattern=r"^acct_[A-Za-z0-9]+$")]
    api_key_env: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")]
    observer_key_id: Text
    observer_private_key_file: Text
    observer_trust_file: Text
    freshness_seconds: int = Field(default=300, ge=1, le=3600)


class RefundArguments(StrictModel):
    """Exact supported tool contract; other adapters may define other contracts."""

    amount_minor: int = Field(gt=0, le=9007199254740991)
    currency: Annotated[str, Field(pattern=r"^[a-z]{3}$")]
    charge: Annotated[str, Field(pattern=r"^ch_[A-Za-z0-9]+$")]
    account: Annotated[str, Field(pattern=r"^acct_[A-Za-z0-9]+$")]
