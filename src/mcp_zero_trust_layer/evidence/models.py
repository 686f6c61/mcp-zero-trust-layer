from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Text = Annotated[str, Field(min_length=1, max_length=256)]
Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Nonce = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Protected(StrictModel):
    version: Literal[1]
    alg: Literal["Ed25519"]
    kind: Literal["authorization", "attempt", "receipt"]
    kid: Text


class Signed(StrictModel):
    protected: Protected
    payload: dict[str, Any]
    signature: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{86}$")]


class Authorization(StrictModel):
    issuer: Text
    audience: Text
    tenant: Text
    principal: Hash
    operation_id: Text
    authorization_id: Text
    approval_id: Text | None
    decision: Literal["allow"]
    method: Literal["tools/call"]
    tool: Text
    request_digest: Hash
    request_nonce: Nonce
    policy_binding: Hash
    issued_at: int = Field(ge=0)
    expires_at: int = Field(ge=0)

    @model_validator(mode="after")
    def window(self) -> Authorization:
        if not 0 < self.expires_at - self.issued_at <= 300:
            raise ValueError("authorization lifetime must be 1..300 seconds")
        return self


class Attempt(StrictModel):
    issuer: Text
    audience: Text
    tenant: Text
    operation_id: Text
    attempt_id: Text
    authorization_digest: Hash
    nonce: Nonce


class Receipt(StrictModel):
    issuer: Text
    audience: Text
    tenant: Text
    operation_id: Text
    authorization_id: Text
    attempt_id: Text
    receipt_id: Text
    attempt_digest: Hash
    request_digest: Hash
    response_digest: Hash
    response_nonce: Nonce
    effect: Literal["pending", "committed", "rejected", "failed", "partially_committed"]
    scope: Text
    transaction_ref: Text | None
    sequence: int = Field(ge=1)
    recorded_at: int = Field(ge=0)

    @model_validator(mode="after")
    def commit_reference(self) -> Receipt:
        if self.effect in {"committed", "partially_committed"} and not self.transaction_ref:
            raise ValueError("committed effects require a transaction reference")
        return self


class Permit(StrictModel):
    authorization: Signed
    attempt: Signed


class Bundle(StrictModel):
    version: Literal[1] = 1
    permit: Permit
    receipt: Signed | None = None


class TrustKey(StrictModel):
    kid: Text
    issuer: Text
    audience: Text
    tenant: Text
    role: Literal["gateway", "destination"]
    public_key: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]
    scopes: list[Text] = Field(default_factory=list)
    status: Literal["active", "retired", "revoked"] = "active"


class TrustStore(StrictModel):
    version: Literal[1] = 1
    keys: list[TrustKey] = Field(max_length=1000)

    @model_validator(mode="after")
    def unique(self) -> TrustStore:
        ids = [key.kid for key in self.keys]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate trust key id")
        gateway_keys = {key.public_key for key in self.keys if key.role == "gateway"}
        if any(key.public_key in gateway_keys for key in self.keys if key.role == "destination"):
            raise ValueError("gateway and destination must use separate signing keys")
        return self


def bundle_schema() -> dict[str, Any]:
    """Constrain Signed.payload by protected.kind, also for independent schema validators."""
    schema = Bundle.model_json_schema()
    definitions = schema["$defs"]
    definitions["Signed"]["allOf"] = []
    payload_models: list[tuple[str, type[BaseModel]]] = [
        ("authorization", Authorization), ("attempt", Attempt), ("receipt", Receipt),
    ]
    for kind, model in payload_models:
        definitions[model.__name__] = model.model_json_schema()
        definitions["Signed"]["allOf"].append({
            "if": {"properties": {"protected": {"properties": {"kind": {"const": kind}}}}},
            "then": {"properties": {"payload": {"$ref": f"#/$defs/{model.__name__}"}}},
        })
    return schema
