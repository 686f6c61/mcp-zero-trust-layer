from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWKClient
from jwt.algorithms import RSAAlgorithm

from mcp_zero_trust_layer.config.models import AuthConfig
from mcp_zero_trust_layer.identity import AuthError, AuthResolver

JWT_SECRET = "jwt-secret-with-at-least-32-bytes"


def test_static_token_identity_from_headers() -> None:
    resolver = AuthResolver(
        AuthConfig(mode="static_token", token="secret", trust_identity_headers=True)
    )

    identity = resolver.resolve_http_identity(
        headers={
            "authorization": "Bearer secret",
            "x-mcpzt-subject": "ana",
            "x-mcpzt-groups": "eng,security",
        },
        source_ip="127.0.0.1",
    )

    assert identity.subject == "ana"
    assert identity.groups == ["eng", "security"]
    assert identity.auth_method == "static_token"


def test_static_token_ignores_identity_headers_by_default() -> None:
    resolver = AuthResolver(AuthConfig(mode="static_token", token="secret"))

    identity = resolver.resolve_http_identity(
        headers={
            "authorization": "Bearer secret",
            "x-mcpzt-subject": "spoofed-admin",
            "x-mcpzt-groups": "security",
        },
        source_ip="127.0.0.1",
        fallback_subject="gateway-client",
    )

    assert identity.subject == "gateway-client"
    assert identity.groups == []


def test_static_token_rejects_invalid_token() -> None:
    resolver = AuthResolver(AuthConfig(mode="static_token", token="secret"))

    with pytest.raises(AuthError, match="invalid static token"):
        resolver.resolve_http_identity(headers={"authorization": "wrong"}, source_ip=None)


def test_api_key_accepts_token_env(monkeypatch) -> None:
    monkeypatch.setenv("MCPZT_TEST_API_KEY", "env-secret")
    resolver = AuthResolver(
        AuthConfig(mode="api_key", header="x-api-key", token_env="MCPZT_TEST_API_KEY")
    )

    identity = resolver.resolve_http_identity(
        headers={"x-api-key": "env-secret", "x-mcpzt-subject": "ci"},
        source_ip=None,
    )

    assert identity.subject == "http-client"
    assert identity.auth_method == "api_key"


def test_api_key_missing_token_env_fails_closed(monkeypatch) -> None:
    monkeypatch.delenv("MCPZT_TEST_API_KEY", raising=False)
    resolver = AuthResolver(
        AuthConfig(mode="api_key", header="x-api-key", token_env="MCPZT_TEST_API_KEY")
    )

    with pytest.raises(AuthError, match="unset environment variable"):
        resolver.resolve_http_identity(headers={"x-api-key": "env-secret"}, source_ip=None)


def test_jwt_maps_claims_to_identity() -> None:
    token = jwt.encode(
        {
            "sub": "user-123",
            "email": "ana@example.com",
            "groups": ["eng"],
            "roles": ["admin"],
            "client_id": "cursor",
            "scope": "mcp:read",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
            "iss": "https://issuer.example",
            "aud": "mcpzt",
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    resolver = AuthResolver(
        AuthConfig(
            mode="jwt",
            token=JWT_SECRET,
            algorithms=["HS256"],
            issuer="https://issuer.example",
            audience="mcpzt",
            required_scopes=["mcp:read"],
        )
    )

    identity = resolver.resolve_http_identity(
        headers={"authorization": f"Bearer {token}"},
        source_ip="127.0.0.1",
    )

    assert identity.subject == "user-123"
    assert identity.email == "ana@example.com"
    assert identity.groups == ["eng"]
    assert identity.roles == ["admin"]
    assert identity.client_id == "cursor"


def test_jwt_rejects_missing_scope() -> None:
    token = jwt.encode(
        {
            "sub": "user-123",
            "scope": "other",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    resolver = AuthResolver(
        AuthConfig(
            mode="jwt",
            token=JWT_SECRET,
            algorithms=["HS256"],
            required_scopes=["mcp:read"],
        )
    )

    with pytest.raises(AuthError, match="missing required scopes"):
        resolver.resolve_http_identity(headers={"authorization": f"Bearer {token}"}, source_ip=None)


def test_jwt_accepts_scp_list_scope_claim() -> None:
    token = jwt.encode(
        {
            "sub": "user-123",
            "scp": ["mcp:read", "mcp:write"],
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    resolver = AuthResolver(
        AuthConfig(
            mode="jwt",
            token=JWT_SECRET,
            algorithms=["HS256"],
            required_scopes=["mcp:read"],
        )
    )

    identity = resolver.resolve_http_identity(
        headers={"authorization": f"Bearer {token}"},
        source_ip=None,
    )

    assert identity.subject == "user-123"


def test_oidc_validates_jwks_issuer_and_audience(monkeypatch) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = "test-key"
    token = jwt.encode(
        {
            "sub": "oidc-user",
            "email": "oidc@example.com",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
            "iss": "https://issuer.example",
            "aud": "mcpzt",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )

    def fake_fetch_data(self: PyJWKClient) -> dict[str, object]:
        return {"keys": [public_jwk]}

    monkeypatch.setattr(PyJWKClient, "fetch_data", fake_fetch_data)
    resolver = AuthResolver(
        AuthConfig(
            mode="oidc",
            issuer="https://issuer.example",
            audience="mcpzt",
            jwks_url="https://issuer.example/jwks.json",
            algorithms=["RS256"],
        )
    )

    identity = resolver.resolve_http_identity(
        headers={"authorization": f"Bearer {token}"},
        source_ip=None,
    )

    assert identity.subject == "oidc-user"
    assert identity.email == "oidc@example.com"
    assert identity.auth_method == "oidc"
