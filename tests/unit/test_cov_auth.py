from __future__ import annotations

import json
import types
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWKClient
from jwt.algorithms import RSAAlgorithm

from mcp_zero_trust_layer.config.models import AuthConfig
from mcp_zero_trust_layer.identity import AuthError, AuthResolver
from mcp_zero_trust_layer.identity import auth as auth_module

JWT_SECRET = "jwt-secret-with-at-least-32-bytes"


def _hs256(claims: dict) -> str:
    payload = {"exp": datetime.now(UTC) + timedelta(minutes=10), **claims}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def test_none_mode_returns_fallback_identity() -> None:
    resolver = AuthResolver(AuthConfig(mode="none"))
    identity = resolver.resolve_http_identity(headers={}, source_ip="1.2.3.4")
    assert identity.subject == "http-client"
    assert identity.auth_method == "none"


def test_unsupported_mode() -> None:
    resolver = AuthResolver(AuthConfig(mode="static_token", token="secret"))
    resolver.config.mode = "weird"  # type: ignore[assignment]
    with pytest.raises(AuthError, match="unsupported auth mode"):
        resolver.resolve_http_identity(
            headers={"authorization": "Bearer secret"}, source_ip=None
        )


def test_missing_auth_header() -> None:
    resolver = AuthResolver(AuthConfig(mode="static_token", token="secret"))
    with pytest.raises(AuthError, match="missing auth header"):
        resolver.resolve_http_identity(headers={}, source_ip=None)


def test_static_token_without_configured_token() -> None:
    resolver = AuthResolver(AuthConfig(mode="static_token"))
    with pytest.raises(AuthError, match="configured without a token"):
        resolver.resolve_http_identity(
            headers={"authorization": "Bearer x"}, source_ip=None
        )


def test_api_key_without_configured_token() -> None:
    resolver = AuthResolver(AuthConfig(mode="api_key", header="x-api-key"))
    with pytest.raises(AuthError, match="configured without a token"):
        resolver.resolve_http_identity(headers={"x-api-key": "x"}, source_ip=None)


def test_api_key_invalid() -> None:
    resolver = AuthResolver(AuthConfig(mode="api_key", header="x-api-key", token="right"))
    with pytest.raises(AuthError, match="invalid API key"):
        resolver.resolve_http_identity(headers={"x-api-key": "wrong"}, source_ip=None)


def test_non_authorization_header_returns_raw_value() -> None:
    resolver = AuthResolver(AuthConfig(mode="api_key", header="x-api-key", token="secret"))
    identity = resolver.resolve_http_identity(
        headers={"x-api-key": "secret"}, source_ip=None
    )
    assert identity.auth_method == "api_key"


def test_jwt_without_secret_or_jwks() -> None:
    resolver = AuthResolver(AuthConfig(mode="jwt", algorithms=["HS256"]))
    token = _hs256({"sub": "u"})
    with pytest.raises(AuthError, match="requires token secret or jwks_url"):
        resolver.resolve_http_identity(
            headers={"authorization": f"Bearer {token}"}, source_ip=None
        )


def test_jwt_invalid_token() -> None:
    resolver = AuthResolver(AuthConfig(mode="jwt", token=JWT_SECRET, algorithms=["HS256"]))
    with pytest.raises(AuthError, match="invalid JWT"):
        resolver.resolve_http_identity(
            headers={"authorization": "Bearer not-a-jwt"}, source_ip=None
        )


def test_jwt_non_dict_claims(monkeypatch) -> None:
    resolver = AuthResolver(AuthConfig(mode="jwt", token=JWT_SECRET, algorithms=["HS256"]))
    token = _hs256({"sub": "u"})
    monkeypatch.setattr(auth_module.jwt, "decode", lambda *a, **k: ["not", "dict"])
    with pytest.raises(AuthError, match="invalid JWT claims"):
        resolver.resolve_http_identity(
            headers={"authorization": f"Bearer {token}"}, source_ip=None
        )


def test_jwt_string_group_claim() -> None:
    token = _hs256({"sub": "u", "groups": "eng", "roles": "admin"})
    resolver = AuthResolver(AuthConfig(mode="jwt", token=JWT_SECRET, algorithms=["HS256"]))
    identity = resolver.resolve_http_identity(
        headers={"authorization": f"Bearer {token}"}, source_ip=None
    )
    assert identity.groups == ["eng"]
    assert identity.roles == ["admin"]


def test_jwt_default_algorithm_when_none() -> None:
    token = _hs256({"sub": "u"})
    config = AuthConfig(mode="jwt", token=JWT_SECRET)
    config.algorithms = []
    resolver = AuthResolver(config)
    identity = resolver.resolve_http_identity(
        headers={"authorization": f"Bearer {token}"}, source_ip=None
    )
    assert identity.subject == "u"


def test_jwt_unknown_subject_and_header_fallbacks() -> None:
    token = _hs256({})
    resolver = AuthResolver(AuthConfig(mode="jwt", token=JWT_SECRET, algorithms=["HS256"]))
    identity = resolver.resolve_http_identity(
        headers={
            "authorization": f"Bearer {token}",
            "x-mcpzt-client-id": "cli",
            "x-mcpzt-agent-id": "agent",
            "x-mcpzt-session-id": "sess",
        },
        source_ip=None,
    )
    assert identity.subject == "unknown"
    assert identity.client_id is None
    assert identity.agent_id is None
    assert identity.session_id is None


# ---- OIDC discovery ----


def test_discover_jwks_url_requires_issuer() -> None:
    resolver = AuthResolver(AuthConfig(mode="oidc"))
    with pytest.raises(AuthError, match="requires issuer or jwks_url"):
        resolver._discover_jwks_url()


def test_discover_jwks_url_http_error(monkeypatch) -> None:
    resolver = AuthResolver(AuthConfig(mode="oidc", issuer="https://issuer.example"))

    def boom(*a, **k):
        raise auth_module.httpx.HTTPError("down")

    monkeypatch.setattr(auth_module.httpx, "get", boom)
    with pytest.raises(AuthError, match="OIDC discovery failed"):
        resolver._discover_jwks_url()


def test_discover_jwks_url_missing_uri(monkeypatch) -> None:
    resolver = AuthResolver(AuthConfig(mode="oidc", issuer="https://issuer.example/"))

    def fake_get(*a, **k):
        return types.SimpleNamespace(raise_for_status=lambda: None, json=lambda: {})

    monkeypatch.setattr(auth_module.httpx, "get", fake_get)
    with pytest.raises(AuthError, match="did not include jwks_uri"):
        resolver._discover_jwks_url()


def test_oidc_full_flow_with_discovery(monkeypatch) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = "test-key"
    token = jwt.encode(
        {
            "sub": "oidc-user",
            "exp": datetime.now(UTC) + timedelta(minutes=10),
            "iss": "https://issuer.example",
            "aud": "mcpzt",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )

    def fake_get(url, *a, **k):
        return types.SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"jwks_uri": "https://issuer.example/jwks.json"},
        )

    monkeypatch.setattr(auth_module.httpx, "get", fake_get)
    monkeypatch.setattr(PyJWKClient, "fetch_data", lambda self: {"keys": [public_jwk]})

    resolver = AuthResolver(
        AuthConfig(
            mode="oidc",
            issuer="https://issuer.example",
            audience="mcpzt",
            algorithms=["RS256"],
        )
    )
    identity = resolver.resolve_http_identity(
        headers={"authorization": f"Bearer {token}"}, source_ip=None
    )
    assert identity.subject == "oidc-user"
