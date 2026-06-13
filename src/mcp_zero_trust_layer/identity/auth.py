from __future__ import annotations

import hmac
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

from mcp_zero_trust_layer.config.models import AuthConfig
from mcp_zero_trust_layer.config.secrets import SecretError, resolve_secret_value
from mcp_zero_trust_layer.identity.models import Identity


class AuthError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class AuthResolver:
    def __init__(self, config: AuthConfig):
        self.config = config
        self._jwk_client: PyJWKClient | None = None

    def resolve_http_identity(
        self,
        *,
        headers: dict[str, str],
        source_ip: str | None,
        fallback_subject: str = "http-client",
        environment: str | None = None,
    ) -> Identity:
        mode = self.config.mode
        normalized_headers = {key.lower(): value for key, value in headers.items()}
        if mode == "none":
            return self._identity_from_headers(
                normalized_headers,
                fallback_subject=fallback_subject,
                source_ip=source_ip,
                auth_method="none",
                environment=environment,
                trust_headers=self.config.trust_identity_headers,
            )

        token = self._read_token(normalized_headers)
        if mode == "static_token":
            self._validate_static_token(token)
            return self._identity_from_headers(
                normalized_headers,
                fallback_subject=fallback_subject,
                source_ip=source_ip,
                auth_method="static_token",
                environment=environment,
                trust_headers=self.config.trust_identity_headers,
            )
        if mode == "api_key":
            self._validate_api_key(token)
            return self._identity_from_headers(
                normalized_headers,
                fallback_subject=fallback_subject,
                source_ip=source_ip,
                auth_method="api_key",
                environment=environment,
                trust_headers=self.config.trust_identity_headers,
            )
        if mode in {"jwt", "oidc"}:
            claims = self._decode_jwt(token)
            self._validate_scopes(claims)
            return self._identity_from_claims(
                claims,
                normalized_headers,
                source_ip=source_ip,
                auth_method=mode,
                environment=environment,
            )

        raise AuthError(f"unsupported auth mode: {mode}")

    def _read_token(self, headers: dict[str, str]) -> str:
        header = self.config.header.lower()
        value = headers.get(header)
        if not value:
            raise AuthError(f"missing auth header: {self.config.header}")
        if header == "authorization" and value.lower().startswith("bearer "):
            return value.split(" ", 1)[1].strip()
        return value.strip()

    def _validate_static_token(self, token: str) -> None:
        expected = self._configured_token()
        if not expected:
            raise AuthError("static_token auth is configured without a token")
        if not hmac.compare_digest(token, expected):
            raise AuthError("invalid static token")

    def _validate_api_key(self, token: str) -> None:
        expected = self._configured_token()
        if not expected:
            raise AuthError("api_key auth is configured without a token")
        if not hmac.compare_digest(token, expected):
            raise AuthError("invalid API key")

    def _decode_jwt(self, token: str) -> dict[str, Any]:
        options = {"require": ["exp"]}
        try:
            if self.config.jwks_url or self.config.mode == "oidc":
                key = self._jwk_client_for_config().get_signing_key_from_jwt(token).key
                claims = jwt.decode(
                    token,
                    key=key,
                    algorithms=self.config.algorithms,
                    audience=self.config.audience,
                    issuer=self.config.issuer,
                    options=options,
                )
            else:
                token_secret = self._configured_token()
                if not token_secret:
                    raise AuthError("jwt auth requires token secret or jwks_url")
                claims = jwt.decode(
                    token,
                    key=token_secret,
                    algorithms=self.config.algorithms or ["HS256"],
                    audience=self.config.audience,
                    issuer=self.config.issuer,
                    options=options,
                )
        except AuthError:
            raise
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid JWT: {exc}") from exc
        if not isinstance(claims, dict):
            raise AuthError("invalid JWT claims")
        return claims

    def _configured_token(self) -> str | None:
        raw = f"env:{self.config.token_env}" if self.config.token_env else self.config.token
        if not raw:
            return None
        try:
            return resolve_secret_value(raw, field="auth.token")
        except SecretError as exc:
            raise AuthError(str(exc)) from exc

    def _jwk_client_for_config(self) -> PyJWKClient:
        if self._jwk_client is None:
            jwks_url = self.config.jwks_url or self._discover_jwks_url()
            self._jwk_client = PyJWKClient(jwks_url)
        return self._jwk_client

    def _discover_jwks_url(self) -> str:
        if not self.config.issuer:
            raise AuthError("oidc auth requires issuer or jwks_url")
        issuer = self.config.issuer.rstrip("/")
        discovery_url = f"{issuer}/.well-known/openid-configuration"
        try:
            response = httpx.get(discovery_url, timeout=5)
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPError as exc:
            raise AuthError(f"OIDC discovery failed: {exc}") from exc
        jwks_uri = payload.get("jwks_uri")
        if not isinstance(jwks_uri, str):
            raise AuthError("OIDC discovery response did not include jwks_uri")
        return jwks_uri

    def _validate_scopes(self, claims: dict[str, Any]) -> None:
        required = set(self.config.required_scopes)
        if not required:
            return
        scopes = _as_scope_set(claims.get(self.config.scopes_claim))
        if self.config.scopes_claim == "scope":
            scopes.update(_as_scope_set(claims.get("scp")))
        missing = required - scopes
        if missing:
            raise AuthError(f"missing required scopes: {', '.join(sorted(missing))}")

    def _identity_from_claims(
        self,
        claims: dict[str, Any],
        headers: dict[str, str],
        *,
        source_ip: str | None,
        auth_method: str,
        environment: str | None,
    ) -> Identity:
        groups = _as_str_list(claims.get(self.config.groups_claim))
        roles = _as_str_list(claims.get(self.config.roles_claim))
        subject = str(claims.get(self.config.subject_claim) or "unknown")
        return Identity(
            subject=subject,
            email=_optional_str(claims.get(self.config.email_claim)),
            groups=groups,
            roles=roles,
            client_id=_optional_str(claims.get(self.config.client_id_claim))
            or headers.get("x-mcpzt-client-id"),
            agent_id=_optional_str(claims.get(self.config.agent_id_claim))
            or headers.get("x-mcpzt-agent-id"),
            session_id=headers.get("x-mcpzt-session-id"),
            conversation_id=headers.get("x-mcpzt-conversation-id"),
            project_id=headers.get("x-mcpzt-project-id"),
            source_ip=source_ip,
            auth_method=auth_method,
            machine_id=headers.get("x-mcpzt-machine-id"),
            environment=environment,
        )

    @staticmethod
    def _identity_from_headers(
        headers: dict[str, str],
        *,
        fallback_subject: str,
        source_ip: str | None,
        auth_method: str,
        environment: str | None,
        trust_headers: bool,
    ) -> Identity:
        if not trust_headers:
            return Identity(
                subject=fallback_subject,
                source_ip=source_ip,
                auth_method=auth_method,
                environment=environment,
            )
        return Identity(
            subject=headers.get("x-mcpzt-subject", fallback_subject),
            email=headers.get("x-mcpzt-email"),
            groups=_split_header(headers.get("x-mcpzt-groups")),
            roles=_split_header(headers.get("x-mcpzt-roles")),
            client_id=headers.get("x-mcpzt-client-id"),
            agent_id=headers.get("x-mcpzt-agent-id"),
            session_id=headers.get("x-mcpzt-session-id"),
            conversation_id=headers.get("x-mcpzt-conversation-id"),
            project_id=headers.get("x-mcpzt-project-id"),
            source_ip=source_ip,
            auth_method=auth_method,
            machine_id=headers.get("x-mcpzt-machine-id"),
            environment=environment,
        )


def _split_header(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _as_scope_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {item for item in value.split() if item}
    if isinstance(value, list):
        return {str(item) for item in value if str(item)}
    return set()


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
