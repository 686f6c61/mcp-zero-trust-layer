from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.config.secrets import resolve_secret_value


def test_production_requires_default_deny() -> None:
    with pytest.raises(ValidationError, match="production requires runtime.default_decision"):
        MCPZTConfig.model_validate(
            {
                "project": {"name": "prod", "environment": "production"},
                "runtime": {
                    "default_decision": "allow",
                    "public_base_url": "https://mcpzt.example",
                },
                "auth": {"mode": "static_token", "token": "secret"},
                "servers": [
                    {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
                ],
            }
        )


def test_production_rejects_auth_none_without_override() -> None:
    with pytest.raises(ValidationError, match="production cannot use auth.mode: none"):
        MCPZTConfig.model_validate(
            {
                "project": {"name": "prod", "environment": "production"},
                "runtime": {
                    "default_decision": "deny",
                    "public_base_url": "https://mcpzt.example",
                },
                "auth": {"mode": "none"},
                "servers": [
                    {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
                ],
            }
        )


def test_production_rejects_dry_run_without_override() -> None:
    with pytest.raises(ValidationError, match="production cannot use runtime.dry_run"):
        MCPZTConfig.model_validate(
            {
                "project": {"name": "prod", "environment": "production"},
                "runtime": {
                    "default_decision": "deny",
                    "dry_run": True,
                    "public_base_url": "https://mcpzt.example",
                },
                "auth": {"mode": "static_token", "token": "secret"},
                "servers": [
                    {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
                ],
            }
        )


def test_production_requires_public_base_url_or_trusted_hosts() -> None:
    with pytest.raises(ValidationError, match="production requires runtime.public_base_url"):
        MCPZTConfig.model_validate(
            {
                "project": {"name": "prod", "environment": "production"},
                "runtime": {"default_decision": "deny"},
                "auth": {"mode": "static_token", "token": "secret"},
                "servers": [
                    {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
                ],
            }
        )


def test_production_jwt_requires_issuer_and_audience() -> None:
    with pytest.raises(ValidationError, match="production jwt auth requires auth.issuer"):
        MCPZTConfig.model_validate(
            {
                "project": {"name": "prod", "environment": "production"},
                "runtime": {
                    "default_decision": "deny",
                    "public_base_url": "https://mcpzt.example",
                },
                "auth": {"mode": "jwt", "token": "secret", "algorithms": ["HS256"]},
                "servers": [
                    {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
                ],
            }
        )


def test_auth_token_and_token_env_are_mutually_exclusive() -> None:
    with pytest.raises(ValidationError, match="auth.token and auth.token_env"):
        MCPZTConfig.model_validate(
            {
                "project": {"name": "dev", "environment": "development"},
                "auth": {
                    "mode": "api_key",
                    "token": "inline",
                    "token_env": "MCPZT_API_KEY",
                },
                "servers": [
                    {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
                ],
            }
        )


def test_file_secret_reference_resolves(tmp_path) -> None:
    secret = tmp_path / "token.txt"
    secret.write_text("super-secret\n", encoding="utf-8")

    assert resolve_secret_value(f"file:{secret}", field="auth.token") == "super-secret"


def test_opa_policy_engine_requires_endpoint() -> None:
    with pytest.raises(ValidationError, match="policy_engine.adapter: opa"):
        MCPZTConfig.model_validate(
            {
                "project": {"name": "dev", "environment": "development"},
                "auth": {"mode": "none"},
                "servers": [
                    {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
                ],
                "policy_engine": {"adapter": "opa"},
            }
        )
