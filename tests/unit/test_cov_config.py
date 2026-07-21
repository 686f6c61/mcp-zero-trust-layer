from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_zero_trust_layer.config.loader import load_config
from mcp_zero_trust_layer.config.models import MCPZTConfig, PolicyConfig
from mcp_zero_trust_layer.errors import ConfigError


def _http_server() -> dict:
    return {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}


# ---- loader.py ----


def test_load_config_file_not_found(tmp_path) -> None:
    with pytest.raises(ConfigError, match="config file not found"):
        load_config(tmp_path / "missing.yaml")


def test_load_config_invalid_yaml(tmp_path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("key: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(path)


def test_load_config_validation_error(tmp_path) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text("project:\n  name: x\n", encoding="utf-8")  # missing servers
    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_success_sets_base_dir(tmp_path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "project:\n  name: ok\nauth:\n  mode: none\n"
        "servers:\n  - name: github\n    transport: http\n    upstream: http://localhost:3001/mcp\n",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.config_base_dir == str(tmp_path.resolve())
    assert config.servers[0].name == "github"


# ---- models.py ----


def test_server_http_requires_upstream() -> None:
    with pytest.raises(ValidationError, match="transport http requires upstream"):
        MCPZTConfig.model_validate(
            {"auth": {"mode": "none"}, "servers": [{"name": "a", "transport": "http"}]}
        )


def test_server_stdio_requires_command() -> None:
    with pytest.raises(ValidationError, match="transport stdio requires command"):
        MCPZTConfig.model_validate(
            {"auth": {"mode": "none"}, "servers": [{"name": "a", "transport": "stdio"}]}
        )


def test_unique_server_names() -> None:
    with pytest.raises(ValidationError, match="server names must be unique"):
        MCPZTConfig.model_validate(
            {
                "auth": {"mode": "none"},
                "servers": [_http_server(), _http_server()],
            }
        )


def test_unique_policy_ids() -> None:
    with pytest.raises(ValidationError, match="policy ids must be unique"):
        MCPZTConfig.model_validate(
            {
                "auth": {"mode": "none"},
                "servers": [_http_server()],
                "policies": [
                    {"id": "p1", "effect": "allow"},
                    {"id": "p1", "effect": "deny"},
                ],
            }
        )


def test_normalize_validators_variants() -> None:
    policy = PolicyConfig.model_validate(
        {
            "id": "p",
            "effect": "allow",
            "validators": ["sql_read_only", {"name": "other", "options": {"a": 1}}],
        }
    )
    assert policy.validators[0].name == "sql_read_only"
    assert policy.validators[1].name == "other"
    assert policy.validators[1].options == {"a": 1}


def test_normalize_validators_none() -> None:
    policy = PolicyConfig.model_validate({"id": "p", "effect": "allow", "validators": None})
    assert policy.validators == []


def test_production_jwt_requires_audience() -> None:
    with pytest.raises(ValidationError, match="production jwt auth requires auth.audience"):
        MCPZTConfig.model_validate(
            {
                "project": {"name": "prod", "environment": "production"},
                "runtime": {"default_decision": "deny", "public_base_url": "https://x.example"},
                "auth": {
                    "mode": "jwt",
                    "token": "secret",
                    "algorithms": ["HS256"],
                    "issuer": "https://issuer.example",
                },
                "servers": [_http_server()],
            }
        )


def test_production_valid_config_passes() -> None:
    config = MCPZTConfig.model_validate(
        {
            "project": {"name": "prod", "environment": "production"},
            "runtime": {"default_decision": "deny", "trusted_hosts": ["mcpzt.example"]},
            "auth": {"mode": "static_token", "token": "secret"},
            "servers": [_http_server()],
        }
    )
    assert config.project.environment == "production"


def test_non_production_environment_skips_checks() -> None:
    config = MCPZTConfig.model_validate(
        {
            "project": {"name": "dev", "environment": "development"},
            "runtime": {"default_decision": "allow"},
            "auth": {"mode": "none"},
            "servers": [_http_server()],
        }
    )
    assert config.runtime.default_decision == "allow"
