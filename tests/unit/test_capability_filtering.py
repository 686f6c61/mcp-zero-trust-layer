from __future__ import annotations

from mcp_zero_trust_layer.capabilities.filtering import filter_capabilities
from mcp_zero_trust_layer.config.models import MCPZTConfig


def test_filters_tools_by_policy() -> None:
    config = MCPZTConfig.model_validate(
        {
            "project": {"name": "example", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "policies": [
                {
                    "id": "allow-search",
                    "effect": "allow",
                    "match": {
                        "server": "github",
                        "capability_type": "tool",
                        "capability": "github.search_issues",
                    },
                }
            ],
        }
    )

    visible = filter_capabilities(
        config,
        "github",
        "tool",
        [
            {"name": "github.search_issues"},
            {"name": "github.delete_repository"},
        ],
    )

    assert visible == [{"name": "github.search_issues"}]


def test_dry_run_returns_all_capabilities() -> None:
    config = MCPZTConfig.model_validate(
        {
            "project": {"name": "example", "environment": "development"},
            "runtime": {"default_decision": "deny", "dry_run": True},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "policies": [],
        }
    )
    capabilities = [
        {"name": "github.search_issues"},
        {"name": "github.delete_repository"},
    ]

    visible = filter_capabilities(config, "github", "tool", capabilities)

    assert visible == capabilities
