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


def test_list_filtering_does_not_run_call_validators() -> None:
    config = MCPZTConfig.model_validate(
        {
            "project": {"name": "example", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "postgres", "transport": "http", "upstream": "http://localhost:3002/mcp"}
            ],
            "capability_mappings": {
                "postgres": {
                    "tools": {
                        "postgres.query": {
                            "action": "db.read",
                            "risk": "medium",
                            "access": "read",
                        }
                    }
                }
            },
            "policies": [
                {
                    "id": "allow-readonly-sql",
                    "effect": "allow",
                    "match": {"server": "postgres", "action": "db.read"},
                    "validators": [{"name": "sql_read_only"}],
                }
            ],
        }
    )

    visible = filter_capabilities(
        config,
        "postgres",
        "tool",
        [{"name": "postgres.query"}],
    )

    assert visible == [{"name": "postgres.query"}]


def test_list_filtering_does_not_require_call_arguments() -> None:
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
                    "id": "allow-safe-issue-search",
                    "effect": "allow",
                    "match": {
                        "server": "github",
                        "capability_type": "tool",
                        "capability": "github.search_issues",
                    },
                    "input": {
                        "allowed_fields": ["query", "limit"],
                        "required_fields": ["query"],
                    },
                }
            ],
        }
    )

    visible = filter_capabilities(
        config,
        "github",
        "tool",
        [{"name": "github.search_issues"}],
    )

    assert visible == [{"name": "github.search_issues"}]
