from __future__ import annotations

import yaml

from mcp_zero_trust_layer.capabilities.discovery import CapabilitySnapshot
from mcp_zero_trust_layer.capabilities.onboarding import (
    build_onboard_config,
    infer_capability_metadata,
    parse_server_specs,
)
from mcp_zero_trust_layer.config.models import MCPZTConfig


def _base_config() -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "onboard-test", "environment": "development"},
            "runtime": {"mode": "gateway", "default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "policies": [],
            "audit": {"destination": "file", "path": "./audit.jsonl"},
        }
    )


def test_infer_capability_metadata_classifies_destructive_tool() -> None:
    metadata = infer_capability_metadata(
        "github.delete_repository",
        capability_type="tools",
        item={"description": "Delete a repository"},
    )

    assert metadata.risk == "critical"
    assert metadata.access == "delete"
    assert "destructive" in metadata.tags


def test_infer_capability_metadata_uses_mcp_annotations() -> None:
    read_metadata = infer_capability_metadata(
        "batch_get",
        capability_type="tools",
        item={"annotations": {"readOnlyHint": True}, "description": "Read objects"},
    )
    write_metadata = infer_capability_metadata(
        "batch_design",
        capability_type="tools",
        item={"annotations": {"destructiveHint": True}, "description": "Modify pencil documents"},
    )

    assert read_metadata.access == "read"
    assert read_metadata.risk == "low"
    assert write_metadata.access == "write"
    assert write_metadata.risk == "high"
    assert "side-effect" in write_metadata.tags


def test_build_onboard_config_generates_mappings_and_policies() -> None:
    snapshot = CapabilitySnapshot(
        server="github",
        discovered_at="2026-06-14T10:00:00Z",
        tools=[
            {"name": "github.search_issues", "description": "Search issues"},
            {"name": "github.merge_pull_request", "description": "Merge a pull request"},
        ],
        resources=[],
        prompts=[],
    )

    result = build_onboard_config(_base_config(), [snapshot])
    parsed = yaml.safe_load(result.config_yaml)

    assert "github.search_issues" in parsed["capability_mappings"]["github"]["tools"]
    assert "github-critical-needs-approval" in result.report.generated_policies
    assert result.report.servers[0].tools == 2


def test_parse_server_specs_builds_http_servers() -> None:
    servers = parse_server_specs(["github=http://localhost:3001/mcp"])

    assert servers[0].name == "github"
    assert servers[0].transport == "http"
    assert servers[0].upstream == "http://localhost:3001/mcp"
