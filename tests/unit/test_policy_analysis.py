from __future__ import annotations

from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.policy import (
    build_policy_coverage,
    find_policy_risks,
    find_unused_policies,
)


def _config() -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "analysis-test", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "capability_mappings": {
                "github": {
                    "tools": {
                        "github.search_issues": {
                            "action": "code.read",
                            "risk": "low",
                            "access": "read",
                        },
                        "github.merge_pull_request": {
                            "action": "code.merge",
                            "risk": "critical",
                            "access": "write",
                        },
                    }
                }
            },
            "policies": [
                {
                    "id": "allow-search",
                    "effect": "allow",
                    "match": {"server": "github", "capability": "github.search_issues"},
                },
                {
                    "id": "allow-merge-too-broad",
                    "effect": "allow",
                    "match": {"server": "github", "capability": "github.merge_pull_request"},
                },
                {
                    "id": "unused-policy",
                    "effect": "deny",
                    "match": {"server": "github", "capability": "github.delete_repository"},
                },
            ],
            "audit": {"destination": "file", "path": "./audit.jsonl"},
        }
    )


def test_policy_coverage_reports_decisions() -> None:
    report = build_policy_coverage(_config())

    decisions = {item.capability: item.decision for item in report.items}

    assert decisions["github.search_issues"] == "allow"
    assert decisions["github.merge_pull_request"] == "allow"


def test_policy_risks_flags_critical_direct_allow() -> None:
    report = find_policy_risks(_config())

    assert any(finding.rule_id == "high-risk-direct-allow" for finding in report.findings)
    assert report.failed is True


def test_unused_policies_reports_unmatched_capability_policy() -> None:
    report = find_unused_policies(_config())

    assert [policy.policy_id for policy in report.policies] == ["unused-policy"]
