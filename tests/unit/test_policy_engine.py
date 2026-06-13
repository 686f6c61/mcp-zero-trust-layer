from __future__ import annotations

from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.policy import PolicyEngine


def _config() -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "example", "environment": "production"},
            "runtime": {
                "default_decision": "deny",
                "allow_auth_none_in_production": True,
                "public_base_url": "https://mcpzt.example",
            },
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
                            "tags": ["destructive"],
                        },
                    }
                }
            },
            "policies": [
                {
                    "id": "allow-read",
                    "effect": "allow",
                    "match": {"server": "github", "action": "code.read"},
                },
                {
                    "id": "deny-specific",
                    "effect": "deny",
                    "match": {"server": "github", "capability": "github.search_issues"},
                },
                {
                    "id": "critical-approval",
                    "effect": "require_approval",
                    "match": {"server": "github", "risk": "critical"},
                },
            ],
        }
    )


def test_deny_wins_over_allow() -> None:
    decision = PolicyEngine(_config()).evaluate(
        RequestContext(
            server="github",
            method="tools/call",
            capability_type="tool",
            capability="github.search_issues",
            environment="production",
            identity=Identity(subject="ana"),
        )
    )

    assert decision.decision == "deny"
    assert decision.policy_id == "deny-specific"


def test_semantic_risk_can_require_approval() -> None:
    decision = PolicyEngine(_config()).evaluate(
        RequestContext(
            server="github",
            method="tools/call",
            capability_type="tool",
            capability="github.merge_pull_request",
            arguments={"base_branch": "main"},
            environment="production",
            identity=Identity(subject="ana", client_id="cursor"),
        )
    )

    assert decision.decision == "require_approval"
    assert decision.approval_required is True
    assert decision.policy_id == "critical-approval"


def test_validator_failure_blocks_allowed_policy() -> None:
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

    decision = PolicyEngine(config).evaluate(
        RequestContext(
            server="postgres",
            method="tools/call",
            capability_type="tool",
            capability="postgres.query",
            arguments={"query": "delete from users"},
        )
    )

    assert decision.decision == "deny"
    assert decision.policy_id == "allow-readonly-sql"
    assert decision.validation_errors


def test_input_policy_blocks_unexpected_fields() -> None:
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
                        "max_field_bytes": {"query": 128},
                        "max_list_items": {"labels": 3},
                    },
                }
            ],
        }
    )

    decision = PolicyEngine(config).evaluate(
        RequestContext(
            server="github",
            method="tools/call",
            capability_type="tool",
            capability="github.search_issues",
            arguments={"query": "is:open", "token": "secret"},
        )
    )

    assert decision.decision == "deny"
    assert decision.policy_id == "allow-safe-issue-search"
    assert "field 'token' is not allowed" in decision.validation_errors


def test_explain_reports_matched_and_discarded_policies() -> None:
    explanation = PolicyEngine(_config()).explain(
        RequestContext(
            server="github",
            method="tools/call",
            capability_type="tool",
            capability="github.merge_pull_request",
            environment="production",
            identity=Identity(subject="ana"),
        )
    )

    assert explanation["decision"]["decision"] == "require_approval"
    assert explanation["selected_policy_id"] == "critical-approval"
    assert "critical-approval" in explanation["matched_policies"]
    assert any(
        policy["policy_id"] == "deny-specific" and not policy["matched"]
        for policy in explanation["policies"]
    )


def test_opa_adapter_decision(monkeypatch) -> None:
    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {
                "result": {
                    "decision": "require_approval",
                    "policy_id": "opa-critical",
                    "reason": "OPA says so",
                }
            }

    captured: dict[str, object] = {}

    def fake_post(url: str, json: dict[str, object], timeout: float) -> Response:
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("mcp_zero_trust_layer.policy.adapters.httpx.post", fake_post)
    data = _config().model_dump()
    data["policy_engine"] = {
        "adapter": "opa",
        "endpoint": "http://opa.example/v1/data/mcpzt/decision",
    }
    data["runtime"]["dry_run"] = True
    data["runtime"]["allow_dry_run_in_production"] = True
    config = MCPZTConfig.model_validate(data)

    decision = PolicyEngine(config).evaluate(
        RequestContext(
            server="github",
            method="tools/call",
            capability_type="tool",
            capability="github.merge_pull_request",
            environment="production",
            identity=Identity(subject="ana"),
        )
    )

    assert decision.decision == "require_approval"
    assert decision.dry_run is True
    assert decision.policy_id == "opa-critical"
    assert captured["url"] == "http://opa.example/v1/data/mcpzt/decision"
