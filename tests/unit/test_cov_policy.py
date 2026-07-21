from __future__ import annotations

from mcp_zero_trust_layer.capabilities.discovery import CapabilitySnapshot
from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.policy import (
    PolicyEngine,
    adapters,
    build_policy_coverage,
    find_policy_risks,
)


def _match_failure_config() -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "example", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "capability_mappings": {
                "github": {
                    "tools": {
                        "github.read_tool": {
                            "action": "code.read",
                            "risk": "low",
                            "access": "read",
                            "tags": ["safe"],
                        }
                    }
                }
            },
            "policies": [
                {"id": "p-method", "effect": "allow", "match": {"method": "tools/list"}},
                {"id": "p-caps", "effect": "allow", "match": {"capabilities": ["other.*"]}},
                {"id": "p-user", "effect": "allow", "match": {"user": "bob"}},
                {"id": "p-group", "effect": "allow", "match": {"group": "admins"}},
                {"id": "p-role", "effect": "allow", "match": {"role": "root"}},
                {"id": "p-tags", "effect": "allow", "match": {"tags": ["safe", "extra"]}},
            ],
        }
    )


def _ctx(config: MCPZTConfig, capability: str = "github.read_tool") -> RequestContext:
    return RequestContext(
        server="github",
        method="tools/call",
        capability_type="tool",
        capability=capability,
        identity=Identity(subject="ana", groups=[], roles=[]),
        environment="development",
        config_base_dir=config.config_base_dir,
    )


def test_no_policy_matches_falls_through_to_default() -> None:
    config = _match_failure_config()
    decision = PolicyEngine(config).evaluate(_ctx(config))
    assert decision.decision == "deny"
    assert decision.policy_id is None


def test_explain_computes_all_match_failure_paths() -> None:
    config = _match_failure_config()
    explanation = PolicyEngine(config).explain(_ctx(config))
    # every policy should have failed to match, exercising each failure helper
    assert explanation["matched_policies"] == []
    failures_by_policy = {
        policy["policy_id"]: policy["match"]["failures"]
        for policy in explanation["policies"]
    }
    assert any("method" in f for f in failures_by_policy["p-method"])
    assert any("capabilities" in f for f in failures_by_policy["p-caps"])
    assert any("user" in f for f in failures_by_policy["p-user"])
    assert any("group" in f for f in failures_by_policy["p-group"])
    assert any("role" in f for f in failures_by_policy["p-role"])
    assert any("tags" in f for f in failures_by_policy["p-tags"])


def test_metadata_missing_but_required_fails_match() -> None:
    config = MCPZTConfig.model_validate(
        {
            "project": {"name": "example", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "policies": [
                {"id": "needs-meta", "effect": "allow", "match": {"action": "code.read"}}
            ],
        }
    )
    # capability has no mapping -> metadata is None while match requires action
    decision = PolicyEngine(config).evaluate(_ctx(config, capability="unmapped.tool"))
    assert decision.decision == "deny"
    assert decision.policy_id is None


def test_explain_with_external_opa_adapter(monkeypatch) -> None:
    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"result": {"decision": "allow", "reason": "ok"}}

    monkeypatch.setattr(adapters.httpx, "post", lambda *a, **k: Response())
    config = MCPZTConfig.model_validate(
        {
            "project": {"name": "example", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "policy_engine": {"adapter": "opa", "endpoint": "http://opa.example/decision"},
        }
    )
    explanation = PolicyEngine(config).explain(_ctx(config))
    assert explanation["adapter"] == "opa"
    assert explanation["decision"]["decision"] == "allow"


# --- analysis: snapshot path + default-allow findings ----------------------


def _default_allow_config() -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "example", "environment": "development"},
            "runtime": {"default_decision": "allow"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "policies": [],
        }
    )


def _snapshot() -> CapabilitySnapshot:
    return CapabilitySnapshot(
        server="github",
        discovered_at="2026-01-01T00:00:00Z",
        tools=[{"name": "github.tool_one"}, {"not_name": "ignored"}],
        resources=[{"uri": "res://one"}],
        prompts=[{"name": "prompt_one"}],
    )


def test_coverage_from_snapshot_lists_all_capability_types() -> None:
    config = _default_allow_config()
    report = build_policy_coverage(config, snapshot=_snapshot())
    caps = {(item.capability_type, item.capability) for item in report.items}
    assert ("tool", "github.tool_one") in caps
    assert ("resource", "res://one") in caps
    assert ("prompt", "prompt_one") in caps
    # item lacking the identity key is skipped
    assert all(item.capability != "ignored" for item in report.items)


def test_risks_flag_default_allow_and_unmapped_and_fallthrough() -> None:
    config = _default_allow_config()
    report = find_policy_risks(config, snapshot=_snapshot())
    rule_ids = {finding.rule_id for finding in report.findings}
    assert "default-allow" in rule_ids
    assert "missing-capability-mapping" in rule_ids
    assert "default-allow-decision" in rule_ids
