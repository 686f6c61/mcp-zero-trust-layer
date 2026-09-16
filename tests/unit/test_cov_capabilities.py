from __future__ import annotations

from typing import Any

import pytest

from mcp_zero_trust_layer.capabilities.discovery import (
    CapabilitySnapshot,
    default_snapshot_path,
    discover_capabilities,
    read_snapshot,
    write_snapshot,
)
from mcp_zero_trust_layer.capabilities.mapping import lookup_capability_metadata
from mcp_zero_trust_layer.capabilities.onboarding import (
    _infer_risk,
    _policy_slug,
    _resource_type,
    build_onboard_config,
    infer_capability_metadata,
    parse_server_specs,
)
from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.core import RequestContext


def _config() -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
        }
    )


class FakeUpstream:
    def __init__(self, responses: dict[str, Any]):
        self.responses = responses
        self.calls: list[str] = []

    def send(self, server, message, *, headers=None):
        self.calls.append(message["method"])
        value = self.responses.get(message["method"])
        if isinstance(value, Exception):
            raise value
        return value


# ---- discovery ----


def test_discover_capabilities_full_flow() -> None:
    upstream = FakeUpstream(
        {
            "initialize": {"result": {"protocolVersion": "2025-03-26", "capabilities": {}}},
            "notifications/initialized": None,
            "tools/list": {"result": {"tools": [{"name": "t1"}]}},
            "resources/list": {"result": {"resources": [{"uri": "r1"}]}},
            "prompts/list": {"result": {"prompts": [{"name": "p1"}]}},
        }
    )
    snapshot = discover_capabilities(_config(), "github", upstream)
    assert snapshot.tools == [{"name": "t1"}]
    assert snapshot.resources == [{"uri": "r1"}]
    assert snapshot.prompts == [{"name": "p1"}]
    assert snapshot.errors == {}


def test_discover_capabilities_non_list_items_skipped() -> None:
    upstream = FakeUpstream(
        {
            "initialize": {"result": {"protocolVersion": "2025-03-26"}},
            "notifications/initialized": None,
            "tools/list": {"result": {"tools": "not-a-list"}},
            "resources/list": None,
            "prompts/list": {"error": {"code": -1}},
        }
    )
    snapshot = discover_capabilities(_config(), "github", upstream)
    assert snapshot.tools == []


def test_discover_capabilities_loop_send_error() -> None:
    upstream = FakeUpstream(
        {
            "initialize": {"result": {"protocolVersion": "2025-03-26"}},
            "notifications/initialized": None,
            "tools/list": RuntimeError("boom"),
            "resources/list": {"result": {"resources": []}},
            "prompts/list": {"result": {"prompts": []}},
        }
    )
    snapshot = discover_capabilities(_config(), "github", upstream)
    assert "boom" in snapshot.errors["tools"]


def test_discover_initialize_error_response() -> None:
    upstream = FakeUpstream(
        {
            "initialize": {"error": {"code": -32000, "message": "no"}},
            "tools/list": {"result": {"tools": []}},
            "resources/list": {"result": {"resources": []}},
            "prompts/list": {"result": {"prompts": []}},
        }
    )
    snapshot = discover_capabilities(_config(), "github", upstream)
    assert "initialize" in snapshot.errors
    assert "notifications/initialized" not in upstream.calls


def test_discover_initialize_raises() -> None:
    upstream = FakeUpstream(
        {
            "initialize": RuntimeError("init-fail"),
            "tools/list": {"result": {"tools": []}},
            "resources/list": {"result": {"resources": []}},
            "prompts/list": {"result": {"prompts": []}},
        }
    )
    snapshot = discover_capabilities(_config(), "github", upstream)
    assert "init-fail" in snapshot.errors["initialize"]


def test_discover_initialized_notification_raises() -> None:
    upstream = FakeUpstream(
        {
            "initialize": {"result": {"protocolVersion": "2025-03-26"}},
            "notifications/initialized": RuntimeError("notif-fail"),
            "tools/list": {"result": {"tools": []}},
            "resources/list": {"result": {"resources": []}},
            "prompts/list": {"result": {"prompts": []}},
        }
    )
    snapshot = discover_capabilities(_config(), "github", upstream)
    assert "notif-fail" in snapshot.errors["initialized"]


def test_discover_unknown_server() -> None:
    with pytest.raises(ValueError, match="unknown server"):
        discover_capabilities(_config(), "nope", FakeUpstream({}))


def test_write_and_read_snapshot(tmp_path) -> None:
    snapshot = CapabilitySnapshot(server="github", discovered_at="2026-01-01T00:00:00Z")
    path = tmp_path / "sub" / "github.json"
    write_snapshot(snapshot, path)
    loaded = read_snapshot(path)
    assert loaded.server == "github"


def test_default_snapshot_path() -> None:
    assert default_snapshot_path("github").name == "github.json"


# ---- mapping ----


def _mapping_config() -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "capability_mappings": {
                "github": {
                    "tools": {"t1": {"risk": "low"}},
                    "resources": {"r1": {"risk": "medium"}},
                    "prompts": {"p1": {"risk": "high"}},
                }
            },
        }
    )


def test_lookup_no_capability() -> None:
    ctx = RequestContext(server="github", method="tools/call", capability_type="tool")
    assert lookup_capability_metadata(_mapping_config(), ctx) is None


def test_lookup_unknown_server() -> None:
    ctx = RequestContext(
        server="other", method="tools/call", capability_type="tool", capability="t1"
    )
    assert lookup_capability_metadata(_mapping_config(), ctx) is None


def test_lookup_tool_resource_prompt_and_method() -> None:
    config = _mapping_config()
    tool_ctx = RequestContext(
        server="github", method="tools/call", capability_type="tool", capability="t1"
    )
    resource_ctx = RequestContext(
        server="github", method="resources/read", capability_type="resource", capability="r1"
    )
    prompt_ctx = RequestContext(
        server="github", method="prompts/get", capability_type="prompt", capability="p1"
    )
    method_ctx = RequestContext(
        server="github", method="ping", capability_type="method", capability="x"
    )
    assert lookup_capability_metadata(config, tool_ctx).risk == "low"
    assert lookup_capability_metadata(config, resource_ctx).risk == "medium"
    assert lookup_capability_metadata(config, prompt_ctx).risk == "high"
    assert lookup_capability_metadata(config, method_ctx) is None


# ---- onboarding ----


def _onboard_config() -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "onboard", "environment": "development"},
            "runtime": {"mode": "gateway", "default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
        }
    )


def test_parse_server_specs_missing_equals() -> None:
    with pytest.raises(ValueError, match="name=url"):
        parse_server_specs(["invalid"])


def test_parse_server_specs_empty_parts() -> None:
    with pytest.raises(ValueError, match="both a name and an upstream"):
        parse_server_specs(["=http://x"])


def test_build_onboard_config_sql_policies_and_dedupe() -> None:
    snapshot = CapabilitySnapshot(
        server="github",
        discovered_at="2026-01-01T00:00:00Z",
        tools=[{"name": "postgres_query", "description": "run a sql query"}],
    )
    # Two identical snapshots for the same server force policy-id deduplication.
    result = build_onboard_config(_onboard_config(), [snapshot, snapshot])
    assert any("read-only-sql" in pid for pid in result.report.generated_policies)
    assert len(result.report.generated_policies) == len(set(result.report.generated_policies))


def test_build_onboard_config_recommends_on_errors() -> None:
    snapshot = CapabilitySnapshot(
        server="github",
        discovered_at="2026-01-01T00:00:00Z",
        errors={"tools": "failed"},
    )
    result = build_onboard_config(_onboard_config(), [snapshot])
    assert any("returned errors" in rec for rec in result.report.recommendations)


def test_infer_metadata_non_tool_is_read() -> None:
    metadata = infer_capability_metadata("file://x", capability_type="resources")
    assert metadata.access == "read"


def test_infer_access_execute_admin_write() -> None:
    execute = infer_capability_metadata("exec_shell", capability_type="tools")
    admin = infer_capability_metadata("admin_panel", capability_type="tools")
    write = infer_capability_metadata("update_record", capability_type="tools")
    neutral = infer_capability_metadata("noop", capability_type="tools")
    assert execute.access == "execute"
    assert admin.access == "admin"
    assert write.access == "write"
    assert neutral.access == "read"


def test_infer_risk_direct_branches() -> None:
    # access value outside the early-return set exercises the trailing fallbacks.
    assert _infer_risk("customer data", "custom") == "medium"
    assert _infer_risk("list things", "custom") == "low"
    assert _infer_risk("zzz", "custom") == "medium"


def test_resource_type_branches() -> None:
    assert _resource_type("x", "github repo pull_request") == "repository"
    assert _resource_type("x", "customer crm contact") == "customer"
    assert _resource_type("x", "payment invoice") == "payment"
    assert _resource_type("foo.bar", "nothing special") == "bar"
    assert _resource_type("123", "999 000") == "capability"


def test_policy_slug() -> None:
    assert _policy_slug("My Tool!") == "my-tool"
    assert _policy_slug("!!!") == "capability"
