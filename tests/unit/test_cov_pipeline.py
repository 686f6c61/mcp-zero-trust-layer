from __future__ import annotations

from typing import Any

from mcp_zero_trust_layer.config.models import MCPZTConfig, ServerConfig
from mcp_zero_trust_layer.core.pipeline import (
    MCPPipeline,
    _extract_approval_id,
    _strip_approval_id,
)
from mcp_zero_trust_layer.identity import Identity


class ConfigurableUpstream:
    def __init__(self, default: Any = "echo", by_method: dict[str, Any] | None = None) -> None:
        self.default = default
        self.by_method = by_method or {}
        self.messages: list[dict[str, Any]] = []

    def send(
        self,
        server: ServerConfig,
        message: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        self.messages.append(message)
        method = message.get("method")
        if method in self.by_method:
            return self.by_method[method]
        if self.default == "echo":
            if "id" not in message:
                return None
            return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}
        return self.default


def _config(policies: list[dict[str, Any]], **runtime: Any) -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "pipeline-cov", "environment": "development"},
            "runtime": {"default_decision": "deny", **runtime},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://upstream.example/mcp"}
            ],
            "policies": policies,
            "audit": {"destination": "stdout"},
        }
    )


def _allow(policy_id: str, match: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"id": policy_id, "effect": "allow", "match": {"server": "github", **match}, **extra}


IDENTITY = Identity(subject="ana")


def test_unsolicited_response_is_rejected_before_upstream() -> None:
    upstream = ConfigurableUpstream()
    pipeline = MCPPipeline(_config([]), upstream)
    result = pipeline.handle(
        "github", {"jsonrpc": "2.0", "id": 5, "result": {"data": 1}}, identity=IDENTITY
    )
    assert upstream.messages == []
    assert result["error"]["code"] == -32600


def test_invalid_message_without_method_is_rejected() -> None:
    upstream = ConfigurableUpstream(by_method={None: {"jsonrpc": "2.0", "id": 9, "result": {}}})
    pipeline = MCPPipeline(_config([]), upstream)
    result = pipeline.handle("github", {"jsonrpc": "2.0", "id": 9}, identity=IDENTITY)
    assert result["error"]["code"] == -32600
    assert upstream.messages == []


def test_handle_unknown_server_returns_error() -> None:
    pipeline = MCPPipeline(_config([]), ConfigurableUpstream())
    result = pipeline.handle(
        "nope", {"jsonrpc": "2.0", "id": 1, "method": "ping"}, identity=IDENTITY
    )
    assert result is not None
    assert result["error"]["code"] == -32004


def test_other_request_denied_by_default() -> None:
    upstream = ConfigurableUpstream()
    pipeline = MCPPipeline(_config([]), upstream)
    result = pipeline.handle(
        "github", {"jsonrpc": "2.0", "id": 1, "method": "ping"}, identity=IDENTITY
    )
    assert result is not None
    assert result["error"]["code"] == -32001
    assert upstream.messages == []


def test_other_request_allowed_and_forwarded() -> None:
    upstream = ConfigurableUpstream(
        by_method={"ping": {"jsonrpc": "2.0", "id": 1, "result": {"pong": True}}}
    )
    policies = [_allow("allow-ping", {"capability_type": "method", "capability": "ping"})]
    pipeline = MCPPipeline(_config(policies), upstream)
    result = pipeline.handle(
        "github", {"jsonrpc": "2.0", "id": 1, "method": "ping"}, identity=IDENTITY
    )
    assert result == {"jsonrpc": "2.0", "id": 1, "result": {"pong": True}}


def test_other_request_allowed_but_upstream_returns_none() -> None:
    upstream = ConfigurableUpstream(by_method={"ping": None})
    policies = [_allow("allow-ping", {"capability_type": "method", "capability": "ping"})]
    pipeline = MCPPipeline(_config(policies), upstream)
    result = pipeline.handle(
        "github", {"jsonrpc": "2.0", "id": 1, "method": "ping"}, identity=IDENTITY
    )
    assert result is not None
    assert result["error"]["code"] == -32603


def test_list_request_denied_with_policy_id() -> None:
    upstream = ConfigurableUpstream()
    policies = [
        {
            "id": "deny-tools-list",
            "effect": "deny",
            "match": {"server": "github", "capability_type": "method", "capability": "tools/list"},
        }
    ]
    pipeline = MCPPipeline(_config(policies), upstream)
    result = pipeline.handle(
        "github", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, identity=IDENTITY
    )
    assert result is not None
    assert result["error"]["code"] == -32001
    assert upstream.messages == []


def _allow_tools_list() -> list[dict[str, Any]]:
    return [_allow("allow-list", {"capability_type": "method", "capability": "tools/list"})]


def test_list_request_upstream_none() -> None:
    upstream = ConfigurableUpstream(by_method={"tools/list": None})
    pipeline = MCPPipeline(_config(_allow_tools_list()), upstream)
    result = pipeline.handle(
        "github", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, identity=IDENTITY
    )
    assert result is not None
    assert result["error"]["code"] == -32603


def test_list_response_without_result_is_passed_through() -> None:
    error_resp = {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"}}
    upstream = ConfigurableUpstream(by_method={"tools/list": error_resp})
    pipeline = MCPPipeline(_config(_allow_tools_list()), upstream)
    result = pipeline.handle(
        "github", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, identity=IDENTITY
    )
    assert result == error_resp


def test_list_response_with_non_dict_result_is_passed_through() -> None:
    resp = {"jsonrpc": "2.0", "id": 1, "result": "not-a-dict"}
    upstream = ConfigurableUpstream(by_method={"tools/list": resp})
    pipeline = MCPPipeline(_config(_allow_tools_list()), upstream)
    result = pipeline.handle(
        "github", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, identity=IDENTITY
    )
    assert result == resp


def test_list_response_with_non_list_items_is_passed_through() -> None:
    resp = {"jsonrpc": "2.0", "id": 1, "result": {"tools": "not-a-list"}}
    upstream = ConfigurableUpstream(by_method={"tools/list": resp})
    pipeline = MCPPipeline(_config(_allow_tools_list()), upstream)
    result = pipeline.handle(
        "github", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, identity=IDENTITY
    )
    assert result == resp


def test_call_allowed_upstream_none() -> None:
    upstream = ConfigurableUpstream(by_method={"tools/call": None})
    policies = [
        _allow("allow-call", {"capability_type": "tool", "capability": "github.safe"}),
    ]
    pipeline = MCPPipeline(_config(policies), upstream)
    result = pipeline.handle(
        "github",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "github.safe", "arguments": {}},
        },
        identity=IDENTITY,
    )
    assert result is not None
    assert result["error"]["code"] == -32603


def test_call_output_without_result_or_error_passes_through() -> None:
    weird = {"jsonrpc": "2.0", "id": 1, "misc": True}
    upstream = ConfigurableUpstream(by_method={"tools/call": weird})
    policies = [_allow("allow-call", {"capability_type": "tool", "capability": "github.safe"})]
    pipeline = MCPPipeline(_config(policies), upstream)
    result = pipeline.handle(
        "github",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "github.safe", "arguments": {}},
        },
        identity=IDENTITY,
    )
    assert result == weird


def test_call_output_denied_by_output_policy() -> None:
    call_resp = {"jsonrpc": "2.0", "id": 1, "result": {"data": {"email": "a@b.com"}}}
    upstream = ConfigurableUpstream(by_method={"tools/call": call_resp})
    policies = [
        _allow("allow-call", {"capability_type": "tool", "capability": "github.safe"}),
        {
            "id": "deny-output-email",
            "effect": "deny",
            "match": {
                "server": "github",
                "capability_type": "tool",
                "capability": "github.safe",
            },
            "when": {"output.data.email": {"exists": True}},
        },
    ]
    pipeline = MCPPipeline(_config(policies), upstream)
    result = pipeline.handle(
        "github",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "github.safe", "arguments": {}},
        },
        identity=IDENTITY,
    )
    assert result is not None
    assert result["error"]["code"] == -32020


def test_call_output_redact_enforcer_blocks() -> None:
    call_resp = {"jsonrpc": "2.0", "id": 1, "result": {"content": "SUPERSECRET token here"}}
    upstream = ConfigurableUpstream(by_method={"tools/call": call_resp})
    policies = [
        _allow("allow-call", {"capability_type": "tool", "capability": "github.safe"}),
        {
            "id": "limit-output",
            "effect": "redact",
            "match": {
                "server": "github",
                "capability_type": "tool",
                "capability": "github.safe",
            },
            "when": {"output.content": {"exists": True}},
            "output": {"deny_if_matches": ["SUPERSECRET"]},
        },
    ]
    pipeline = MCPPipeline(_config(policies), upstream)
    result = pipeline.handle(
        "github",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "github.safe", "arguments": {}},
        },
        identity=IDENTITY,
    )
    assert result is not None
    assert result["error"]["code"] == -32020


def test_resources_read_uses_params_as_arguments() -> None:
    read_resp = {"jsonrpc": "2.0", "id": 1, "result": {"contents": []}}
    upstream = ConfigurableUpstream(by_method={"resources/read": read_resp})
    policies = [
        _allow("allow-read", {"capability_type": "resource", "capability": "file:///safe.md"}),
    ]
    pipeline = MCPPipeline(_config(policies), upstream)
    result = pipeline.handle(
        "github",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {"uri": "file:///safe.md", "_mcpzt_approval_id": "x"},
        },
        identity=IDENTITY,
    )
    assert result == read_resp


def test_notification_allowed_non_safe_is_forwarded() -> None:
    upstream = ConfigurableUpstream(by_method={"custom/notify": None})
    policies = [_allow("allow-notify", {"capability_type": "method", "capability": "custom/notify"})]
    pipeline = MCPPipeline(_config(policies), upstream)
    result = pipeline.handle(
        "github",
        {"jsonrpc": "2.0", "method": "custom/notify", "params": {}},
        identity=IDENTITY,
    )
    assert result is None
    assert upstream.messages[0]["method"] == "custom/notify"


# ---------------------------------------------------------------------------
# module-level approval id helpers
# ---------------------------------------------------------------------------


def test_extract_approval_id_variants() -> None:
    assert _extract_approval_id({"params": "not-a-dict"}) is None
    assert _extract_approval_id({}) is None
    assert _extract_approval_id({"params": {"_mcpzt_approval_id": "direct"}}) == "direct"
    assert (
        _extract_approval_id({"params": {"arguments": {"_mcpzt_approval_id": "nested"}}})
        == "nested"
    )
    assert _extract_approval_id({"params": {"arguments": {}}}) is None


def test_strip_approval_id_variants() -> None:
    assert _strip_approval_id({"params": "not-a-dict"}) == {"params": "not-a-dict"}
    stripped = _strip_approval_id(
        {"params": {"_mcpzt_approval_id": "x", "arguments": {"_mcpzt_approval_id": "y", "a": 1}}}
    )
    assert "_mcpzt_approval_id" not in stripped["params"]
    assert stripped["params"]["arguments"] == {"a": 1}
