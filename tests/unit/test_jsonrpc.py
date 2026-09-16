from __future__ import annotations

import pytest

from mcp_zero_trust_layer.protocol.jsonrpc import JSONRPCError, require_jsonrpc_message


def test_rejects_null_id() -> None:
    with pytest.raises(JSONRPCError, match="Invalid Request"):
        require_jsonrpc_message({"jsonrpc": "2.0", "id": None, "method": "tools/list"})


def test_accepts_notification_without_id() -> None:
    message = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    assert require_jsonrpc_message(message) == message


@pytest.mark.parametrize(
    "payload",
    [
        {"id": 1},
        {"method": "ping", "id": True},
        {"method": "ping", "id": 1.5},
        {"method": "ping", "id": []},
        {"method": "ping", "id": {}},
        {"method": []},
        {"method": None},
        {"method": ""},
        {"method": "ping", "params": []},
        {"method": "ping", "params": None},
        {"method": "ping", "params": "text"},
        {"method": "ping", "result": {}},
        {"method": "ping", "error": {}},
        {"id": 1, "result": {}, "error": {"code": -1, "message": "failed"}},
        {"result": {}},
        {"id": 1, "result": "not an MCP result"},
        {"id": 1, "result": {}, "params": {}},
        {"id": 1, "error": "failed"},
        {"id": 1, "error": {"code": True, "message": "failed"}},
        {"id": 1, "error": {"code": 1.1, "message": "failed"}},
        {"id": 1, "error": {"code": -1, "message": []}},
        {"id": 1, "error": {}},
    ],
)
def test_invalid_mcp_envelopes_fail_before_dispatch(payload: dict) -> None:
    with pytest.raises(JSONRPCError) as exc:
        require_jsonrpc_message({"jsonrpc": "2.0", **payload})
    assert exc.value.code == -32600


@pytest.mark.parametrize(
    "payload",
    [
        {"id": 0, "method": "ping", "params": {}},
        {"id": "", "method": "ping"},
        {"method": "notifications/initialized", "params": {}},
        {"id": "response", "result": {"content": []}},
        {"error": {"code": -32700, "message": "Parse error"}},
        {"id": -1, "error": {"code": -32603, "message": "failed", "data": [1, 2]}},
    ],
)
def test_valid_request_notification_response_and_error(payload: dict) -> None:
    message = {"jsonrpc": "2.0", **payload}
    assert require_jsonrpc_message(message) is message
