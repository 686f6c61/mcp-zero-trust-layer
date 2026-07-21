from __future__ import annotations

import pytest

from mcp_zero_trust_layer.protocol import (
    JSONRPCError,
    error_response,
    is_notification,
    is_request,
    is_response,
    success_response,
)
from mcp_zero_trust_layer.protocol.jsonrpc import require_jsonrpc_message


def test_message_classification() -> None:
    assert is_request({"method": "x", "id": 1})
    assert is_notification({"method": "x"})
    assert is_response({"id": 1, "result": {}})
    assert not is_response({"id": 1})


def test_success_and_error_response() -> None:
    assert success_response(7, {"ok": True}) == {
        "jsonrpc": "2.0",
        "id": 7,
        "result": {"ok": True},
    }
    without_data = error_response(1, -32000, "boom")
    assert "data" not in without_data["error"]
    with_data = error_response(1, -32000, "boom", {"k": "v"})
    assert with_data["error"]["data"] == {"k": "v"}


def test_require_jsonrpc_rejects_non_dict() -> None:
    with pytest.raises(JSONRPCError) as exc:
        require_jsonrpc_message(["not", "a", "dict"])
    assert exc.value.code == -32600


def test_require_jsonrpc_rejects_wrong_version() -> None:
    with pytest.raises(JSONRPCError) as exc:
        require_jsonrpc_message({"jsonrpc": "1.0", "id": 1, "method": "x"})
    assert exc.value.code == -32600


def test_require_jsonrpc_rejects_null_id() -> None:
    with pytest.raises(JSONRPCError):
        require_jsonrpc_message({"jsonrpc": "2.0", "id": None, "method": "x"})


def test_require_jsonrpc_rejects_message_without_method_or_id() -> None:
    with pytest.raises(JSONRPCError) as exc:
        require_jsonrpc_message({"jsonrpc": "2.0"})
    assert exc.value.code == -32600


def test_require_jsonrpc_accepts_valid_message() -> None:
    message = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert require_jsonrpc_message(message) is message
