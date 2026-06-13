from __future__ import annotations

import pytest

from mcp_zero_trust_layer.protocol.jsonrpc import JSONRPCError, require_jsonrpc_message


def test_rejects_null_id() -> None:
    with pytest.raises(JSONRPCError, match="Invalid Request"):
        require_jsonrpc_message({"jsonrpc": "2.0", "id": None, "method": "tools/list"})


def test_accepts_notification_without_id() -> None:
    message = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    assert require_jsonrpc_message(message) == message

