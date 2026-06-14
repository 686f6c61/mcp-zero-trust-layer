from __future__ import annotations

from typing import Any

INVALID_REQUEST = "Invalid Request"


class JSONRPCError(Exception):
    def __init__(self, code: int, message: str, data: Any | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def is_request(message: dict[str, Any]) -> bool:
    return "method" in message and "id" in message


def is_notification(message: dict[str, Any]) -> bool:
    return "method" in message and "id" not in message


def is_response(message: dict[str, Any]) -> bool:
    return "method" not in message and "id" in message and (
        "result" in message or "error" in message
    )


def success_response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_response(
    request_id: Any | None,
    code: int,
    message: str,
    data: Any | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def require_jsonrpc_message(message: Any) -> dict[str, Any]:
    if not isinstance(message, dict):
        raise JSONRPCError(-32600, INVALID_REQUEST, {"reason": "message must be an object"})
    if message.get("jsonrpc") != "2.0":
        raise JSONRPCError(-32600, INVALID_REQUEST, {"reason": "jsonrpc must be '2.0'"})
    if "id" in message and message["id"] is None:
        raise JSONRPCError(-32600, INVALID_REQUEST, {"reason": "id must not be null"})
    if "method" not in message and "id" not in message:
        raise JSONRPCError(-32600, INVALID_REQUEST, {"reason": "not a JSON-RPC message"})
    return message
