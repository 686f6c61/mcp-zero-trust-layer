from __future__ import annotations

import json
from typing import Any, NoReturn

INVALID_REQUEST = "Invalid Request"


def strict_json_loads(data: str | bytes) -> Any:
    """Reject ambiguous JSON at ingress, before a parser can discard duplicate keys."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in items:
            if key in value:
                raise json.JSONDecodeError("duplicate key", "", 0)
            value[key] = child
        return value

    def constant(value: str) -> NoReturn:
        raise json.JSONDecodeError("nonfinite number", "", 0)

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except RecursionError as exc:
        raise json.JSONDecodeError("nesting limit", "", 0) from exc


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
    return "method" not in message and (
        ("id" in message and "result" in message) or "error" in message
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
    """Validate MCP's JSON-RPC envelope before classification or policy evaluation."""

    def invalid(reason: str) -> NoReturn:
        raise JSONRPCError(-32600, INVALID_REQUEST, {"reason": reason})

    if not isinstance(message, dict):
        invalid("message must be an object")
    if message.get("jsonrpc") != "2.0":
        invalid("jsonrpc must be '2.0'")
    if "id" in message and (type(message["id"]) not in (str, int)):
        invalid("id must be a non-null string or integer")

    if "method" in message:
        if not isinstance(message["method"], str) or not message["method"]:
            invalid("method must be a non-empty string")
        if "result" in message or "error" in message:
            invalid("requests and notifications must not contain result or error")
        if "params" in message and not isinstance(message["params"], dict):
            invalid("MCP params must be an object")
    else:
        if "result" in message and "id" not in message:
            invalid("result responses require an id")
        if ("result" in message) == ("error" in message):
            invalid("responses require exactly one of result or error")
        if "params" in message:
            invalid("responses must not contain params")
        if "result" in message and not isinstance(message["result"], dict):
            invalid("MCP result must be an object")
        if "error" in message:
            error = message["error"]
            if not isinstance(error, dict):
                invalid("error must be an object")
            if type(error.get("code")) is not int or not isinstance(error.get("message"), str):
                invalid("error requires an integer code and a string message")
    return message
