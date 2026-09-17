from __future__ import annotations

import json
import threading
from typing import Any

import httpx

from mcp_zero_trust_layer.audit import redact_sensitive
from mcp_zero_trust_layer.config.models import ServerConfig
from mcp_zero_trust_layer.config.secrets import SecretError, resolve_secret_value
from mcp_zero_trust_layer.protocol import JSONRPCError
from mcp_zero_trust_layer.protocol.jsonrpc import require_jsonrpc_message, strict_json_loads

FORWARDED_HEADERS = {
    "accept",
    "content-type",
    "mcp-protocol-version",
}
MAX_ERROR_BODY_BYTES = 4096


class HTTPUpstreamClient:
    def __init__(self) -> None:
        # Only gateway/discovery-generated internal scopes may retain sessions.
        # Public session headers are never forwarded or used as cache keys.
        self._session_ids: dict[tuple[str, str], str] = {}
        self._session_lock = threading.Lock()
        self._active_sessions: set[tuple[str, str]] = set()

    def send(
        self,
        server: ServerConfig,
        message: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        if not server.upstream:
            raise JSONRPCError(-32603, "HTTP upstream is not configured")
        inbound = headers or {}
        forwarded_headers = _forwarded_headers(inbound)
        forwarded_headers.update(_configured_upstream_headers(server))
        forwarded_headers.setdefault("accept", "application/json, text/event-stream")
        forwarded_headers.setdefault("content-type", "application/json")
        session_key = (server.name, _downstream_session(inbound))
        with self._session_lock:
            cached_session = self._session_ids.get(session_key)
        if cached_session:
            forwarded_headers["mcp-session-id"] = cached_session
        try:
            with httpx.Client(timeout=server.timeout) as client, client.stream(
                "POST",
                server.upstream,
                json=message,
                headers=forwarded_headers,
            ) as response:
                if response.headers.get("content-type", "").split(";", 1)[0] == "text/event-stream":
                    raise JSONRPCError(-32603, "Upstream SSE is not supported; configure JSON responses")
                content = _read_response_content(response, server)
                if session_key[1] and response.status_code < 400 and (session_id := response.headers.get("mcp-session-id")):
                    with self._session_lock:
                        if session_key in self._active_sessions:
                            self._session_ids[session_key] = session_id
        except httpx.TimeoutException as exc:
            raise JSONRPCError(-32002, "Upstream timeout", {"server": server.name}) from exc
        except httpx.HTTPError as exc:
            raise JSONRPCError(-32003, "Upstream HTTP error", {"error": str(exc)}) from exc

        if response.status_code >= 400:
            raise JSONRPCError(
                -32003,
                "Upstream HTTP error",
                {
                    "status_code": response.status_code,
                    "body": _safe_error_body(content),
                },
            )
        if response.status_code == 202 or not content:
            return None
        if "id" not in message:
            raise JSONRPCError(-32603, "Upstream returned a response to a notification")
        try:
            payload = strict_json_loads(content)
        except ValueError as exc:
            raise JSONRPCError(-32603, "Invalid upstream JSON response") from exc
        try:
            require_jsonrpc_message(payload)
        except JSONRPCError as exc:
            raise JSONRPCError(-32603, "Invalid upstream JSON-RPC response") from exc
        if payload.get("jsonrpc") != "2.0" or payload.get("id") != message.get("id") or type(payload.get("id")) is not type(message.get("id")) or ("result" in payload) == ("error" in payload):
            raise JSONRPCError(-32603, "Invalid or uncorrelated upstream JSON-RPC response")
        return payload

    def register_session(self, server: str, session_key: str) -> None:
        with self._session_lock:
            self._active_sessions.add((server, session_key))

    def forget_session(self, server: str, session_key: str) -> None:
        with self._session_lock:
            self._session_ids.pop((server, session_key), None)
            self._active_sessions.discard((server, session_key))


def _downstream_session(headers: dict[str, str]) -> str:
    for key, value in headers.items():
        if key.lower() == "x-mcpzt-session-key":
            return value
    return ""


def _forwarded_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key.lower(): value
        for key, value in headers.items()
        if key.lower() in FORWARDED_HEADERS
    }


def _configured_upstream_headers(server: ServerConfig) -> dict[str, str]:
    configured: dict[str, str] = {}
    for key, value in server.upstream_headers.items():
        try:
            configured[key.lower()] = resolve_secret_value(
                value,
                field=f"servers.{server.name}.upstream_headers.{key}",
            )
        except SecretError as exc:
            raise JSONRPCError(-32031, "Upstream secret is not configured", {"error": str(exc)}) from exc
    return configured


def _read_response_content(response: httpx.Response, server: ServerConfig) -> bytes:
    content_length = response.headers.get("content-length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError:
            declared_length = None
        if declared_length is not None and declared_length > server.max_response_bytes:
            raise JSONRPCError(
                -32032,
                "Upstream response too large",
                {"server": server.name, "max_response_bytes": server.max_response_bytes},
            )

    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > server.max_response_bytes:
            raise JSONRPCError(
                -32032,
                "Upstream response too large",
                {"server": server.name, "max_response_bytes": server.max_response_bytes},
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _safe_error_body(content: bytes) -> Any:
    truncated = content[:MAX_ERROR_BODY_BYTES]
    try:
        parsed: Any = json.loads(truncated)
    except ValueError:
        parsed = truncated.decode("utf-8", errors="replace")
    return redact_sensitive(parsed)
