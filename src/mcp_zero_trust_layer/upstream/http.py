from __future__ import annotations

import json
from typing import Any

import httpx

from mcp_zero_trust_layer.audit import redact_sensitive
from mcp_zero_trust_layer.config.models import ServerConfig
from mcp_zero_trust_layer.config.secrets import SecretError, resolve_secret_value
from mcp_zero_trust_layer.protocol import JSONRPCError

FORWARDED_HEADERS = {
    "accept",
    "content-type",
    "mcp-protocol-version",
    "mcp-session-id",
}
MAX_ERROR_BODY_BYTES = 4096


class HTTPUpstreamClient:
    def send(
        self,
        server: ServerConfig,
        message: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        if not server.upstream:
            raise JSONRPCError(-32603, "HTTP upstream is not configured")
        forwarded_headers = _forwarded_headers(headers or {})
        forwarded_headers.update(_configured_upstream_headers(server))
        forwarded_headers.setdefault("accept", "application/json, text/event-stream")
        forwarded_headers.setdefault("content-type", "application/json")
        try:
            with httpx.Client(timeout=server.timeout) as client:
                with client.stream(
                    "POST",
                    server.upstream,
                    json=message,
                    headers=forwarded_headers,
                ) as response:
                    content = _read_response_content(response, server)
        except httpx.TimeoutException as exc:
            raise JSONRPCError(-32002, "Upstream timeout", {"server": server.name}) from exc
        except httpx.HTTPError as exc:
            raise JSONRPCError(-32003, "Upstream HTTP error", {"error": str(exc)}) from exc

        if response.status_code == 202 or not content:
            return None
        if response.status_code >= 400:
            raise JSONRPCError(
                -32003,
                "Upstream HTTP error",
                {
                    "status_code": response.status_code,
                    "body": _safe_error_body(content),
                },
            )
        try:
            payload = json.loads(content)
        except ValueError as exc:
            raise JSONRPCError(-32603, "Invalid upstream JSON response") from exc
        if not isinstance(payload, dict):
            raise JSONRPCError(-32603, "Invalid upstream JSON-RPC response")
        return payload


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
