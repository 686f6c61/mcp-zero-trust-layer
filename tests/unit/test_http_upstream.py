from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from mcp_zero_trust_layer.config.models import ServerConfig
from mcp_zero_trust_layer.protocol import JSONRPCError
from mcp_zero_trust_layer.upstream.http import HTTPUpstreamClient


class HeaderCaptureHandler(BaseHTTPRequestHandler):
    received_headers: dict[str, str] = {}

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        self.__class__.received_headers = {key.lower(): value for key, value in self.headers.items()}
        size = int(self.headers.get("content-length", "0"))
        message = json.loads(self.rfile.read(size))
        response = {"jsonrpc": "2.0", "id": message.get("id"), "result": {"ok": True}}
        raw = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class LargeResponseHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        raw = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"text": "x" * 128}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class ErrorResponseHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        raw = json.dumps(
            {
                "message": "bad upstream",
                "authorization": "Bearer super-secret-token",
                "nested": {"api_key": "secret-key"},
            }
        ).encode()
        self.send_response(500)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def test_http_upstream_uses_configured_secret_headers_and_does_not_forward_auth(
    monkeypatch,
) -> None:
    monkeypatch.setenv("MCPZT_UPSTREAM_TOKEN", "outbound-token")
    monkeypatch.setenv("MCPZT_UPSTREAM_API_KEY", "outbound-key")
    server = ThreadingHTTPServer(("127.0.0.1", 0), HeaderCaptureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        upstream = ServerConfig(
            name="secure",
            transport="http",
            upstream=f"http://127.0.0.1:{port}/mcp",
            upstream_headers={
                "Authorization": "Bearer ${MCPZT_UPSTREAM_TOKEN}",
                "X-API-Key": "env:MCPZT_UPSTREAM_API_KEY",
            },
        )

        response = HTTPUpstreamClient().send(
            upstream,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={
                "authorization": "Bearer inbound-client-token",
                "mcp-protocol-version": "2025-11-25",
            },
        )

        assert response == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        assert HeaderCaptureHandler.received_headers["authorization"] == "Bearer outbound-token"
        assert HeaderCaptureHandler.received_headers["x-api-key"] == "outbound-key"
        assert HeaderCaptureHandler.received_headers["mcp-protocol-version"] == "2025-11-25"
    finally:
        server.shutdown()


def test_http_upstream_fails_closed_when_secret_env_is_missing(monkeypatch) -> None:
    monkeypatch.delenv("MCPZT_MISSING_UPSTREAM_TOKEN", raising=False)
    upstream = ServerConfig(
        name="secure",
        transport="http",
        upstream="http://127.0.0.1:1/mcp",
        upstream_headers={"Authorization": "Bearer ${MCPZT_MISSING_UPSTREAM_TOKEN}"},
    )

    with pytest.raises(JSONRPCError) as exc:
        HTTPUpstreamClient().send(
            upstream,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )

    assert exc.value.code == -32031


def test_http_upstream_blocks_oversized_response() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), LargeResponseHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        upstream = ServerConfig(
            name="large",
            transport="http",
            upstream=f"http://127.0.0.1:{port}/mcp",
            max_response_bytes=32,
        )

        with pytest.raises(JSONRPCError) as exc:
            HTTPUpstreamClient().send(
                upstream,
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            )

        assert exc.value.code == -32032
    finally:
        server.shutdown()


def test_http_upstream_redacts_error_body() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ErrorResponseHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        upstream = ServerConfig(
            name="error",
            transport="http",
            upstream=f"http://127.0.0.1:{port}/mcp",
        )

        with pytest.raises(JSONRPCError) as exc:
            HTTPUpstreamClient().send(
                upstream,
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            )

        body = exc.value.data["body"]
        assert body["authorization"] == "[REDACTED]"
        assert body["nested"]["api_key"] == "[REDACTED]"
    finally:
        server.shutdown()
