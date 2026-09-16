from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from mcp_zero_trust_layer.config.models import MCPZTConfig, ServerConfig
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.protocol import JSONRPCError
from mcp_zero_trust_layer.transports.http.app import create_app_from_config
from mcp_zero_trust_layer.transports.http.sessions import SessionRegistry
from mcp_zero_trust_layer.upstream.http import HTTPUpstreamClient


@pytest.fixture
def wire_server():
    """Exercise real HTTP framing/session headers against a controllable peer."""
    state = {"status": 200, "body": None, "session": "peer-session", "wait": False, "content_type": "application/json"}
    received = threading.Event()
    release = threading.Event()

    class Peer(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):  # noqa: N802
            message = json.loads(self.rfile.read(int(self.headers["content-length"])))
            supplied = self.headers.get("mcp-session-id")
            if state["wait"]:
                received.set()
                if not release.wait(5):
                    self.send_error(500)
                    return
            payload = state["body"]
            if payload is None:
                payload = json.dumps({
                    "jsonrpc": "2.0", "id": message.get("id"),
                    "result": {"received_session": supplied},
                }).encode()
            self.send_response(state["status"])
            self.send_header("Content-Type", state["content_type"])
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Mcp-Session-Id", state["session"])
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    config = ServerConfig(name="peer", transport="http", upstream=f"http://127.0.0.1:{server.server_port}")
    try:
        yield config, state, received, release
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(5)


def request(method="ping"):
    return {"jsonrpc": "2.0", "id": 1, "method": method}


@pytest.mark.parametrize("status", [401, 404, 500])
def test_empty_http_errors_are_not_notification_acknowledgements(wire_server, status):
    config, state, _, _ = wire_server
    state.update(status=status, body=b"")
    client = HTTPUpstreamClient()
    for message in [request(), {"jsonrpc": "2.0", "method": "notifications/initialized"}]:
        with pytest.raises(JSONRPCError) as error:
            client.send(config, message)
        assert error.value.code == -32003
        assert error.value.data["status_code"] == status


@pytest.mark.parametrize("payload", [
    {"jsonrpc": "2.0", "id": 1, "result": {}},
    {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": "error"}},
])
def test_notifications_reject_unexpected_success_or_error_responses(wire_server, payload):
    config, state, _, _ = wire_server
    state["body"] = json.dumps(payload).encode()
    with pytest.raises(JSONRPCError, match="response to a notification"):
        HTTPUpstreamClient().send(config, {"jsonrpc": "2.0", "method": "notifications/initialized"})


@pytest.mark.parametrize("payload", [
    {"jsonrpc": "2.0", "id": 2, "result": {}},
    {"jsonrpc": "2.0", "id": True, "result": {}},
    {"jsonrpc": "2.0", "id": 1, "result": "not-an-object"},
    {"jsonrpc": "2.0", "id": 1, "error": {"code": "invalid", "message": "failed"}},
    {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603}},
    {"jsonrpc": "2.0", "id": 1, "error": "not-an-object"},
    {"jsonrpc": "2.0", "id": "1", "error": {"code": -32603, "message": "wrong request"}},
    {"jsonrpc": "2.0", "id": 1, "error": {}, "result": {}},
    {"jsonrpc": "1.0", "id": 1, "result": {}},
    {"jsonrpc": "2.0", "id": 1},
])
def test_request_rejects_uncorrelated_or_invalid_response_envelope(wire_server, payload):
    config, state, _, _ = wire_server
    state["body"] = json.dumps(payload).encode()
    with pytest.raises(JSONRPCError) as error:
        HTTPUpstreamClient().send(config, request())
    assert error.value.code == -32603


def test_forgotten_scope_is_not_resurrected_by_late_response(wire_server):
    config, state, received, release = wire_server
    client = HTTPUpstreamClient()
    client.register_session(config.name, "scope")
    state["wait"] = True
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(client.send, config, request("initialize"), headers={"x-mcpzt-session-key": "scope"})
        assert received.wait(5)
        client.forget_session(config.name, "scope")
        release.set()
        assert pending.result(timeout=5)["result"]["received_session"] is None
    state["wait"] = False
    # If the late response resurrected the cache, the peer sees its old session.
    response = client.send(config, request(), headers={"x-mcpzt-session-key": "scope"})
    assert response["result"]["received_session"] is None
    assert not client._session_ids


def test_registry_expiry_and_repeated_removal_forget_actual_upstream_session(wire_server, monkeypatch):
    config, _, _, _ = wire_server
    upstream = HTTPUpstreamClient()
    registry = SessionRegistry(upstream, ttl=10, capacity=1)
    now = [0.0]
    monkeypatch.setattr("mcp_zero_trust_layer.transports.http.sessions.time.monotonic", lambda: now[0])
    identity = Identity(subject="alice")
    key = registry.resolve(config.name, identity, None, initialize=True)
    headers = {"x-mcpzt-session-key": key}
    upstream.send(config, request("initialize"), headers=headers)
    assert upstream.send(config, request(), headers=headers)["result"]["received_session"] == "peer-session"
    now[0] = 10.0
    with pytest.raises(KeyError):
        registry.resolve(config.name, identity, key, initialize=False)
    registry.remove(key)
    registry.remove(key)
    assert not registry.active(key)
    assert upstream.send(config, request(), headers=headers)["result"]["received_session"] is None
    # Expiration also frees capacity; explicit deletion is equally idempotent.
    replacement = registry.resolve(config.name, identity, None, initialize=True)
    registry.remove(replacement)
    registry.remove(replacement)
    assert not registry.entries


@pytest.mark.parametrize("status,body", [
    (500, b""),
    (200, b'{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"failed"}}'),
    (200, b"not json"),
    (202, b""),
])
def test_failed_initialize_leaves_no_downstream_or_upstream_session(wire_server, tmp_path, status, body):
    server, state, _, _ = wire_server
    state.update(status=status, body=body)
    config = MCPZTConfig.model_validate({
        "servers": [server.model_dump()],
        "policies": [{"id": "allow", "effect": "allow"}],
        "audit": {"path": str(tmp_path / "audit.jsonl")},
    })
    app = create_app_from_config(config)
    with TestClient(app) as client:
        response = client.post("/mcp", json=request("initialize"))
        assert "error" in response.json()
        assert "mcp-session-id" not in response.headers
        assert not app.state.sessions.entries
        assert not app.state.sessions.upstream._session_ids
        # A subsequent successful initialize can establish a fresh session.
        state.update(status=200, body=None)
        success = client.post("/mcp", json=request("initialize"))
        assert "result" in success.json()
        assert success.headers["mcp-session-id"]
        assert len(app.state.sessions.entries) == 1


def test_sse_upstream_fails_explicitly(wire_server):
    config, state, _, _ = wire_server
    state.update(content_type="text/event-stream; charset=utf-8", body=b"data: {}\n\n")
    with pytest.raises(JSONRPCError, match="SSE is not supported"):
        HTTPUpstreamClient().send(config, request())


def gateway_config(server, tmp_path):
    return MCPZTConfig.model_validate({
        "servers": [server.model_dump()],
        "policies": [{"id": "allow", "effect": "allow"}],
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "runtime": {"allowed_origins": ["https://trusted.test"]},
    })


def test_rejected_delete_origin_does_not_destroy_session(wire_server, tmp_path):
    server, _, _, _ = wire_server
    app = create_app_from_config(gateway_config(server, tmp_path))
    with TestClient(app) as client:
        key = client.post("/mcp", json=request("initialize")).headers["mcp-session-id"]
        response = client.delete("/mcp", headers={"origin": "https://evil.test", "mcp-session-id": key})
        assert response.status_code == 403
        assert app.state.sessions.active(key)
        assert client.post("/mcp", json=request(), headers={"mcp-session-id": key}).status_code == 200


def test_upstream_404_invalidates_downstream_session(wire_server, tmp_path):
    server, state, _, _ = wire_server
    app = create_app_from_config(gateway_config(server, tmp_path))
    with TestClient(app) as client:
        key = client.post("/mcp", json=request("initialize")).headers["mcp-session-id"]
        state.update(status=404, body=b"")
        failed = client.post("/mcp", json=request(), headers={"mcp-session-id": key})
        assert failed.status_code == 404
        assert "mcp-session-id" not in failed.headers
        assert not app.state.sessions.active(key)
        assert not app.state.sessions.upstream._session_ids
        state.update(status=200, body=None)
        assert client.post("/mcp", json=request(), headers={"mcp-session-id": key}).status_code == 404


def test_initialization_exception_removes_reserved_session(wire_server, tmp_path):
    server, _, _, _ = wire_server
    config = gateway_config(server, tmp_path)
    config.audit.path = str(tmp_path)  # Real strict audit I/O failure, before dispatch.
    app = create_app_from_config(config)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/mcp", json=request("initialize"))
        assert response.status_code == 500
        assert not app.state.sessions.entries
        assert not app.state.sessions.upstream._active_sessions


def test_delete_during_inflight_request_cannot_return_a_live_session(wire_server, tmp_path):
    server, state, received, release = wire_server
    app = create_app_from_config(gateway_config(server, tmp_path))
    with TestClient(app) as client:
        key = client.post("/mcp", json=request("initialize")).headers["mcp-session-id"]
        state["wait"] = True
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(client.post, "/mcp", json=request(), headers={"mcp-session-id": key})
            assert received.wait(5)
            deleted = client.delete("/mcp", headers={"mcp-session-id": key})
            assert deleted.status_code == 204
            release.set()
            response = pending.result(timeout=5)
        assert response.status_code == 404
        assert response.json()["error"]["message"] == "Session expired"
        assert "mcp-session-id" not in response.headers
        assert not app.state.sessions.entries
        assert not app.state.sessions.upstream._session_ids


@pytest.mark.parametrize("error_data", [None, "diagnostic text", ["diagnostic", 42]])
@pytest.mark.parametrize("during_initialize", [False, True])
def test_arbitrary_mcp_error_data_does_not_crash_session_handling(
    wire_server, tmp_path, error_data, during_initialize
):
    server, state, _, _ = wire_server
    app = create_app_from_config(gateway_config(server, tmp_path))
    error = {"code": -32003, "message": "Application error", "data": error_data}
    with TestClient(app) as client:
        headers = {}
        key = None
        if not during_initialize:
            key = client.post("/mcp", json=request("initialize")).headers["mcp-session-id"]
            headers["mcp-session-id"] = key
        state["body"] = json.dumps({"jsonrpc": "2.0", "id": 1, "error": error}).encode()
        failed = client.post(
            "/mcp", json=request("initialize" if during_initialize else "ping"), headers=headers
        )
        assert failed.status_code == 200
        assert failed.json()["error"] == error
        if during_initialize:
            assert "mcp-session-id" not in failed.headers
            assert not app.state.sessions.entries
            assert not app.state.sessions.upstream._session_ids
            assert not app.state.sessions.upstream._active_sessions
        else:
            assert failed.headers["mcp-session-id"] == key
            assert app.state.sessions.active(key)
        state["body"] = None
        recovered = client.post(
            "/mcp", json=request("initialize" if during_initialize else "ping"), headers=headers
        )
        assert recovered.status_code == 200
        assert "result" in recovered.json()
        assert len(app.state.sessions.entries) == 1
