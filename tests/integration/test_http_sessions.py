from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient

from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.transports.http.app import create_app_from_config
from mcp_zero_trust_layer.transports.http.sessions import SessionRegistry
from mcp_zero_trust_layer.upstream.http import HTTPUpstreamClient

SECRET = 'synthetic-release-contract-key-32-bytes'


class StatefulServer(BaseHTTPRequestHandler):
    seen: list[tuple[str, str | None]] = []

    def log_message(self, *args):
        pass

    def do_POST(self):  # noqa: N802
        message = json.loads(self.rfile.read(int(self.headers['content-length'])))
        supplied = self.headers.get('mcp-session-id')
        self.seen.append((message['method'], supplied))
        session = uuid4().hex if message['method'] == 'initialize' else supplied
        raw = json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': {'session': session}}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        if session:
            self.send_header('Mcp-Session-Id', session)
        self.end_headers()
        self.wfile.write(raw)


def token(subject):
    return jwt.encode({'sub': subject, 'exp': time.time() + 120}, SECRET, algorithm='HS256')


@pytest.fixture
def gateway(tmp_path):
    StatefulServer.seen = []
    server = ThreadingHTTPServer(('127.0.0.1', 0), StatefulServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cfg = MCPZTConfig.model_validate({
        'auth': {'mode': 'jwt', 'token': SECRET, 'algorithms': ['HS256']},
        'servers': [{'name': 's', 'transport': 'http', 'upstream': f'http://127.0.0.1:{server.server_port}'}],
        'policies': [{'id': 'allow', 'effect': 'allow'}],
        'audit': {'path': str(tmp_path / 'audit.jsonl')},
    })
    app = create_app_from_config(cfg)
    with TestClient(app) as client:
        yield client, app.state.sessions
    server.shutdown()
    server.server_close()
    thread.join()


def post(client, subject, method, session=None, **extra_headers):
    headers = {'authorization': 'Bearer ' + token(subject), **extra_headers}
    if session:
        headers['mcp-session-id'] = session
    return client.post('/mcp', json={'jsonrpc': '2.0', 'id': 1, 'method': method}, headers=headers)


def test_stateful_clients_are_isolated_and_public_keys_not_trusted(gateway):
    client, registry = gateway
    alice = post(client, 'alice', 'initialize')
    bob = post(client, 'bob', 'initialize')
    a = alice.headers['mcp-session-id']
    b = bob.headers['mcp-session-id']
    assert a != b
    assert alice.json()['result']['session'] != bob.json()['result']['session']
    assert a != alice.json()['result']['session']
    assert post(client, 'alice', 'ping', a).json()['result']['session'] == alice.json()['result']['session']
    before = len(StatefulServer.seen)
    assert post(client, 'bob', 'ping', a).status_code == 404
    assert len(StatefulServer.seen) == before
    assert post(client, 'bob', 'ping', b).json()['result']['session'] == bob.json()['result']['session']
    # A public forged internal key never attaches another client's upstream session.
    assert post(client, 'bob', 'ping', **{'x-mcpzt-session-key': a}).json()['result']['session'] is None
    assert post(client, 'bob', 'ping').json()['result']['session'] is None
    assert len(registry.entries) == 2


def test_session_lifecycle_errors_and_protocol_version(gateway):
    client, registry = gateway
    session = post(client, 'alice', 'initialize').headers['mcp-session-id']
    assert post(client, 'alice', 'initialize', session).status_code == 400
    assert post(client, 'alice', 'ping', **{'mcp-protocol-version': 'invalid'}).status_code == 400
    assert client.delete('/mcp').status_code == 401
    headers = {'authorization': 'Bearer ' + token('alice')}
    assert client.delete('/mcp', headers=headers).status_code == 400
    assert client.delete('/mcp', headers={**headers, 'mcp-session-id': 'unknown'}).status_code == 404
    assert client.delete('/mcp', headers={**headers, 'mcp-session-id': session}).status_code == 204
    assert post(client, 'alice', 'ping', session).status_code == 404
    assert not registry.entries and not registry.upstream._session_ids
    registry.capacity = 0
    assert post(client, 'alice', 'initialize').status_code == 503


def test_registry_expiry_owner_and_server_binding(monkeypatch):
    upstream = HTTPUpstreamClient()
    registry = SessionRegistry(upstream, ttl=10, capacity=1)
    monkeypatch.setattr('mcp_zero_trust_layer.transports.http.sessions.time.monotonic', lambda: 1)
    alice = Identity(subject='alice')
    key = registry.resolve('s', alice, None, initialize=True)
    upstream._session_ids[('s', key)] = 'upstream-session'
    with pytest.raises(KeyError):
        registry.resolve('other-server', alice, key, initialize=False)
    with pytest.raises(OverflowError):
        registry.resolve('s', alice, None, initialize=True)
    monkeypatch.setattr('mcp_zero_trust_layer.transports.http.sessions.time.monotonic', lambda: 12)
    with pytest.raises(KeyError):
        registry.resolve('s', alice, key, initialize=False)
    assert not upstream._session_ids
