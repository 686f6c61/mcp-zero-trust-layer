from __future__ import annotations

import sys
import time

import pytest

from mcp_zero_trust_layer.capabilities.discovery import discover_capabilities
from mcp_zero_trust_layer.config.models import MCPZTConfig, ServerConfig
from mcp_zero_trust_layer.protocol import JSONRPCError
from mcp_zero_trust_layer.upstream.stdio import StdioProcessUpstream


@pytest.mark.parametrize(('body', 'code'), [
    ("sys.stdout.write('{');sys.stdout.flush();time.sleep(5)", -32002),
    ("print('x'*1000,flush=True)", -32032),
    ("print(json.dumps({'jsonrpc':'2.0','id':999,'result':{}}),flush=True)", -32603),
    ("print(json.dumps({'jsonrpc':'2.0','id':7,'method':'sampling/createMessage'}),flush=True)", -32603),
])
def test_stdio_contract_failure_terminates_session(body, code):
    server = ServerConfig(name='test', transport='stdio', command=[sys.executable, '-c',
        'import sys,time,json;sys.stdin.readline();' + body], timeout=0.15, max_response_bytes=128)
    upstream = StdioProcessUpstream(server)
    started = time.monotonic()
    try:
        with pytest.raises(JSONRPCError) as exc:
            upstream.send(server, {'jsonrpc':'2.0','id':1,'method':'ping'})
        assert exc.value.code == code
        assert time.monotonic() - started < 2
        assert upstream.process.poll() is not None
    finally:
        upstream.close()


def test_stdio_notification_is_explicitly_rejected():
    body = "import sys,json;sys.stdin.readline();print(json.dumps({'jsonrpc':'2.0','method':'notifications/progress'})+'\\n'+json.dumps({'jsonrpc':'2.0','id':1,'result':{}}),flush=True)"
    server = ServerConfig(name='test', transport='stdio', command=[sys.executable,'-c',body])
    upstream = StdioProcessUpstream(server)
    try:
        with pytest.raises(JSONRPCError, match='notifications are unsupported'):
            upstream.send(server, {'jsonrpc':'2.0','id':1,'method':'ping'})
    finally:
        upstream.close()


def test_discovery_pages_negotiation_and_session_cleanup():
    class Upstream:
        def __init__(self):
            self.headers = []
            self.forgotten = None

        def send(self, server, message, *, headers=None):
            self.headers.append(dict(headers))
            method = message['method']
            if method == 'initialize':
                return {'result': {'protocolVersion':'2025-06-18'}}
            if method == 'notifications/initialized':
                return None
            if method == 'tools/list':
                return {'result': {'tools':[{'name':'second'}]}} if message['params'].get('cursor') else {'result': {'tools':[{'name':'first'}], 'nextCursor':'page2'}}
            return {'result':{method.split('/')[0]:[]}}

        def forget_session(self, server, key):
            self.forgotten = (server, key)

    server = ServerConfig(name='test', transport='http', upstream='https://example.invalid')
    upstream = Upstream()
    snapshot = discover_capabilities(MCPZTConfig(servers=[server]), 'test', upstream)
    assert snapshot.errors == {}
    assert snapshot.tools == [{'name':'first'},{'name':'second'}]
    assert all(h['mcp-protocol-version'] == '2025-06-18' for h in upstream.headers[1:])
    assert len({h['x-mcpzt-session-key'] for h in upstream.headers}) == 1
    assert upstream.forgotten == ('test', upstream.headers[0]['x-mcpzt-session-key'])


def test_discovery_stops_before_lists_on_unsupported_version():
    class Upstream:
        def send(self, server, message, *, headers=None):
            assert message['method'] == 'initialize'
            return {'result': {'protocolVersion':'invalid'}}

    config = MCPZTConfig(servers=[ServerConfig(name='test', transport='http', upstream='https://example.invalid')])
    snapshot = discover_capabilities(config, 'test', Upstream())
    assert 'unsupported negotiated' in snapshot.errors['initialize']


def test_stdio_deadline_covers_child_that_does_not_read_stdin():
    server = ServerConfig(name='test', transport='stdio', command=[sys.executable,'-c','import time;time.sleep(10)'], timeout=0.15)
    upstream = StdioProcessUpstream(server)
    try:
        started = time.monotonic()
        with pytest.raises(JSONRPCError) as exc:
            upstream.send(server, {'jsonrpc':'2.0','id':1,'method':'ping','params':{'blob':'x'*1000000}})
        assert exc.value.code == -32002
        assert time.monotonic() - started < 2
    finally:
        upstream.close()


@pytest.fixture
def echo_upstream():
    script = "import sys,json\nfor line in sys.stdin:\n m=json.loads(line); print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{}}),flush=True)"
    server = ServerConfig(name='test', transport='stdio', command=[sys.executable,'-c',script])
    upstream = StdioProcessUpstream(server)
    try:
        yield upstream
    finally:
        upstream.close()


@pytest.mark.parametrize('operation', ['read', 'write'])
def test_stdio_rejects_platform_without_pipe_select(echo_upstream, monkeypatch, operation):
    import mcp_zero_trust_layer.upstream.stdio as module
    monkeypatch.setattr(module, 'select', None)
    with pytest.raises(JSONRPCError, match='requires POSIX'):
        if operation == 'read':
            echo_upstream._readline_with_timeout()
        else:
            echo_upstream._write_with_timeout({}, time.monotonic() + 1)


@pytest.mark.parametrize('operation', ['read', 'write'])
def test_stdio_expired_whole_message_deadline(echo_upstream, operation):
    with pytest.raises(JSONRPCError) as exc:
        if operation == 'read':
            echo_upstream._readline_with_timeout(time.monotonic() - 1)
        else:
            echo_upstream._write_with_timeout({}, time.monotonic() - 1)
    assert exc.value.code == -32002


def test_stdio_write_recovers_from_transient_backpressure(echo_upstream, monkeypatch):
    import mcp_zero_trust_layer.upstream.stdio as module
    original = module.os.write
    attempts = []

    def transient(fd, data):
        attempts.append(fd)
        if len(attempts) == 1:
            raise BlockingIOError('temporary pipe backpressure')
        return original(fd, data)

    monkeypatch.setattr(module.os, 'write', transient)
    response = echo_upstream.send(echo_upstream.server, {'jsonrpc':'2.0','id':1,'method':'ping'})
    assert response['result'] == {}
    assert len(attempts) >= 2


def test_stdio_write_broken_pipe_becomes_controlled_error(echo_upstream, monkeypatch):
    import mcp_zero_trust_layer.upstream.stdio as module

    def broken(fd, data):
        raise BrokenPipeError('closed pipe')

    monkeypatch.setattr(module.os, 'write', broken)
    with pytest.raises(JSONRPCError) as exc:
        echo_upstream.send(echo_upstream.server, {'jsonrpc':'2.0','id':1,'method':'ping'})
    assert exc.value.code == -32030
    assert echo_upstream.process.poll() is not None


def test_stdio_eof_mid_frame_is_not_a_response():
    server = ServerConfig(name='test', transport='stdio', command=[sys.executable,'-c',"import sys;sys.stdin.readline();sys.stdout.write('{');sys.stdout.flush()"])
    upstream = StdioProcessUpstream(server)
    try:
        with pytest.raises(JSONRPCError, match='incomplete'):
            upstream.send(server, {'jsonrpc':'2.0','id':1,'method':'ping'})
    finally:
        upstream.close()


@pytest.mark.parametrize(('payload', 'max_bytes', 'exit_code', 'error_code'), [
    ('x'*100, 32, 2, -32042),
    ('[1,2,3]\n', 32, 0, -32600),
])
def test_wrapper_rejects_invalid_input_before_upstream(tmp_path, monkeypatch, payload, max_bytes, exit_code, error_code):
    import json
    from io import StringIO

    import mcp_zero_trust_layer.transports.stdio.wrapper as module

    class NeverCalled:
        closed = False

        def __init__(self, server):
            pass

        def pump_stderr(self, stderr):
            pass

        def send(self, *args, **kwargs):
            pytest.fail('invalid input reached upstream')

        def close(self):
            NeverCalled.closed = True

    server = ServerConfig(name='test', transport='stdio', command=['unused'])
    config = MCPZTConfig(servers=[server], runtime={'max_request_bytes':max_bytes}, audit={'path':str(tmp_path/'audit')}, approvals={'path':str(tmp_path/'approvals')})
    monkeypatch.setattr(module, 'load_config', lambda path: config)
    monkeypatch.setattr(module, 'StdioProcessUpstream', NeverCalled)
    output = StringIO()
    assert module.run_stdio_wrapper(tmp_path/'unused', stdin=StringIO(payload), stdout=output, stderr=StringIO()) == exit_code
    assert json.loads(output.getvalue())['error']['code'] == error_code
    assert NeverCalled.closed


@pytest.mark.parametrize(('cursor_mode', 'expected'), [('repeat','repeated discovery cursor'), ('distinct','page limit exceeded')])
def test_discovery_rejects_unbounded_pagination(monkeypatch, cursor_mode, expected):
    import mcp_zero_trust_layer.capabilities.discovery as module
    monkeypatch.setattr(module, 'MAX_DISCOVERY_PAGES', 2)

    class Upstream:
        registered = None
        forgotten = None
        count = 0

        def register_session(self, server, key):
            self.registered = (server, key)

        def forget_session(self, server, key):
            self.forgotten = (server, key)

        def send(self, server, message, *, headers=None):
            if message['method'] == 'initialize':
                return {'result':{'protocolVersion':'2025-11-25'}}
            if message['method'] == 'notifications/initialized':
                return None
            field = message['method'].split('/')[0]
            self.count += 1
            return {'result':{field:[], 'nextCursor':'same' if cursor_mode == 'repeat' else str(self.count)}}

    upstream = Upstream()
    config = MCPZTConfig(servers=[ServerConfig(name='test', transport='http', upstream='https://example.invalid')])
    result = discover_capabilities(config, 'test', upstream)
    assert all(expected in result.errors[key] for key in ['tools','resources','prompts'])
    assert upstream.registered == upstream.forgotten
    assert upstream.registered is not None
