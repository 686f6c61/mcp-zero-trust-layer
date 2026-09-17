from __future__ import annotations

import copy
import io
import json
import runpy
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from typer.testing import CliRunner

from mcp_zero_trust_layer.cli.main import app
from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.evidence.cli import runtime
from mcp_zero_trust_layer.evidence.crypto import sign
from mcp_zero_trust_layer.evidence.demo import run_demo
from mcp_zero_trust_layer.evidence.models import bundle_schema
from mcp_zero_trust_layer.evidence.protocol import META
from mcp_zero_trust_layer.upstream.http import HTTPUpstreamClient

from .conftest import call
from .test_receipts import operation

runner = CliRunner()


def test_cli_demo_verify_export_show_reconcile_and_schema(tmp_path):
    directory = tmp_path / 'cli'
    result = runner.invoke(app, ['evidence', 'demo', '--directory', str(directory)])
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary['ledger_rows'] == 1 and summary['denied'] == 1
    operation_id = summary['operation_id']
    opts = ['--config', str(directory / 'mcpzt.yaml'), '--server', 'refund']
    for command in ['show', 'reconcile']:
        result = runner.invoke(app, ['evidence', command, operation_id, *opts])
        assert result.exit_code == 0, result.output
        assert 'committed' in result.output
    exported = directory / 'export.json'
    assert runner.invoke(app, ['evidence', 'export', operation_id, '--output', str(exported), *opts]).exit_code == 0
    assert exported.stat().st_mode & 0o777 == 0o600
    assert 'Refund recorded' not in exported.read_text()
    result = runner.invoke(app, ['evidence', 'verify', str(exported), '--trust', str(directory / 'trust.json')])
    assert result.exit_code == 0 and json.loads(result.output)['effect'] == 'committed'
    result = runner.invoke(app, ['evidence', 'schema'])
    assert result.exit_code == 0 and json.loads(result.output) == bundle_schema()
    assert runner.invoke(app, ['evidence', 'demo', '--directory', str(directory)]).exit_code != 0
    assert runner.invoke(app, ['evidence', 'export', operation_id, '--output', str(exported), *opts]).exit_code != 0
    for command in ['show', 'reconcile']:
        assert runner.invoke(app, ['evidence', command, 'unknown', *opts]).exit_code != 0
    with pytest.raises(ValueError):
        runtime(directory / 'mcpzt.yaml', 'other')


def test_cli_invalid_and_mismatched_content(env, tmp_path):
    _, service, bundle = operation(env)
    path = tmp_path / 'bundle.json'
    path.write_text(json.dumps(bundle))
    bad = tmp_path / 'bad.json'
    bad.write_text('{}')
    opts = ['evidence', 'verify', str(path), '--trust', str(env[0] / 'trust.json')]
    assert runner.invoke(app, opts + ['--request', str(bad), '--response', str(bad)]).exit_code == 1
    assert runner.invoke(app, ['evidence', 'verify', str(bad), '--trust', str(bad)]).exit_code == 2
    bad.write_text('bad json')
    assert runner.invoke(app, opts + ['--request', str(bad)]).exit_code == 2


def test_bundle_schema_constrains_signed_payload(env):
    import jsonschema
    _, _, bundle = operation(env)
    jsonschema.validate(bundle, bundle_schema())
    bundle['receipt']['payload']['effect'] = 'magically-proven'
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bundle, bundle_schema())


def test_destination_module_entrypoint(env, monkeypatch, capsys):
    operation(env)
    raw = json.dumps(env[3].message)
    monkeypatch.setattr(sys, 'argv', ['destination', str(env[0])])
    monkeypatch.setattr(sys, 'stdin', io.StringIO('{invalid}\n' + raw + '\n'))
    # __main__ entry is exercised in-process for coverage, with real generated keys/database.
    with pytest.warns(RuntimeWarning, match='found in sys.modules'):
        runpy.run_module('mcp_zero_trust_layer.evidence.destination', run_name='__main__')
    lines = capsys.readouterr().out.splitlines()
    assert json.loads(lines[0])['error']['code'] == -32700
    assert 'result' in json.loads(lines[1])


def test_http_wire_and_read_only_reconciliation(env):
    dest = env[2]
    received = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            message = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            received.append(message['method'])
            result = dest.handle(message)
            encoded = json.dumps(result).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = env[1]
        cfg.servers[0].transport = 'http'
        cfg.servers[0].upstream = f'http://127.0.0.1:{server.server_port}/mcp'
        pipeline = MCPPipeline(cfg, HTTPUpstreamClient())
        assert 'result' in pipeline.handle('refund', call())
        service = pipeline.evidence['refund']
        from mcp_zero_trust_layer.evidence.store import database
        with database(env[0] / 'destination.sqlite3') as db:
            op = db.execute('SELECT operation_id FROM refunds').fetchone()[0]
        assert service.reconcile(op, lambda m: pipeline.upstream.send(cfg.servers[0], m))['effect'] == 'committed'
        # Test the operator CLI's HTTP route as well.
        import yaml
        path = env[0] / 'http.yaml'
        path.write_text(yaml.safe_dump(cfg.model_dump(mode='json')))
        result = runner.invoke(app, ['evidence', 'reconcile', op, '--config', str(path), '--server', 'refund'])
        assert result.exit_code == 0, result.output
        assert received == ['tools/call', 'mcpzt/evidence/get', 'mcpzt/evidence/get']
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_unexpected_configured_scope_and_reconciliation_shapes(env):
    op, service, bundle = operation(env)
    changed = copy.deepcopy(bundle['receipt']['payload'])
    changed['scope'] = 'other-trusted-scope'
    service.trust.keys[1].scopes.append(changed['scope'])
    receipt = sign(changed, 'receipt', 'destination-demo', env[2].key).model_dump()
    response = copy.deepcopy(env[3].response)
    response['result']['_meta'][META] = receipt
    with pytest.raises(ValueError, match='DESTINATION_EVIDENCE_UNVERIFIED'):
        service.observe(op, response)
    with pytest.raises(ValueError, match='UNEXPECTED_EFFECT_SCOPE'):
        service.reconcile(op, lambda m: {'result': {'receipt': receipt}})
    for response in [None, {'error': {}}, {'result': {}}, {'result': {'receipt': {}}}]:
        with pytest.raises(ValueError, match='RECONCILIATION_UNKNOWN'):
            service.reconcile(op, lambda m, response=response: response)


@pytest.mark.parametrize('failure', ['invariant', 'verification'])
def test_demo_refuses_false_success(tmp_path, monkeypatch, failure):
    if failure == 'verification':
        monkeypatch.setattr('mcp_zero_trust_layer.evidence.verify.verify_bundle',
                            lambda *a, **k: {'claim': 'none'})
    else:
        original = MCPPipeline.handle
        def deny(self, *a, **k):
            message = a[1]
            if message.get('params', {}).get('arguments', {}).get('amount_minor') == 5000:
                return {'error': {}}
            return original(self, *a, **k)
        monkeypatch.setattr(MCPPipeline, 'handle', deny)
    with pytest.raises(ValueError):
        run_demo(tmp_path / failure)


def test_real_mcp_sdk_preserves_permit_and_receipt_metadata(env):
    import asyncio

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from mcp_zero_trust_layer.evidence.verify import verify_bundle
    from mcp_zero_trust_layer.identity import Identity
    service = env[4].evidence['refund']
    context = env[4]._context_for_message('refund', call(), identity=Identity())
    op, message = service.prepare(call(), context)
    async def exercise():
        argv = env[1].servers[0].command
        async with stdio_client(StdioServerParameters(command=argv[0], args=argv[1:])) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool('refund', {'amount_minor': 5000}, meta=message['params']['_meta'])
            assert result.meta and META in result.meta
            bundle = service.store.get(op, 'demo')
            bundle['receipt'] = result.meta[META]
            assert verify_bundle(bundle, service.trust)['effect'] == 'committed'
    asyncio.run(exercise())


def test_generated_ledger_config_works_through_gateway_with_real_sdk(tmp_path):
    import asyncio

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from mcp_zero_trust_layer.evidence.demo import create_demo
    from mcp_zero_trust_layer.evidence.store import database

    root = tmp_path / 'gateway-demo'
    create_demo(root)

    async def exercise():
        params = StdioServerParameters(command=sys.executable, args=[
            '-c', 'from mcp_zero_trust_layer.cli.main import app; app()',
            'wrap', '--config', str(root / 'mcpzt.yaml'), '--server', 'refund'])
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert [tool.name for tool in tools.tools] == ['refund']
            result = await session.call_tool('refund', {'amount_minor': 5000})
            assert result.isError is False and (not result.meta or META not in result.meta)
            assert result.structuredContent['amount_minor'] == 5000
    asyncio.run(exercise())
    with database(root / 'destination.sqlite3') as db:
        assert db.execute('SELECT count(*) FROM refunds').fetchone()[0] == 1


@pytest.mark.parametrize('point', ['before_commit', 'after_commit'])
def test_destination_process_crash_at_transaction_boundary(env, monkeypatch, point):
    import subprocess

    from mcp_zero_trust_layer.evidence.store import database
    source = '''import json,os,sys
from pathlib import Path
import mcp_zero_trust_layer.evidence.destination as m
d=m.RefundDestination(Path(sys.argv[1]))
if sys.argv[2]=='after_commit':
    d._receipt=lambda *args: os._exit(99)
else:
    m.Receipt=lambda **kwargs: os._exit(99)
d.handle(json.load(sys.stdin))
'''
    def send(server, message, **kwargs):
        child = subprocess.run([sys.executable, '-c', source, str(env[0]), point],
                               input=json.dumps(message), text=True, timeout=10)
        assert child.returncode == 99
        raise ConnectionError('destination died')
    monkeypatch.setattr(env[3], 'send', send)
    result = env[4].handle('refund', call())
    assert result['error']['data']['effect'] == 'unknown'
    op = result['error']['data']['operation_id']
    with database(env[0] / 'destination.sqlite3') as db:
        assert db.execute('SELECT count(*) FROM refunds').fetchone()[0] == (point == 'after_commit')
    if point == 'after_commit':
        assert env[4].evidence['refund'].reconcile(op, env[2].handle)['effect'] == 'committed'
    else:
        with pytest.raises(ValueError):
            env[4].evidence['refund'].reconcile(op, env[2].handle)
