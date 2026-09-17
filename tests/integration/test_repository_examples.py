"""Execute published examples; only endpoints and temporary state are substituted."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt import PyJWKClient
from jwt.algorithms import RSAAlgorithm
from typer.testing import CliRunner

from mcp_zero_trust_layer.approvals import ApprovalStore
from mcp_zero_trust_layer.cli.main import _lint_config, app
from mcp_zero_trust_layer.config import load_config
from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.transports.http.app import create_app_from_config
from mcp_zero_trust_layer.upstream.stdio import StdioProcessUpstream

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / 'examples'


def isolated(name, tmp_path):
    cfg = load_config(EXAMPLES / name / 'mcpzt.yaml')
    cfg.audit.path = str(tmp_path / 'audit.jsonl')
    cfg.approvals.path = str(tmp_path / 'approvals.sqlite3')
    return cfg


def message(name, arguments=None):
    return {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': name, 'arguments': arguments or {}}}


class RecordingPeer:
    def __init__(self, result=None):
        self.calls = []
        self.result = result if result is not None else {'content': [{'type': 'text', 'text': 'ok'}]}

    def send(self, server, request, **kwargs):
        self.calls.append((server.name, request))
        return {'jsonrpc': '2.0', 'id': request['id'], 'result': self.result}


@pytest.mark.parametrize('path', sorted(EXAMPLES.rglob('mcpzt.yaml')),
                         ids=lambda p: str(p.parent.relative_to(EXAMPLES)))
def test_every_example_loads_and_has_no_lint_errors(path):
    cfg = load_config(path)
    assert not [f for f in _lint_config(cfg) if f['severity'] == 'error']
    assert cfg.runtime.default_decision == 'deny' and cfg.runtime.dry_run is False


@pytest.mark.parametrize('name', sorted(p.parent.name for p in EXAMPLES.glob('*/mcpzt.yaml')))
def test_example_lifecycle_does_not_authorize_business_tool_names(name, tmp_path, monkeypatch):
    cfg = isolated(name, tmp_path)
    monkeypatch.setenv('MCPZT_AUDIT_HMAC_KEY', 'synthetic-example-audit-key')
    peer = RecordingPeer()
    pipeline = MCPPipeline(cfg, peer)
    server = cfg.servers[0].name
    for method in ['initialize', 'ping']:
        assert 'result' in pipeline.handle(server, {'jsonrpc': '2.0', 'id': 1, 'method': method})
        assert pipeline.handle(server, message(method))['error']['code'] == -32001
    assert pipeline.handle(server, {'jsonrpc': '2.0', 'id': 1, 'method': 'admin/reset'})['error']['code'] == -32001
    assert len(peer.calls) == 2


def test_github_example_read_approval_and_unknown_tool(tmp_path):
    cfg = isolated('github-readonly', tmp_path)
    peer = RecordingPeer()
    pipeline = MCPPipeline(cfg, peer)
    assert 'result' in pipeline.handle('github', message('github.search_issues', {'q': 'security'}))
    assert pipeline.handle('github', message('github.delete_repository'))['error']['code'] == -32001
    assert len(peer.calls) == 1
    merge = message('github.merge_pull_request', {'repo': 'demo', 'pull_number': 1})
    pending = pipeline.handle('github', merge)
    aid = pending['error']['data']['approval_id']
    ApprovalStore(cfg.approvals).set_status(aid, 'approved', decided_by='reviewer')
    merge['params']['_mcpzt_approval_id'] = aid
    assert 'result' in pipeline.handle('github', merge)
    assert len(peer.calls) == 2 and '_mcpzt_approval_id' not in peer.calls[-1][1]['params']


def test_postgres_example_lists_query_and_blocks_writes(tmp_path):
    cfg = isolated('postgres-readonly', tmp_path)
    peer = RecordingPeer({'tools': [{'name': 'postgres.query'}, {'name': 'postgres.drop_table'}]})
    pipeline = MCPPipeline(cfg, peer)
    listed = pipeline.handle('postgres', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
    assert listed['result']['tools'] == [{'name': 'postgres.query'}]
    peer.result = {'rows': []}
    assert 'result' in pipeline.handle('postgres', message('postgres.query', {'query': 'select 1'}))
    blocked = pipeline.handle('postgres', message('postgres.query', {'query': 'delete from accounts'}))
    assert blocked['result']['isError'] is True and len(peer.calls) == 2


@pytest.mark.parametrize('group,allowed', [('support', True), ('engineering', False), ('outsider', False)])
def test_oidc_example_group_is_required_even_with_redaction(tmp_path, monkeypatch, group, allowed):
    cfg = isolated('oidc-gateway', tmp_path)
    monkeypatch.setenv('MCPZT_AUDIT_HMAC_KEY', 'synthetic-example-audit-key')
    peer = RecordingPeer({'customer_id': 'c1', 'api_key': 'synthetic-sensitive-value',
                          'content': [{'type': 'text', 'text': 'Contact person@example.com'}]})
    monkeypatch.setattr('mcp_zero_trust_layer.transports.http.app.HTTPUpstreamClient', lambda: peer)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk['kid'] = 'example-test'
    monkeypatch.setattr(PyJWKClient, 'fetch_data', lambda self: {'keys': [jwk]})
    token = jwt.encode({'sub': 'example-user', 'iss': cfg.auth.issuer, 'aud': cfg.auth.audience,
        'exp': datetime.now(UTC) + timedelta(minutes=5), 'scope': 'mcp:read', 'groups': [group]},
        key, algorithm='RS256', headers={'kid': 'example-test'})
    with TestClient(create_app_from_config(cfg), base_url='https://mcpzt.example.com') as client:
        result = client.post('/mcp/crm', json=message('crm.get_customer', {'customer_id': 'c1'}),
            headers={'Authorization': 'Bearer ' + token, 'x-mcpzt-groups': 'support'})
        assert result.status_code == 200
        body = result.json()
        if allowed:
            assert len(peer.calls) == 1
            assert body['result']['api_key'] == '[REDACTED]'
            assert 'person@example.com' not in json.dumps(body)
        else:
            assert body['error']['code'] == -32001 and peer.calls == []


def test_protected_example_client_and_upstream_credentials_are_distinct(tmp_path, monkeypatch):
    from test_multi_mcp_use_cases import _start_upstream

    upstream = _start_upstream('github')
    cfg = isolated('protected-http-upstream', tmp_path)
    cfg.servers[0].upstream = upstream.url
    monkeypatch.setenv('MCPZT_API_KEY', 'synthetic-client-key')
    monkeypatch.setenv('GITHUB_MCP_TOKEN', 'synthetic-upstream-key')
    observed = []
    original = upstream.handler.do_POST
    def capture(handler):
        observed.append(dict(handler.headers.items()))
        original(handler)
    monkeypatch.setattr(upstream.handler, 'do_POST', capture)
    try:
        with TestClient(create_app_from_config(cfg)) as client:
            body = message('github.search_issues', {'q': 'test'})
            assert client.post('/mcp/github', json=body).status_code == 401
            result = client.post('/mcp/github', json=body, headers={
                'x-api-key': 'synthetic-client-key', 'Authorization': 'Bearer caller-cannot-override'})
            assert result.status_code == 200 and 'result' in result.json()
        assert len(observed) == 1
        headers = {k.lower(): v for k, v in observed[0].items()}
        assert headers['authorization'] == 'Bearer synthetic-upstream-key'
        assert 'x-api-key' not in headers
    finally:
        upstream.server.shutdown()
        upstream.server.server_close()


def test_multi_example_redacts_secrets_even_without_email(tmp_path):
    cfg = isolated('multi-mcp', tmp_path)
    peer = RecordingPeer({'api_key': 'synthetic-private-key'})
    pipeline = MCPPipeline(cfg, peer)
    reply = pipeline.handle('crm', message('crm.get_customer', {'customer_id': 'c1'}))
    assert reply['result']['api_key'] == '[REDACTED]'
    invalid = pipeline.handle('crm', message('crm.get_customer'))
    assert invalid['result']['isError'] is True and len(peer.calls) == 1


def test_filesystem_example_names_and_path_gates(tmp_path):
    directory = tmp_path / 'filesystem'
    shutil.copytree(EXAMPLES / 'filesystem-safe', directory)
    cfg = load_config(directory / 'mcpzt.yaml')
    cfg.audit.path = str(tmp_path / 'audit.jsonl')
    cfg.approvals.path = str(tmp_path / 'approvals.json')
    peer = RecordingPeer({'tools': [{'name': 'read_text_file'}, {'name': 'write_file'}, {'name': 'move_file'}]})
    pipeline = MCPPipeline(cfg, peer)
    listed = pipeline.handle('filesystem', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
    assert [t['name'] for t in listed['result']['tools']] == ['read_text_file', 'write_file']
    peer.result = {'content': [{'type': 'text', 'text': 'synthetic content'}]}
    safe = str(directory / 'workspace/README.md')
    assert 'result' in pipeline.handle('filesystem', message('read_text_file', {'path': safe}))
    for tool in ['read_text_file', 'write_file']:
        result = pipeline.handle('filesystem', message(tool, {'path': str(tmp_path / 'outside'), 'content': 'x'}))
        assert result['result']['isError'] is True
    assert len(peer.calls) == 2
    pending = pipeline.handle('filesystem', message('write_file', {'path': safe, 'content': 'x'}))
    assert pending['error']['code'] == -32010 and len(peer.calls) == 2


@pytest.mark.skipif(not os.environ.get('MCPZT_FILESYSTEM_ENTRYPOINT'),
                    reason='Official pinned filesystem peer not installed (CI installs it)')
def test_official_filesystem_example_real_stdio(tmp_path, monkeypatch):
    directory = tmp_path / 'filesystem'
    shutil.copytree(EXAMPLES / 'filesystem-safe', directory)
    monkeypatch.chdir(directory)
    cfg = load_config(directory / 'mcpzt.yaml')
    target = cfg.servers[0]
    entry = Path(os.environ['MCPZT_FILESYSTEM_ENTRYPOINT'])
    installed = json.loads((entry.parent.parent / 'package.json').read_text())
    assert target.command[2] == installed['name'] + '@' + installed['version']
    target.command = ['node', str(entry), target.command[-1]]
    upstream = StdioProcessUpstream(target)
    pipeline = MCPPipeline(cfg, upstream)
    identity = Identity(subject='stdio-client', client_id='stdio')
    def send(request):
        return pipeline.handle('filesystem', request, identity=identity)
    try:
        init = send({'jsonrpc': '2.0', 'id': 0, 'method': 'initialize', 'params': {
            'protocolVersion': '2025-11-25', 'capabilities': {},
            'clientInfo': {'name': 'example-test', 'version': '1'}}})
        assert 'result' in init
        send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        listed = send({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
        assert {t['name'] for t in listed['result']['tools']} == {'read_text_file', 'write_file'}
        path = directory / 'workspace/README.md'
        read = send(message('read_text_file', {'path': str(path)}))
        assert 'synthetic local content' in read['result']['content'][0]['text']
        outside = tmp_path / 'outside.txt'
        outside.write_text('must not change')
        blocked = send(message('write_file', {'path': str(outside), 'content': 'bad'}))
        assert blocked['result']['isError'] is True and outside.read_text() == 'must not change'
        created = directory / 'workspace/new.txt'
        write = message('write_file', {'path': str(created), 'content': 'approved example'})
        pending = send(write)
        assert pending['error']['code'] == -32010 and not created.exists()
        aid = pending['error']['data']['approval_id']
        pipeline.approvals.set_status(aid, 'approved', decided_by='reviewer')
        write['params']['_mcpzt_approval_id'] = aid
        assert send(write)['result'].get('isError') is not True
        assert created.read_text() == 'approved example'
        assert send(write)['error']['code'] == -32010
    finally:
        upstream.close()


def test_generated_http_demo_runs_and_asserts_outcomes(tmp_path):
    directory = tmp_path / 'http-demo'
    result = CliRunner().invoke(app, ['demo', '--output', str(directory)])
    assert result.exit_code == 0, result.output
    # Run the generated scripts with this environment's installed CLI, outside the checkout.
    run = subprocess.run([str(directory / 'run_demo.sh')], cwd=directory, timeout=30,
        env={**os.environ, 'PYTHON': sys.executable, 'MCPZT': str(Path(sys.executable).parent / 'mcpzt')},
        capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    assert 'All demo assertions passed' in run.stdout
    records = [json.loads(line) for line in (directory / 'mcpzt-demo-audit.jsonl').read_text().splitlines()]
    assert not any(r.get('capability') == 'demo.delete_everything' and r.get('upstream_called')
                   for r in records)


def test_stripe_template_contracts_agree():
    from mcp_zero_trust_layer.core import RequestContext
    from mcp_zero_trust_layer.evidence.check_models import RefundArguments, StripeCheckConfig
    from mcp_zero_trust_layer.policy.engine import PolicyEngine

    root = EXAMPLES / 'evidence/stripe-sandbox'
    cfg = load_config(root / 'mcpzt.yaml')
    checker = StripeCheckConfig.model_validate_json((root / 'checker.json').read_text())
    request = json.loads((root / 'request-preimage.json').read_text())
    arguments = RefundArguments.model_validate(request['params']['arguments'])
    assert arguments.account == checker.account
    evidence = cfg.servers[0].evidence
    assert (evidence.scope, evidence.tenant, evidence.destination) == (
        checker.receipt_scope, checker.tenant, checker.destination)
    assert cfg.approvals.path == evidence.store and cfg.approvals.backend == 'sqlite'
    context = RequestContext(server='refund', method='tools/call', capability_type='tool',
        capability=checker.tool, arguments=arguments.model_dump())
    engine = PolicyEngine(cfg)
    assert engine.evaluate(context).decision == 'allow'
    for amount in ['5000', 50000, None]:
        context.arguments['amount_minor'] = amount
        assert engine.evaluate(context).decision == 'deny'
