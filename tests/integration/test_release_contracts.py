"""Release contracts: observable enforcement and evidence, not implementation coverage."""
from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import jwt
import pytest

from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.identity import AuthResolver, Identity
from mcp_zero_trust_layer.protocol import JSONRPCError


class Tool:
    def __init__(self, *, fails=False):
        self.calls = 0
        self.fails = fails

    def send(self, server, message, *, headers=None):
        self.calls += 1
        if self.fails:
            raise JSONRPCError(-32003, 'connection lost after dispatch')
        return {'jsonrpc': '2.0', 'id': message['id'], 'result': {'data': 'protected'}}


def config(tmp_path, **extra):
    return MCPZTConfig.model_validate({
        'servers': [{'name': 's', 'transport': 'http', 'upstream': 'http://unused.invalid'}],
        'audit': {'destination': 'file', 'path': str(tmp_path / 'audit.jsonl'), 'strict': True},
        'approvals': {'path': str(tmp_path / 'approvals.json')},
        **extra,
    })


def call():
    return {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'read', 'arguments': {}}}


@pytest.mark.parametrize('failure', ['false', 'timeout', 'invalid'])
def test_opa_outbound_denial_never_releases_payload(tmp_path, monkeypatch, failure):
    cfg = config(tmp_path, policy_engine={'adapter': 'opa', 'endpoint': 'http://unused.invalid/opa'})
    def opa_post(url, *, json, timeout):
        if json['input']['context']['direction'] == 'inbound':
            return httpx.Response(200, json={'result': True}, request=httpx.Request('POST', url))
        if failure == 'timeout':
            raise httpx.ReadTimeout('synthetic')
        return httpx.Response(200, json={'result': False if failure == 'false' else []}, request=httpx.Request('POST', url))
    monkeypatch.setattr('mcp_zero_trust_layer.policy.adapters.httpx.post', opa_post)
    tool = Tool()
    result = MCPPipeline(cfg, tool).handle('s', call())
    assert result['error']['code'] == -32020
    assert 'protected' not in json.dumps(result)
    assert tool.calls == 1


@pytest.mark.parametrize('method', ['custom/action', 'tools/list'])
def test_unsupported_approval_methods_fail_before_dispatch(tmp_path, method):
    cfg = config(tmp_path, policies=[{'id': 'review', 'effect': 'require_approval', 'match': {'method': method}}])
    tool = Tool()
    result = MCPPipeline(cfg, tool).handle('s', {'jsonrpc': '2.0', 'id': 1, 'method': method})
    assert result['error']['code'] == -32001
    assert tool.calls == 0


def test_strict_unwritable_audit_prevents_side_effect(tmp_path):
    cfg = config(tmp_path, policies=[{'id': 'allow', 'effect': 'allow'}])
    cfg.audit.path = str(tmp_path)
    tool = Tool()
    with pytest.raises(OSError):
        MCPPipeline(cfg, tool).handle('s', call())
    assert tool.calls == 0


def test_dispatch_error_has_linked_intent_and_unknown_outcome(tmp_path):
    cfg = config(tmp_path, policies=[{'id': 'allow', 'effect': 'allow'}])
    tool = Tool(fails=True)
    result = MCPPipeline(cfg, tool).handle('s', call())
    assert result['error']['code'] == -32003
    events = [json.loads(line) for line in Path(cfg.audit.path).read_text().splitlines()]
    assert [event['upstream_status'] for event in events] == ['dispatch_intent', 'unknown']
    assert events[0]['correlation_id'] == events[1]['correlation_id']
    assert events[0]['arguments_hash'] == events[1]['arguments_hash']


def test_signed_identity_does_not_fall_back_to_untrusted_headers(tmp_path):
    secret = 'synthetic-test-key-with-at-least-32-bytes'
    cfg = config(tmp_path, auth={'mode': 'jwt', 'token': secret, 'algorithms': ['HS256']})
    token = jwt.encode({'sub': 'alice', 'exp': time.time() + 60}, secret, algorithm='HS256')
    headers = {'authorization': f'Bearer {token}', 'x-mcpzt-client-id': 'admin-client', 'x-mcpzt-agent-id': 'admin-agent'}
    identity = AuthResolver(cfg.auth).resolve_http_identity(headers=headers, source_ip=None)
    assert identity.subject == 'alice'
    assert identity.client_id is None and identity.agent_id is None
    cfg.auth.trust_identity_headers = True
    assert AuthResolver(cfg.auth).resolve_http_identity(headers=headers, source_ip=None).client_id == 'admin-client'


@pytest.mark.parametrize('change', ['params', 'policy', 'server'])
def test_approval_cannot_be_reused_after_binding_change(tmp_path, change):
    cfg = config(tmp_path, policies=[{'id': 'review', 'effect': 'require_approval', 'match': {'method': 'tools/call'}}])
    pipeline = MCPPipeline(cfg, Tool())
    identity = Identity(subject='alice')
    first = pipeline.handle('s', call(), identity=identity)
    approval_id = first['error']['data']['approval_id']
    pipeline.approvals.set_status(approval_id, 'approved', decided_by='reviewer')
    retry = call()
    retry['params']['_mcpzt_approval_id'] = approval_id
    if change == 'params':
        retry['params']['_meta'] = {'different': True}
    elif change == 'policy':
        cfg.policies[0].reason = 'new policy revision'
    else:
        cfg.servers[0].upstream = 'http://different.invalid'
    result = pipeline.handle('s', retry, identity=identity)
    assert result['error']['code'] == -32010
    assert pipeline.upstream.calls == 0


def test_approved_dispatch_links_exact_approval(tmp_path):
    cfg = config(tmp_path, policies=[{'id': 'review', 'effect': 'require_approval', 'match': {'method': 'tools/call'}}])
    pipeline = MCPPipeline(cfg, Tool())
    first = pipeline.handle('s', call())
    approval_id = first['error']['data']['approval_id']
    pipeline.approvals.set_status(approval_id, 'approved', decided_by='reviewer')
    retry = call()
    retry['params']['_mcpzt_approval_id'] = approval_id
    assert 'result' in pipeline.handle('s', retry)
    events = [json.loads(line) for line in Path(cfg.audit.path).read_text().splitlines()]
    dispatch = next(e for e in events if e.get('upstream_status') == 'dispatch_intent')
    assert dispatch['approval_id'] == approval_id
    assert dispatch['request_binding'] == pipeline.approvals.get(approval_id).request_binding
    assert dispatch['arguments_hash'] == pipeline.approvals.get(approval_id).arguments_hash


@pytest.mark.parametrize("decision", ["redact", "limit", "transform", "require_approval"])
def test_external_output_action_without_enforcement_config_is_blocked(tmp_path, monkeypatch, decision):
    cfg = config(tmp_path, policy_engine={"adapter": "opa", "endpoint": "http://unused.invalid/opa"})
    def opa_post(url, *, json, timeout):
        result = True if json["input"]["context"]["direction"] == "inbound" else {"decision": decision}
        return httpx.Response(200, json={"result": result}, request=httpx.Request("POST", url))
    monkeypatch.setattr("mcp_zero_trust_layer.policy.adapters.httpx.post", opa_post)
    result = MCPPipeline(cfg, Tool()).handle("s", call())
    assert result["error"]["code"] == -32020
    assert "protected" not in json.dumps(result)
