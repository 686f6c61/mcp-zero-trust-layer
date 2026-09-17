from __future__ import annotations

import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.evidence.crypto import sign
from mcp_zero_trust_layer.evidence.models import Bundle, Permit
from mcp_zero_trust_layer.evidence.protocol import (
    IDEMPOTENCY,
    LOOKUP,
    META,
    request_payload,
    response_payload,
    split_response,
)
from mcp_zero_trust_layer.evidence.runtime import EvidenceRuntime
from mcp_zero_trust_layer.evidence.store import EvidenceStore, database
from mcp_zero_trust_layer.evidence.verify import verify_bundle
from mcp_zero_trust_layer.identity import Identity

from .conftest import call


def operation(env):
    directory, cfg, dest, peer, pipeline = env
    assert 'result' in pipeline.handle('refund', call())
    service = pipeline.evidence['refund']
    op = peer.message['params']['_meta'][META]['authorization']['payload']['operation_id']
    return op, service, service.store.get(op, 'demo')


def ledger(env):
    with database(env[0] / 'destination.sqlite3') as db:
        return [tuple(row) for row in db.execute('SELECT amount_minor FROM refunds')]


def test_allow_deny_binding_and_raw_filtering(env):
    op, service, bundle = operation(env)
    peer, pipeline = env[3:]
    verdict = verify_bundle(bundle, service.trust, request=request_payload(peer.message),
                            response=response_payload(peer.response))
    assert verdict['claim'] == 'destination_commit_attested'
    assert verdict['request_content'] == verdict['response_content'] == 'verified'
    assert verdict['completeness'] == 'unknown'
    assert verdict['execution_uniqueness'] == 'not_proven'
    denied = pipeline.handle('refund', call(50000, 'deny'))
    assert denied['error']['code'] == -32001 and peer.calls == 1
    assert ledger(env) == [(5000,)]
    events = service.store.events(op, 'demo')
    assert [e['phase'] for e in events] == ['dispatch_intent', 'response_observed', 'client_response_prepared']
    assert 'Refund recorded' not in json.dumps(events)
    with pytest.raises(ValueError, match='OPERATION_NOT_FOUND'):
        service.store.get(op, 'other-tenant')


def test_replay_is_not_a_second_dispatch_even_after_restart(env):
    op, service, _ = operation(env)
    pipeline = MCPPipeline(env[1], env[3])
    result = pipeline.handle('refund', call())
    assert result['error']['code'] == -32052
    assert result['error']['data']['operation_id'] == op
    assert env[3].calls == 1 and ledger(env) == [(5000,)]
    with pytest.raises(ValueError, match='IDEMPOTENCY_CONFLICT'):
        context = pipeline._context_for_message('refund', call(6000), identity=Identity())
        service.prepare(call(6000), context)


def test_concurrent_callers_claim_once(env):
    pipeline = env[4]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: pipeline.handle('refund', call()), range(8)))
    assert sum('result' in result for result in results) == 1
    assert sum(result.get('error', {}).get('code') == -32052 for result in results) == 7
    assert ledger(env) == [(5000,)] and env[3].calls == 1


@pytest.mark.parametrize('when', ['before', 'after', 'none', 'missing', 'bad_signature', 'post_audit'])
def test_unknown_outcome_reconciles_without_resending(env, monkeypatch, when):
    dest, peer, pipeline = env[2:]
    def failing(server, message, *, headers=None):
        peer.message = copy.deepcopy(message)
        if when == 'before':
            raise TimeoutError('private credentials must not escape')
        result = dest.handle(message)
        if when == 'after':
            raise TimeoutError('committed but reply lost')
        if when == 'none':
            return None
        if when == 'missing':
            return split_response(result)[0]
        if when == 'bad_signature':
            result['result']['_meta'][META]['signature'] = 'A' * 86
        return result
    monkeypatch.setattr(peer, 'send', failing)
    if when == 'post_audit':
        original = pipeline._log_decision
        def fail_outcome(*args, **kwargs):
            if kwargs.get('upstream_status') == 'response_received':
                raise OSError('disk full')
            return original(*args, **kwargs)
        monkeypatch.setattr(pipeline, '_log_decision', fail_outcome)
    result = pipeline.handle('refund', call())
    assert result['error']['code'] == -32051
    assert 'private' not in json.dumps(result)
    op = result['error']['data']['operation_id']
    service = pipeline.evidence['refund']
    assert service.store.events(op, 'demo')[-1]['phase'] == 'outcome_unavailable'
    if when == 'before':
        with pytest.raises(ValueError, match='RECONCILIATION_UNKNOWN'):
            service.reconcile(op, dest.handle)
        assert ledger(env) == []
    else:
        assert service.reconcile(op, dest.handle)['effect'] == 'committed'
        assert ledger(env) == [(5000,)]
        assert pipeline.handle('refund', call())['error']['code'] == -32052


def test_observe_does_not_require_receipt_but_records_missing(env, monkeypatch):
    pipeline = env[4]
    pipeline.evidence['refund'].config.mode = 'observe'
    original = env[3].send
    monkeypatch.setattr(env[3], 'send', lambda *a, **k: split_response(original(*a, **k))[0])
    result = pipeline.handle('refund', call())
    assert 'result' in result and META not in json.dumps(result)


def test_output_redaction_and_error_commitments_are_distinct(env):
    from mcp_zero_trust_layer.config.models import PolicyConfig
    env[1].policies.append(PolicyConfig.model_validate({'id': 'redact', 'effect': 'redact',
        'when': {'output.structuredContent.amount_minor': {'exists': True}},
        'output': {'redact_fields': ['amount_minor']}}))
    pipeline = MCPPipeline(env[1], env[3])
    response = pipeline.handle('refund', call())
    assert response['result']['structuredContent']['amount_minor'] != 5000
    op = env[3].message['params']['_meta'][META]['authorization']['payload']['operation_id']
    events = pipeline.evidence['refund'].store.events(op, 'demo')
    assert events[1]['response_digest'] != events[-1]['digest']
    original = {'error': {'code': -1, 'message': 'failure', 'data': {'reason': 'some effect may exist'}}}
    with_receipt = copy.deepcopy(original)
    with_receipt['error']['data']['_meta'] = {META: {'untrusted': True}}
    clean, receipt = split_response(with_receipt)
    assert clean == original and receipt == {'untrusted': True}
    assert response_payload(with_receipt) == original


def test_approvals_consumption_and_reservation_are_atomic(env, monkeypatch):
    from mcp_zero_trust_layer.config.models import PolicyConfig
    env[1].policies = [PolicyConfig(id='review', effect='require_approval')]
    pipeline = MCPPipeline(env[1], env[3])
    pending = pipeline.handle('refund', call())
    aid = pending['error']['data']['approval_id']
    pipeline.approvals.set_status(aid, 'approved', decided_by='reviewer')
    retry = call()
    retry['params']['_mcpzt_approval_id'] = aid
    original = EvidenceStore.append
    monkeypatch.setattr(EvidenceStore, 'append', staticmethod(lambda *a: (_ for _ in ()).throw(OSError())))
    assert pipeline.handle('refund', retry)['error']['code'] == -32050
    assert pipeline.approvals.get(aid).status == 'approved'
    assert ledger(env) == []
    monkeypatch.setattr(EvidenceStore, 'append', staticmethod(original))
    assert 'result' in pipeline.handle('refund', retry)
    assert pipeline.approvals.get(aid).status == 'consumed'
    assert pipeline.handle('refund', retry)['error']['code'] == -32010
    assert ledger(env) == [(5000,)]


@pytest.mark.parametrize('mutation', ['resources/read', 'prompts/get', LOOKUP, 'tools/call-notification', 'forgery'])
def test_unsupported_and_client_forgery_are_not_dispatched(env, mutation):
    message = call()
    if mutation == 'forgery':
        message['params']['_meta'][META] = {'caller': 'not-authoritative'}
    elif mutation == 'tools/call-notification':
        message.pop('id')
    else:
        message['method'] = mutation
    assert 'error' in env[4].handle('refund', message)
    assert env[3].calls == 0


@pytest.mark.parametrize('kind', ['dry_run', 'audit', 'backend', 'path'])
def test_incomplete_runtime_is_rejected(env, kind):
    cfg = env[1]
    if kind == 'dry_run':
        cfg.runtime.dry_run = True
    elif kind == 'audit':
        cfg.audit.strict = False
    elif kind == 'backend':
        cfg.approvals.backend = 'file'
    else:
        cfg.approvals.path += '.other'
    with pytest.raises(ValueError):
        MCPPipeline(cfg, env[3])


def test_destination_deduplicates_concurrent_transport_replay(env):
    operation(env)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: env[2].handle(env[3].message), range(8)))
    assert all(r == results[0] for r in results)
    assert ledger(env) == [(5000,)]


def test_signing_failure_after_commit_can_recover(env, monkeypatch):
    import mcp_zero_trust_layer.evidence.destination as module
    original = module.sign
    monkeypatch.setattr(module, 'sign', lambda *a, **k: (_ for _ in ()).throw(ValueError('key unavailable')))
    result = env[4].handle('refund', call())
    op = result['error']['data']['operation_id']
    assert ledger(env) == [(5000,)]
    monkeypatch.setattr(module, 'sign', original)
    assert env[4].evidence['refund'].reconcile(op, env[2].handle)['effect'] == 'committed'
    assert ledger(env) == [(5000,)]


def test_reconciliation_conflict_is_durable_and_blocks_export(env):
    op, service, bundle = operation(env)
    altered = copy.deepcopy(bundle['receipt']['payload'])
    altered.update(sequence=2, transaction_ref='contradictory')
    receipt = sign(altered, 'receipt', 'destination-demo', env[2].key).model_dump()
    with pytest.raises(ValueError, match='RECEIPT_CONFLICT'):
        service.reconcile(op, lambda m: {'result': {'receipt': receipt}})
    with pytest.raises(ValueError, match='RECEIPT_CONFLICT'):
        service.store.get(op, 'demo')


def test_prerequisite_failure_and_unknown_storage_failure(env, monkeypatch):
    service = env[4].evidence['refund']
    monkeypatch.setattr(service.store, 'flush', lambda emit: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(service.store, 'record', lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError()))
    result = env[4].handle('refund', call())
    assert result['error']['code'] == -32051 and env[3].calls == 0


def test_database_permissions_outbox_and_not_found(env, tmp_path):
    path = tmp_path / 'public.db'
    path.touch(mode=0o644)
    with pytest.raises(ValueError, match='private'), database(path):
        pass
    op, service, _ = operation(env)
    with pytest.raises(ValueError, match='OPERATION_NOT_FOUND'):
        service.store.record('absent', 'demo', {})
    with pytest.raises(ValueError, match='APPROVAL_NOT_ACTIVE'):
        service.prepare(call(key='new'), env[4]._context_for_message('refund', call(), identity=Identity()), lambda db: False)
    emitted = []
    service.store.record(op, 'demo', {'phase': 'test'})
    service.store.flush(emitted.append)
    service.store.flush(emitted.append)
    assert len(emitted) == 1


def test_private_scope_salt_survives_runtime_restart(env):
    service = env[4].evidence['refund']
    restarted = EvidenceRuntime(service.config)
    assert service.private_digest('scope', ['alice']) == restarted.private_digest('scope', ['alice'])


def test_request_metadata_contract(env):
    message = call()
    message['params']['_meta']['application'] = {'important': True}
    expected = request_payload(message)
    assert IDEMPOTENCY not in expected['params']['_meta']
    assert expected['params']['_meta']['application'] == {'important': True}
    assert 'result' in env[4].handle('refund', message)
    changed = copy.deepcopy(env[3].message)
    changed['params']['_meta']['application']['important'] = False
    assert 'error' in env[2].handle(changed)


def test_signed_new_attempt_cannot_reexecute_existing_operation(env):
    op, service, bundle = operation(env)
    permit = Permit.model_validate(bundle['permit'])
    attempt = copy.deepcopy(permit.attempt.payload)
    attempt['attempt_id'] = 'different'
    permit.attempt = sign(attempt, 'attempt', 'gateway-demo', service.key)
    changed = copy.deepcopy(env[3].message)
    changed['params']['_meta'][META] = permit.model_dump()
    assert 'error' in env[2].handle(changed)
    assert ledger(env) == [(5000,)]
    assert verify_bundle(Bundle(permit=permit).model_dump(), service.trust)['claim'] == 'authorization_recorded'


def test_pending_receipt_can_advance_but_never_regress(env):
    pipeline, peer = env[4], env[3]
    service = pipeline.evidence['refund']
    context = pipeline._context_for_message('refund', call(), identity=Identity())
    op, forwarded = service.prepare(call(), context)
    terminal = peer.send(env[1].servers[0], forwarded)['result']['_meta'][META]
    pending_payload = {**terminal['payload'], 'effect': 'pending', 'transaction_ref': None}
    pending = sign(pending_payload, 'receipt', 'destination-demo', env[2].key).model_dump()
    assert service.reconcile(op, lambda m: {'result': {'receipt': pending}})['effect'] == 'pending'
    done = sign({**terminal['payload'], 'sequence': 2}, 'receipt', 'destination-demo', env[2].key).model_dump()
    assert service.reconcile(op, lambda m: {'result': {'receipt': done}})['effect'] == 'committed'
    with pytest.raises(ValueError, match='RECEIPT_CONFLICT'):
        service.reconcile(op, lambda m: {'result': {'receipt': pending}})


def test_deep_request_is_rejected_before_copy_or_dispatch(env):
    message = call()
    nested = value = {}
    for _ in range(1100):
        value['nested'] = {}
        value = value['nested']
    message['params']['arguments']['nested'] = nested
    assert env[4].handle('refund', message)['error']['code'] == -32602
    assert env[3].calls == 0
