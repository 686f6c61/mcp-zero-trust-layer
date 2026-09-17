from __future__ import annotations

import copy
import json
import os
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from mcp_zero_trust_layer.cli.main import app
from mcp_zero_trust_layer.evidence.canonical import digest
from mcp_zero_trust_layer.evidence.check_models import (
    CheckedBundle,
    ObserverKey,
    ObserverTrust,
    SignedObservation,
    StripeCheckConfig,
)
from mcp_zero_trust_layer.evidence.checks import (
    StripeRefundReader,
    check_refund,
    load_observer_private_key,
    observation_bytes,
    observation_digest,
)
from mcp_zero_trust_layer.evidence.crypto import encode, sign
from mcp_zero_trust_layer.evidence.models import Receipt
from mcp_zero_trust_layer.evidence.protocol import request_payload
from mcp_zero_trust_layer.evidence.store import database
from mcp_zero_trust_layer.evidence.verify import verify_bundle
from mcp_zero_trust_layer.identity import Identity

from .conftest import call


@pytest.fixture
def checked(env):
    service = env[4].evidence['refund']
    service.config.scope = 'stripe.refund.status.v1'
    service.trust.keys[1].scopes.append(service.config.scope)
    (env[0] / 'trust.json').write_text(service.trust.model_dump_json())
    message = call()
    message['params']['arguments'].update(currency='eur', charge='ch_demo', account='acct_demo')
    context = env[4]._context_for_message('refund', message, identity=Identity())
    op, forwarded = service.prepare(message, context)
    bundle = service.store.get(op, 'demo')
    auth = bundle['permit']['authorization']['payload']
    attempt = bundle['permit']['attempt']['payload']
    receipt = Receipt(
        issuer=auth['audience'], audience=auth['issuer'], tenant=auth['tenant'],
        operation_id=op, authorization_id=auth['authorization_id'], attempt_id=attempt['attempt_id'],
        receipt_id='receipt_demo', attempt_digest=digest('attempt', bundle['permit']),
        request_digest=auth['request_digest'], response_digest='0' * 64, response_nonce='1' * 64,
        effect='committed', scope=service.config.scope, transaction_ref='re_demo', sequence=1,
        recorded_at=auth['issued_at'])
    bundle['receipt'] = sign(receipt.model_dump(), 'receipt', 'destination-demo', env[2].key).model_dump()
    service.store.record(op, 'demo', {'phase': 'reconciled'}, bundle['receipt'])
    key = Ed25519PrivateKey.generate()
    observer = ObserverKey(kid='observer', issuer='checker', tenant='demo', destination='refund-demo',
        account='acct_demo', public_key=encode(key.public_key().public_bytes_raw()))
    trust = ObserverTrust(keys=[observer])
    config = StripeCheckConfig(tenant='demo', destination='refund-demo',
        receipt_scope=service.config.scope, tool='refund', account='acct_demo', api_key_env='TEST_STRIPE',
        observer_key_id='observer', observer_private_key_file='observer.key',
        observer_trust_file='observers.json')
    refund = {'id': 're_demo', 'object': 'refund', 'amount': 5000, 'currency': 'eur',
        'charge': 'ch_demo', 'created': auth['issued_at'], 'status': 'succeeded',
        'metadata': {'mcpzt_operation_id': op, 'mcpzt_authorization_id': auth['authorization_id'],
            'mcpzt_attempt_id': attempt['attempt_id'], 'mcpzt_request_digest': auth['request_digest']}}
    return {'env': env, 'service': service, 'op': op, 'bundle': bundle,
            'request': request_payload(forwarded), 'key': key, 'trust': trust,
            'config': config, 'refund': refund}


def perform(c, *, handler=None, **kwargs):
    seen = []
    def handle(request):
        seen.append(request)
        assert request.method == 'GET' and request.url.host == 'api.stripe.com'
        assert request.headers['stripe-account'] == 'acct_demo'
        if handler:
            return handler(request)
        return httpx.Response(200, json={'id': 'acct_demo'} if request.url.path == '/v1/account'
                              else c['refund'])
    reader = StripeRefundReader('rk_test_fixture', 'acct_demo', transport=httpx.MockTransport(handle))
    try:
        doc = check_refund(c['bundle'], c['request'], c['service'].trust, c['config'],
            c['trust'], c['key'], reader, **kwargs)
        return doc, seen
    finally:
        reader.close()


def envelope(c, docs):
    return CheckedBundle(evidence=c['bundle'], observations=docs).model_dump()


def test_signed_lie_is_authentic_but_external_source_contradicts(checked):
    c = checked
    c['refund']['status'] = 'failed'
    doc, seen = perform(c)
    assert [r.url.path for r in seen] == ['/v1/account', '/v1/refunds/re_demo']
    assert doc.payload.result == 'contradicted'
    verdict = verify_bundle(envelope(c, [doc]), c['service'].trust, observers=c['trust'])
    assert verdict['claim'] == 'destination_commit_attested'
    assert verdict['effect_basis'] == 'destination_attested'
    assert verdict['external_check']['history'][0]['reported_result'] == 'contradicted'
    assert verdict['external_check']['result'] == 'observer_attested'
    assert verdict['external_check']['provider_signature'] == 'not_provided'
    assert verdict['gateway_observation'] == 'not_in_bundle'
    assert c['env'][3].calls == 0  # neither the fixture nor checking executed any action


@pytest.mark.parametrize(('status', 'expected'), [
    ('succeeded', 'corroborated'), ('failed', 'contradicted'), ('canceled', 'contradicted'),
    ('pending', 'pending'), ('requires_action', 'pending'), ('future-status', 'unknown')])
def test_provider_status_has_narrow_meaning(checked, status, expected):
    checked['refund']['status'] = status
    doc, _ = perform(checked)
    assert doc.payload.result == expected


@pytest.mark.parametrize(('field', 'value'), [('amount', 5001), ('currency', 'usd'),
    ('charge', 'ch_other'), ('id', 're_other')])
def test_correct_signature_wrong_business_operation(checked, field, value):
    checked['refund'][field] = value
    assert perform(checked)[0].payload.reason == 'FIELD_MISMATCH'


@pytest.mark.parametrize('field', ['mcpzt_operation_id', 'mcpzt_authorization_id',
    'mcpzt_attempt_id', 'mcpzt_request_digest'])
def test_stale_other_operation_metadata_never_corroborates(checked, field):
    checked['refund']['metadata'][field] = 'other'
    assert perform(checked)[0].payload.reason == 'BINDING_MISMATCH'


@pytest.mark.parametrize(('field', 'value'), [('object', 'charge'), ('created', True),
    ('created', -1), ('amount', True), ('metadata', None)])
def test_malformed_source(checked, field, value):
    checked['refund'][field] = value
    assert perform(checked)[0].payload.result == 'unknown'


@pytest.mark.parametrize('status', [301, 401, 403, 404, 429, 500])
def test_missing_unavailable_or_redirect_is_unknown_and_not_retried(checked, status):
    def handler(req):
        if req.url.path == '/v1/account':
            return httpx.Response(200, json={'id': 'acct_demo'})
        return httpx.Response(status, headers={'location': 'https://attacker.invalid/'})
    doc, seen = perform(checked, handler=handler)
    assert len(seen) == 2 and doc.payload.result == 'unknown'
    assert doc.payload.reason == ('SOURCE_NOT_FOUND' if status == 404 else 'SOURCE_UNAVAILABLE')


def test_unavailable_account_timeout_invalid_json_and_size(checked):
    handlers = [lambda r: httpx.Response(403), lambda r: httpx.Response(200, content=b'{'),
        lambda r: httpx.Response(200, content=b'x' * 1048577),
        lambda r: (_ for _ in ()).throw(httpx.ReadTimeout('secret!'))]
    for handler in handlers:
        doc, seen = perform(checked, handler=handler)
        assert len(seen) <= 2 and doc.payload.result == 'unknown'
        assert 'secret!' not in doc.model_dump_json()


def test_bad_account_and_nonobject_refund(checked):
    doc, _ = perform(checked, handler=lambda r: httpx.Response(200, json={'id': 'acct_other'}))
    assert doc.payload.reason == 'ACCOUNT_MISMATCH'
    checked['refund'] = []
    assert perform(checked)[0].payload.reason == 'SOURCE_INVALID'


def test_invalid_receipt_reference_never_becomes_network_target(checked):
    receipt = checked['bundle']['receipt']['payload']
    receipt['transaction_ref'] = 'https://attacker.invalid/secret'
    checked['bundle']['receipt'] = sign(receipt, 'receipt', 'destination-demo',
                                      checked['env'][2].key).model_dump()
    doc, seen = perform(checked)
    assert seen == [] and doc.payload.result == 'unknown'


@pytest.mark.parametrize('kind', ['request', 'receipt', 'scope', 'account', 'observer',
    'retired', 'private_key', 'same_key', 'observer_scope', 'tool'])
def test_prerequisites_fail_before_queries(checked, kind):
    c = checked
    if kind == 'request':
        c['request']['params']['arguments']['amount_minor'] = 6000
    elif kind == 'receipt':
        c['bundle']['receipt'] = None
    elif kind == 'scope':
        c['config'].tenant = 'another'
    elif kind == 'account':
        c['config'].account = 'acct_other'
    elif kind == 'observer':
        c['trust'].keys = []
    elif kind == 'retired':
        c['trust'].keys[0].status = 'retired'
    elif kind == 'private_key':
        c['key'] = Ed25519PrivateKey.generate()
    elif kind == 'same_key':
        c['key'] = c['service'].key
        c['trust'].keys[0].public_key = encode(c['key'].public_key().public_bytes_raw())
    elif kind == 'observer_scope':
        c['trust'].keys[0].account = 'acct_other'
    else:
        # Re-sign a malformed permit claiming another tool for the exact same request.
        auth = c['bundle']['permit']['authorization']['payload']
        auth['tool'] = 'other'
        c['config'].tool = 'other'
        c['bundle']['permit']['authorization'] = sign(auth, 'authorization', 'gateway-demo', c['service'].key).model_dump()
        attempt = c['bundle']['permit']['attempt']['payload']
        attempt['authorization_digest'] = digest('authorization', c['bundle']['permit']['authorization'])
        c['bundle']['permit']['attempt'] = sign(attempt, 'attempt', 'gateway-demo', c['service'].key).model_dump()
        payload = c['bundle']['receipt']['payload']
        payload['attempt_digest'] = digest('attempt', c['bundle']['permit'])
        c['bundle']['receipt'] = sign(payload, 'receipt', 'destination-demo', c['env'][2].key).model_dump()
    def forbidden(_):
        pytest.fail('network attempted with invalid prerequisites')
    with pytest.raises(ValueError):
        perform(c, handler=forbidden)


def test_append_preserves_confirmation_then_failure_without_rewriting_receipt(checked):
    c = checked
    original = copy.deepcopy(c['bundle']['receipt'])
    first, _ = perform(c, now=100)
    c['service'].store.append_observation(c['op'], 'demo', first.model_dump())
    c['refund']['status'] = 'failed'
    second, _ = perform(c, now=200, previous=observation_digest(first))
    c['service'].store.append_observation(c['op'], 'demo', second.model_dump())
    exported = c['service'].store.checked_bundle(c['op'], 'demo')
    assert exported['evidence']['receipt'] == original
    verdict = verify_bundle(exported, c['service'].trust, observers=c['trust'], now=450)
    history = verdict['external_check']['history']
    assert [h['reported_result'] for h in history] == ['corroborated', 'contradicted']
    assert [h['fresh'] for h in history] == [False, True]
    assert verdict['external_check']['current_state'] == 'not_established_offline'
    assert verify_bundle(exported, c['service'].trust)['rejection'] == 'UNTRUSTED_OBSERVER'
    c['trust'].keys[0].status = 'retired'
    assert verify_bundle(exported, c['service'].trust, observers=c['trust'])['rejection'] is None
    c['trust'].keys[0].status = 'revoked'
    assert verify_bundle(exported, c['service'].trust, observers=c['trust'])['rejection']


@pytest.mark.parametrize('kind', ['signature', 'binding', 'chain', 'tamper', 'version'])
def test_offline_rejects_tampering_and_substitution(checked, kind):
    c = checked
    doc, _ = perform(c)
    raw = envelope(c, [doc])
    if kind == 'signature':
        raw['observations'][0]['signature'] = 'A' * 86
    elif kind == 'version':
        raw['version'] = 3
    elif kind == 'tamper':
        raw['observations'][0]['payload']['result'] = 'contradicted'
    else:
        payload = doc.payload.model_copy(update={
            'evidence_digest' if kind == 'binding' else 'previous_digest': 'f' * 64})
        raw['observations'][0] = SignedObservation(protected=doc.protected, payload=payload,
            signature=encode(c['key'].sign(observation_bytes(doc.protected, payload)))).model_dump()
    assert verify_bundle(raw, c['service'].trust, observers=c['trust'])['rejection']


def test_v2_no_observations_and_invalid_inner_evidence(checked):
    c = checked
    raw = envelope(c, [])
    assert verify_bundle(raw, c['service'].trust)['external_check']['verification'] == 'not_provided'
    raw['evidence']['permit']['attempt']['signature'] = 'A' * 86
    assert verify_bundle(raw, c['service'].trust)['rejection']


def test_concurrent_append_cannot_fork(checked):
    c = checked
    docs = [perform(c)[0] for _ in range(2)]
    def append(doc):
        try:
            c['service'].store.append_observation(c['op'], 'demo', doc.model_dump())
            return 'ok'
        except ValueError as exc:
            return str(exc)
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(append, docs)) == ['OBSERVATION_CONCURRENT_UPDATE', 'ok']
    assert len(c['service'].store.checked_bundle(c['op'], 'demo')['observations']) == 1


def test_store_rejects_missing_changed_conflicted_and_overfull(checked):
    c = checked
    doc, _ = perform(c)
    store = c['service'].store
    with pytest.raises(ValueError, match='OPERATION_NOT_FOUND'):
        store.append_observation(c['op'], 'other', doc.model_dump())
    changed = copy.deepcopy(doc.model_dump())
    changed['payload']['evidence_digest'] = 'f' * 64
    with pytest.raises(ValueError, match='OBSERVATION_BINDING_MISMATCH'):
        store.append_observation(c['op'], 'demo', changed)
    with database(store.path) as db:
        for n in range(256):
            db.execute('INSERT INTO evidence_v2_observations(operation_id,digest,document) VALUES(?,?,?)',
                       (c['op'], str(n), '{}'))
    with pytest.raises(ValueError, match='OBSERVATION_LIMIT'):
        store.append_observation(c['op'], 'demo', doc.model_dump())
    store.record(c['op'], 'demo', {'phase': 'receipt_conflict'})
    with pytest.raises(ValueError, match='RECEIPT_CONFLICT'):
        store.append_observation(c['op'], 'demo', doc.model_dump())


def test_configuration_and_key_safety(checked, tmp_path):
    c = checked
    with pytest.raises(ValueError):
        ObserverTrust(keys=[c['trust'].keys[0], c['trust'].keys[0]])
    for key in ['', 'sk_live_disallowed', 'sk_test_newline\n']:
        with pytest.raises(ValueError, match='TEST_MODE_KEY_REQUIRED'):
            StripeRefundReader(key, 'acct_demo')
    keyfile = tmp_path / 'key'
    keyfile.write_text(encode(c['key'].private_bytes_raw()))
    keyfile.chmod(0o644)
    with pytest.raises(ValueError, match='PRIVATE'):
        load_observer_private_key(keyfile)
    keyfile.chmod(0o600)
    assert load_observer_private_key(keyfile).private_bytes_raw() == c['key'].private_bytes_raw()
    doc, _ = perform(c)
    with pytest.raises(ValueError, match='INVALID_CHECK_INTERVAL'):
        doc.payload.model_validate({**doc.payload.model_dump(), 'expires_at': doc.payload.checked_at})
    with pytest.raises(ValueError, match='MISSING_SOURCE_COMMITMENT'):
        doc.payload.model_validate({**doc.payload.model_dump(), 'source_digest': None})
    with pytest.raises(ValueError, match='INCONSISTENT_SOURCE_STATUS'):
        doc.payload.model_validate({**doc.payload.model_dump(), 'source_status': 'failed'})
    with pytest.raises(ValueError, match='INVALID_STRIPE_ACCOUNT'):
        StripeRefundReader('rk_test_fixture', 'acct_demo\r\nHeader: injected')


def test_observation_cannot_elevate_authorization_only_bundle(checked):
    c = checked
    doc, _ = perform(c)
    raw = envelope(c, [doc])
    raw['evidence']['receipt'] = None
    assert verify_bundle(raw, c['service'].trust, observers=c['trust'])['rejection'] == 'OBSERVATION_EFFECT_SCOPE_MISMATCH'


def test_cli_check_export_offline_and_schema(checked, monkeypatch):
    c = checked
    root = c['env'][0]
    (root / 'checker.json').write_text(c['config'].model_dump_json())
    (root / 'observers.json').write_text(c['trust'].model_dump_json())
    fd = os.open(root / 'observer.key', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(encode(c['key'].private_bytes_raw()))
    (root / 'request.json').write_text(json.dumps(c['request']))
    monkeypatch.setenv('TEST_STRIPE', 'rk_test_fixture')
    monkeypatch.setattr(StripeRefundReader, 'read', lambda self, ref: (200, {'id': 'acct_demo'}, c['refund']))
    runner = CliRunner()
    opts = ['--config', str(root / 'mcpzt.yaml'), '--server', 'refund']
    args = ['evidence', 'check', c['op'], *opts, '--checker', str(root / 'checker.json'),
            '--request', str(root / 'request.json')]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)['external_check']['basis'] == 'online_provider_query'
    c['refund']['status'] = 'failed'
    assert runner.invoke(app, args).exit_code == 1
    output = root / 'v2.json'
    assert runner.invoke(app, ['evidence', 'export', c['op'], *opts, '--version', '2',
                               '--output', str(output)]).exit_code == 0
    result = runner.invoke(app, ['evidence', 'verify', str(output), '--trust', str(root / 'trust.json'),
                               '--observers', str(root / 'observers.json')])
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.output)['external_check']['history']) == 2
    import jsonschema
    schema = json.loads(runner.invoke(app, ['evidence', 'schema', '--version', '2']).output)
    jsonschema.validate(json.loads(output.read_text()), schema)
    result = runner.invoke(app, ['evidence', 'show', c['op'], *opts,
                                 '--observers', str(root / 'observers.json')])
    assert result.exit_code == 0
    assert len(json.loads(result.output)['verdict']['external_check']['history']) == 2
    legacy = root / 'v1.json'
    assert runner.invoke(app, ['evidence', 'export', c['op'], *opts, '--version', '1',
                              '--output', str(legacy)]).exit_code == 0
    assert json.loads(legacy.read_text())['version'] == 1
    c['trust'].keys[0].status = 'revoked'
    (root / 'observers.json').write_text(c['trust'].model_dump_json())
    monkeypatch.setattr(StripeRefundReader, 'read', lambda *a: pytest.fail('corrupt history queried'))
    assert runner.invoke(app, args).exit_code == 2
    c['trust'].keys[0].status = 'active'
    (root / 'observers.json').write_text(c['trust'].model_dump_json())
    monkeypatch.delenv('TEST_STRIPE')
    result = runner.invoke(app, args)
    assert result.exit_code == 2 and 'TEST_STRIPE' not in result.output


def test_adversarial_demo_timeout_reconciliation_and_export(tmp_path):
    root = tmp_path / 'adversarial'
    runner = CliRunner()
    result = runner.invoke(app, ['evidence', 'check-demo', '--directory', str(root)])
    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report['destination_methods'] == ['tools/call', 'mcpzt/evidence/get']
    assert report['provider_contacted'] is False and report['administration'] == 'shared'
    assert all(r['method'] == 'GET' for r in report['provider_requests'])
    assert [c['result'] for c in report['cases']] == [
        'contradicted', 'corroborated', 'contradicted', 'contradicted', 'pending', 'unknown']
    assert json.loads((root / 'bundle-at-timeout.json').read_text())['receipt'] is None
    result = runner.invoke(app, ['evidence', 'verify', str(root / 'bundle-v2.json'),
        '--trust', str(root / 'trust.json'), '--observers', str(root / 'observers.json'),
        '--request', str(root / 'request-preimage.json')])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)['external_check']['result'] == 'observer_attested'
    assert runner.invoke(app, ['evidence', 'check-demo', '--directory', str(root)]).exit_code != 0


def test_real_http_reader_checks_without_any_business_write(checked):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    seen = []
    c = checked

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen.append(('GET', self.path, self.headers['Stripe-Account']))
            payload = {'id': 'acct_demo'} if self.path == '/v1/account' else c['refund']
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            seen.append(('POST', self.path, ''))
            self.send_error(405)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    class LocalTransport(httpx.HTTPTransport):
        def handle_request(self, request):
            assert request.url.host == 'api.stripe.com'
            request.url = request.url.copy_with(scheme='http', host='127.0.0.1', port=server.server_port)
            return super().handle_request(request)

    reader = StripeRefundReader('rk_test_fixture', 'acct_demo', transport=LocalTransport())
    try:
        doc = check_refund(c['bundle'], c['request'], c['service'].trust, c['config'],
                          c['trust'], c['key'], reader)
        assert doc.payload.result == 'corroborated'
        assert seen == [('GET', '/v1/account', 'acct_demo'), ('GET', '/v1/refunds/re_demo', 'acct_demo')]
    finally:
        reader.close()
        server.shutdown()
        server.server_close()
        thread.join()


def test_frozen_public_cases_and_independent_node_signatures():
    import subprocess
    from pathlib import Path

    from mcp_zero_trust_layer.evidence.models import TrustStore

    root = Path(__file__).resolve().parents[2] / 'examples/evidence/external-checks'
    trust = TrustStore.model_validate_json((root / 'trust.json').read_text())
    observers = ObserverTrust.model_validate_json((root / 'observers.json').read_text())
    assert not list(root.glob('*.key'))
    for name, expected in [('signed-lie', 'contradicted'), ('corroborated', 'corroborated'),
                           ('later-failure', 'contradicted'), ('not-found', 'unknown')]:
        raw = json.loads((root / f'{name}.json').read_text())
        verdict = verify_bundle(raw, trust, observers=observers)
        assert verdict['rejection'] is None
        assert verdict['external_check']['history'][-1]['reported_result'] == expected
    result = subprocess.run(['node', '--input-type=module', '-e', r'''
        import {readFileSync} from 'node:fs';
        import {createPublicKey, verify, createHash} from 'node:crypto';
        import assert from 'node:assert/strict';
        const root = process.argv[1];
        const bundle = JSON.parse(readFileSync(root + '/bundle-v2.json'));
        const trust = JSON.parse(readFileSync(root + '/observers.json'));
        const jcs = value => value === null || typeof value !== 'object' ? JSON.stringify(value) :
          Array.isArray(value) ? '[' + value.map(jcs).join(',') + ']' :
          '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + jcs(value[k])).join(',') + '}';
        const domain = 'mcpzt.evidence.v2:external_observation:';
        let previous = null;
        for (const doc of bundle.observations) {
          const trusted = trust.keys.find(k => k.kid === doc.protected.kid);
          const key = createPublicKey({format: 'der', type: 'spki', key: Buffer.concat([
            Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(trusted.public_key, 'base64url')])});
          assert(verify(null, Buffer.from(domain + jcs({protected: doc.protected, payload: doc.payload})),
                        key, Buffer.from(doc.signature, 'base64url')));
          assert.equal(doc.payload.previous_digest, previous);
          previous = createHash('sha256').update(domain + 'chain:' + jcs(doc)).digest('hex');
        }
        console.log(bundle.observations.length);
    ''', str(root)], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == '6'
