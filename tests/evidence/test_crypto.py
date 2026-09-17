from __future__ import annotations

import copy
import json
import math
import subprocess

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from mcp_zero_trust_layer.config.models import EvidenceConfig
from mcp_zero_trust_layer.evidence.canonical import MAX_BYTES, canonical, digest, loads
from mcp_zero_trust_layer.evidence.crypto import decode, sign, verify_signature
from mcp_zero_trust_layer.evidence.models import (
    Attempt,
    Authorization,
    Permit,
    Receipt,
    Signed,
    TrustStore,
)
from mcp_zero_trust_layer.evidence.protocol import (
    request_payload,
    response_payload,
    validate_client,
)
from mcp_zero_trust_layer.evidence.runtime import EvidenceRuntime, load_private_key, local_path
from mcp_zero_trust_layer.evidence.verify import verify_bundle, verify_permit
from mcp_zero_trust_layer.protocol.jsonrpc import strict_json_loads

from .conftest import call
from .test_receipts import operation


@pytest.mark.parametrize('value', [math.nan, math.inf, -math.inf, 2**53, -(2**53), '\ud800',
                                   {1: 'not a string key'}, (1, 2), b'bytes', {'x': object()}])
def test_noncanonical_inputs_fail(value):
    with pytest.raises((ValueError, TypeError)):
        canonical(value)


def test_bounded_duplicate_and_deep_json():
    with pytest.raises(ValueError):
        canonical('x' * MAX_BYTES)
    with pytest.raises(ValueError):
        loads(' ' * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        loads('{"a":1,"a":2}')
    with pytest.raises(ValueError):
        loads('[' * 3000 + '0' + ']' * 3000)
    with pytest.raises(ValueError):
        loads(b'\xff')
    with pytest.raises(ValueError):
        canonical([[[[1]]]], depth=32)
    assert loads('{"a":1}') == {'a': 1}


@pytest.mark.parametrize('raw', ['{"x":1,"x":2}', 'NaN', 'Infinity', '[' * 3000])
def test_ingress_rejects_ambiguous_json(raw):
    with pytest.raises(json.JSONDecodeError):
        strict_json_loads(raw)


@given(st.dictionaries(st.text(alphabet='abcé😀', min_size=1, max_size=5), st.integers(-100000, 100000), max_size=8))
def test_jcs_invariant_under_object_reordering(value):
    assert canonical(value) == canonical(dict(reversed(list(value.items()))))
    assert loads(canonical(value)) == value


def test_jcs_independent_javascript_vector():
    # UTF-16 key order, negative zero, exponent rules, escaping and nested arrays.
    vectors = [{'😀': 1, '\ue000': 2, 'a': [1e-7, 1e20, -0.0, 'line\n']},
               {'é': 'e\u0301', 'z': {'b': True, 'a': None}}]
    code = '''const fs=require('fs');
    function jcs(x) { if(Array.isArray(x)) return '['+x.map(jcs).join(',')+']';
      if(x!==null && typeof x==='object') return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+jcs(x[k])).join(',')+'}';
      return JSON.stringify(x); }
    process.stdout.write(JSON.parse(fs.readFileSync(0,'utf8')).map(jcs).join('\\n'));'''
    output = subprocess.run(['node', '-e', code], input=json.dumps(vectors), text=True,
                            capture_output=True, check=True).stdout
    assert output.splitlines() == [canonical(v).decode() for v in vectors]


@pytest.mark.parametrize('where,field,value', [
    ('authorization', 'decision', 'deny'), ('authorization', 'expires_at', 0),
    ('authorization', 'unexpected', True), ('attempt', 'nonce', 'bad'),
    ('receipt', 'sequence', 0), ('receipt', 'transaction_ref', None),
    ('receipt', 'scope', ''),
])
def test_signed_payload_schema_is_strict(env, where, field, value):
    _, service, bundle = operation(env)
    target = bundle['receipt'] if where == 'receipt' else bundle['permit'][where]
    target['payload'][field] = value
    assert verify_bundle(bundle, service.trust)['rejection']


@pytest.mark.parametrize('where', ['authorization', 'attempt', 'receipt'])
def test_changed_signature_rejected(env, where):
    _, service, bundle = operation(env)
    target = bundle['receipt'] if where == 'receipt' else bundle['permit'][where]
    target['signature'] = 'A' * 86
    assert verify_bundle(bundle, service.trust)['rejection'] == 'INVALID_SIGNATURE'


@pytest.mark.parametrize('field,value', [('alg', 'none'), ('version', 2), ('kind', 'unknown')])
def test_header_cannot_downgrade(env, field, value):
    _, service, bundle = operation(env)
    bundle['receipt']['protected'][field] = value
    assert verify_bundle(bundle, service.trust)['rejection']


@pytest.mark.parametrize('field,value', [('role', 'gateway'), ('issuer', 'other'),
    ('audience', 'other'), ('tenant', 'other'), ('status', 'revoked'), ('kid', 'other')])
def test_trust_is_bound_to_role_issuer_audience_tenant(env, field, value):
    _, service, bundle = operation(env)
    trust = service.trust.model_copy(deep=True)
    setattr(trust.keys[1], field, value)
    assert verify_bundle(bundle, trust)['rejection']


def test_unknown_scope_and_current_vs_historical_time(env):
    _, service, bundle = operation(env)
    trust = service.trust.model_copy(deep=True)
    trust.keys[1].scopes = []
    assert verify_bundle(bundle, trust)['rejection'] == 'UNTRUSTED_EFFECT_SCOPE'
    permit = Permit.model_validate(bundle['permit'])
    assert verify_bundle(bundle, service.trust)['effect'] == 'committed'
    with pytest.raises(ValueError, match='PERMIT_NOT_CURRENT'):
        verify_permit(permit, service.trust, now=permit.authorization.payload['expires_at'])
    trust = service.trust.model_copy(deep=True)
    trust.keys[0].status = 'retired'
    assert verify_bundle(bundle, trust)['effect'] == 'committed'
    with pytest.raises(ValueError, match='PERMIT_NOT_CURRENT'):
        verify_permit(permit, trust, now=permit.authorization.payload['issued_at'])


@pytest.mark.parametrize('field', ['issuer', 'audience', 'tenant', 'operation_id', 'authorization_id',
                                  'attempt_id', 'request_digest', 'attempt_digest'])
def test_validly_signed_receipt_for_other_request_is_not_accepted(env, field):
    _, service, bundle = operation(env)
    payload = copy.deepcopy(bundle['receipt']['payload'])
    payload[field] = 'a' * 64 if 'digest' in field else 'other'
    bundle['receipt'] = sign(payload, 'receipt', 'destination-demo', env[2].key).model_dump()
    assert verify_bundle(bundle, service.trust)['rejection']


@pytest.mark.parametrize('field', ['operation_id', 'authorization_digest'])
def test_validly_signed_attempt_substitution_rejected(env, field):
    _, service, bundle = operation(env)
    payload = copy.deepcopy(bundle['permit']['attempt']['payload'])
    payload[field] = 'b' * 64 if 'digest' in field else 'other'
    bundle['permit']['attempt'] = sign(payload, 'attempt', 'gateway-demo', service.key).model_dump()
    assert verify_bundle(bundle, service.trust)['rejection']


def test_request_result_substitution_and_no_receipt(env):
    _, service, bundle = operation(env)
    assert verify_bundle(bundle, service.trust, request={'changed': True})['rejection'] == 'REQUEST_MISMATCH'
    assert verify_bundle(bundle, service.trust, response={'changed': True})['rejection'] == 'RESPONSE_MISMATCH'
    bundle['receipt'] = None
    assert verify_bundle(bundle, service.trust)['claim'] == 'authorization_recorded'


@pytest.mark.parametrize('effect', ['pending', 'failed', 'rejected', 'partially_committed'])
def test_noncommitted_receipt_does_not_claim_commit(env, effect):
    _, service, bundle = operation(env)
    payload = copy.deepcopy(bundle['receipt']['payload'])
    payload['effect'] = effect
    bundle['receipt'] = sign(payload, 'receipt', 'destination-demo', env[2].key).model_dump()
    verdict = verify_bundle(bundle, service.trust)
    assert verdict['effect'] == effect and verdict['claim'] == 'destination_receipt_verified'


def test_schema_trust_key_and_encoding_rejections(env):
    _, service, bundle = operation(env)
    document = Signed.model_validate(bundle['receipt'])
    with pytest.raises(ValueError, match='WRONG_DOCUMENT_KIND'):
        verify_signature(document, service.trust, 'attempt')
    with pytest.raises(ValueError):
        decode('AB')
    raw = service.trust.model_dump()
    raw['keys'].append(raw['keys'][0])
    with pytest.raises(ValueError, match='duplicate'):
        TrustStore.model_validate(raw)
    with pytest.raises(ValueError, match='requires'):
        EvidenceConfig(mode='required')
    assert EvidenceConfig().mode == 'off'
    for cls, value in [(Authorization, bundle['permit']['authorization']['payload']),
                       (Attempt, bundle['permit']['attempt']['payload']),
                       (Receipt, bundle['receipt']['payload'])]:
        with pytest.raises(ValidationError):
            cls.model_validate({**value, 'unrecognized': 1})


@pytest.mark.parametrize('key', [0, '', 'x' * 129])
def test_bad_idempotency_keys(key):
    with pytest.raises(ValueError):
        validate_client(call(key=key))


def test_invalid_metadata_shapes():
    message = call()
    message['params']['_meta'] = []
    with pytest.raises(ValueError):
        request_payload(message)
    with pytest.raises(ValueError):
        validate_client(message)
    assert response_payload({'error': {'code': -1, 'message': 'x'}}) == {'error': {'code': -1, 'message': 'x'}}


@pytest.mark.parametrize('change', ['private', 'own_missing', 'dest_missing', 'wrong_public'])
def test_key_configuration_prerequisites(env, change):
    directory, cfg = env[:2]
    if change == 'private':
        (directory / 'gateway.key').chmod(0o644)
        with pytest.raises(ValueError):
            load_private_key(directory / 'gateway.key')
    else:
        trust = json.loads((directory / 'trust.json').read_text())
        if change == 'own_missing':
            trust['keys'] = trust['keys'][1:]
        elif change == 'dest_missing':
            trust['keys'] = trust['keys'][:1]
        else:
            trust['keys'][0]['public_key'] = trust['keys'][1]['public_key']
        (directory / 'trust.json').write_text(json.dumps(trust))
        with pytest.raises(ValueError):
            EvidenceRuntime(cfg.servers[0].evidence)
    assert local_path('relative', str(directory)) == directory / 'relative'


def test_destination_bad_scope_business_rule_and_method(env):
    _, service, bundle = operation(env)
    assert env[2].handle({'method': 'notifications/initialized'}) is None
    for method in ['initialize', 'tools/list']:
        assert 'result' in env[2].handle({'id': 2, 'method': method})
    assert 'error' in env[2].handle({'id': 2, 'method': 'unknown'})
    with pytest.raises(ValueError):
        env[2]._audience('other', 'demo')
    message = copy.deepcopy(env[3].message)
    message['params']['arguments']['amount_minor'] = 60000
    auth = copy.deepcopy(bundle['permit']['authorization']['payload'])
    auth['request_digest'] = digest('request', request_payload(message), auth['request_nonce'])
    signed_auth = sign(auth, 'authorization', 'gateway-demo', service.key)
    attempt = copy.deepcopy(bundle['permit']['attempt']['payload'])
    attempt['authorization_digest'] = digest('authorization', signed_auth.model_dump())
    permit = Permit(authorization=signed_auth, attempt=sign(attempt, 'attempt', 'gateway-demo', service.key))
    from mcp_zero_trust_layer.evidence.protocol import META
    message['params']['_meta'][META] = permit.model_dump()
    assert 'error' in env[2].handle(message)


def test_parser_recursion_failure_is_a_parse_error(monkeypatch):
    monkeypatch.setattr(json, 'loads', lambda *a, **k: (_ for _ in ()).throw(RecursionError()))
    with pytest.raises(json.JSONDecodeError, match='nesting limit'):
        strict_json_loads('{}')


def test_gateway_and_destination_cannot_share_signing_key(env):
    trust = env[4].evidence['refund'].trust.model_dump()
    trust['keys'][1]['public_key'] = trust['keys'][0]['public_key']
    with pytest.raises(ValueError, match='separate signing keys'):
        TrustStore.model_validate(trust)
