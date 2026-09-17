"""Opt-in, read-only check against a real Stripe sandbox; never creates a refund.

MCPZT_STRIPE_SANDBOX_DIRECTORY must contain checker.json, request.json, bundle.json,
trust.json and the observer trust/key paths configured by checker.json. The named
API-key environment variable must hold a test key. No credential values are logged.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from mcp_zero_trust_layer.evidence.check_models import ObserverTrust, StripeCheckConfig
from mcp_zero_trust_layer.evidence.checks import (
    StripeRefundReader,
    check_refund,
    load_observer_private_key,
)
from mcp_zero_trust_layer.evidence.cli import read_json
from mcp_zero_trust_layer.evidence.models import TrustStore


@pytest.mark.skipif(not os.environ.get('MCPZT_STRIPE_SANDBOX_DIRECTORY'),
                    reason='Real Stripe sandbox artifacts/credentials not configured')
def test_real_stripe_sandbox_read_only():
    root = Path(os.environ['MCPZT_STRIPE_SANDBOX_DIRECTORY'])
    cfg = StripeCheckConfig.model_validate(read_json(root / 'checker.json'))
    reader = StripeRefundReader(os.environ.get(cfg.api_key_env, ''), cfg.account)
    try:
        document = check_refund(read_json(root / 'bundle.json'), read_json(root / 'request.json'),
            TrustStore.model_validate(read_json(root / 'trust.json')), cfg,
            ObserverTrust.model_validate(read_json(root / cfg.observer_trust_file)),
            load_observer_private_key(root / cfg.observer_private_key_file), reader)
        assert document.payload.result == 'corroborated', document.payload.reason
    finally:
        reader.close()
