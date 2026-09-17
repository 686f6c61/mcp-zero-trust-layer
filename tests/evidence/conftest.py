from __future__ import annotations

import copy

import pytest

from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.evidence.demo import create_demo
from mcp_zero_trust_layer.evidence.destination import RefundDestination
from mcp_zero_trust_layer.evidence.protocol import IDEMPOTENCY


@pytest.fixture
def env(tmp_path):
    directory = tmp_path / 'demo'
    cfg = create_demo(directory)
    destination = RefundDestination(directory)

    class Peer:
        calls = 0
        message = None
        response = None

        def send(self, server, message, *, headers=None):
            self.calls += 1
            self.message = copy.deepcopy(message)
            self.response = destination.handle(message)
            return copy.deepcopy(self.response)

    peer = Peer()
    pipeline = MCPPipeline(cfg, peer)
    return directory, cfg, destination, peer, pipeline


def call(amount=5000, key='once'):
    return {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
        'name': 'refund', 'arguments': {'amount_minor': amount},
        '_meta': {IDEMPOTENCY: key}}}
