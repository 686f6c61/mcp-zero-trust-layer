"""Local contract checks; synthetic data, no external services or credentials."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from mcp_zero_trust_layer.config.models import AuthConfig, MCPZTConfig
from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.identity.auth import AuthResolver
from mcp_zero_trust_layer.policy import PolicyDecision


class LocalUpstream:
    def __init__(self):
        self.calls = 0

    def send(self, server, message, *, headers=None):
        self.calls += 1
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"sample": "synthetic"}}


with tempfile.TemporaryDirectory() as directory:
    config = MCPZTConfig.model_validate(
        {
            "servers": [
                {"name": "sample", "transport": "http", "upstream": "http://unused.invalid"}
            ],
            "audit": {"destination": "file", "path": str(Path(directory) / "audit.jsonl")},
        }
    )
    upstream = LocalUpstream()
    pipeline = MCPPipeline(config, upstream)
    with patch.object(
        pipeline.policy_engine,
        "evaluate",
        side_effect=[
            PolicyDecision(decision="allow", reason="test inbound"),
            PolicyDecision(decision="deny", reason="OPA failed closed"),
        ],
    ):
        result = pipeline.handle(
            "sample",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "sample", "arguments": {}},
            },
            identity=Identity(subject="test"),
        )
    print("outbound_deny_without_policy_id:", json.dumps(result))
    with patch.object(
        pipeline.policy_engine,
        "evaluate",
        return_value=PolicyDecision(
            decision="require_approval", policy_id="approval-rule", reason="test"
        ),
    ):
        before = upstream.calls
        result = pipeline.handle(
            "sample",
            {"jsonrpc": "2.0", "id": 2, "method": "custom/action", "params": {}},
            identity=Identity(subject="test"),
        )
        print(
            "generic_method_approval:",
            json.dumps({"upstream_calls": upstream.calls - before, "response": result}),
        )
    auth = AuthResolver(AuthConfig(mode="jwt", trust_identity_headers=False))
    identity = auth._identity_from_claims(
        {"sub": "test"},
        {"x-mcpzt-client-id": "caller-supplied"},
        source_ip=None,
        auth_method="jwt",
        environment="test",
    )
    print("identity_with_untrusted_headers:", json.dumps({"client_id": identity.client_id}))
