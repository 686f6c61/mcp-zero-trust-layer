import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import httpx
import jwt

from mcp_zero_trust_layer.config.models import (
    ApprovalsConfig,
    AuditConfig,
    AuthConfig,
    InputPolicy,
    MCPZTConfig,
    PolicyConfig,
    PolicyEngineConfig,
    PolicyMatch,
    ServerConfig,
)
from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.identity.auth import AuthResolver
from mcp_zero_trust_layer.upstream.http import HTTPUpstreamClient
from mcp_zero_trust_layer.validators.basic import validate_email, validate_sql_read_only
from mcp_zero_trust_layer.validators.input_policy import validate_input_policy

root = Path(tempfile.mkdtemp(prefix="mcpzt-audit-"))


def conf(policies, **kw):
    return MCPZTConfig(
        servers=[ServerConfig(name="s", transport="http", upstream="https://upstream.invalid/mcp")],
        policies=policies,
        audit=AuditConfig(path=str(root / "audit.jsonl")),
        approvals=ApprovalsConfig(path=str(root / "approvals.json")),
        **kw,
    )


class Stub:
    def __init__(self):
        self.calls = []

    def send(self, server, message, **kw):
        self.calls.append(message)
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"secret": "sensitive", "tools": []},
        }


auth = AuthResolver(AuthConfig(mode="jwt", token="x" * 32, algorithms=["HS256"]))
token = jwt.encode({"sub": "alice", "exp": int(time.time()) + 600}, "x" * 32, algorithm="HS256")
i = auth.resolve_http_identity(
    headers={"authorization": "Bearer " + token, "x-mcpzt-agent-id": "privileged-agent"},
    source_ip=None,
)
u = Stub()
p = MCPPipeline(
    conf(
        [
            PolicyConfig(
                id="only-agent", effect="allow", match=PolicyMatch(agent_id="privileged-agent")
            )
        ]
    ),
    u,
)
p.handle(
    "s",
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "dangerous", "arguments": {}},
    },
    identity=i,
)
print("JWT_HEADER_SPOOF", i.agent_id, "upstream_calls", len(u.calls))

u = Stub()
p = MCPPipeline(conf([PolicyConfig(id="all-approval", effect="require_approval")]), u)
r = p.handle(
    "s",
    {"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe", "params": {"uri": "private://x"}},
    identity=Identity(subject="alice"),
)
print("OTHER_METHOD_APPROVAL_BYPASS", "upstream_calls", len(u.calls), "response", r)

u = Stub()
p = MCPPipeline(
    conf(
        [],
        policy_engine=PolicyEngineConfig(
            adapter="opa", endpoint="https://opa.invalid", fail_closed=True
        ),
    ),
    u,
)
with patch(
    "mcp_zero_trust_layer.policy.adapters.httpx.post",
    side_effect=[
        httpx.Response(
            200, json={"result": True}, request=httpx.Request("POST", "https://opa.invalid")
        ),
        httpx.ConnectError("unavailable"),
    ],
):
    r = p.handle(
        "s",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read", "arguments": {}},
        },
    )
print("OPA_OUTBOUND_FAIL_OPEN", r)

seen = []


def handler(req):
    seen.append(req.headers.get("mcp-session-id"))
    return httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": 1, "result": {}},
        headers={"mcp-session-id": "alice-session"},
    )


real_client = httpx.Client
with patch(
    "mcp_zero_trust_layer.upstream.http.httpx.Client",
    side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw),
):
    c = HTTPUpstreamClient()
    s = ServerConfig(name="s", transport="http", upstream="https://upstream.invalid")
    for name in ["alice", "bob"]:
        c.send(
            s,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers={"x-mcpzt-subject": name},
        )
print("SESSION_CROSS_CLIENT", seen)

print(
    "EMAIL_DOMAIN_BYPASS",
    validate_email(
        {"to": "attacker@evil.test, trusted@company.test"}, {"allowed_domains": ["company.test"]}
    ).model_dump(),
)
print(
    "INPUT_SHAPE_BYPASS",
    validate_input_policy(
        {"customer": [{"secret": "leak"}]}, InputPolicy(allowed_fields=["customer.name"])
    ).model_dump(),
)
print(
    "SQL_MUTATING_FUNCTION",
    validate_sql_read_only({"query": "SELECT nextval('invoice_seq')"}, {}).model_dump(),
)
