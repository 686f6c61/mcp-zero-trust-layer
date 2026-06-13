from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mcp_zero_trust_layer.approvals import ApprovalStore
from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.transports.http.app import create_app_from_config


@dataclass
class UpstreamHandle:
    server: ThreadingHTTPServer
    handler: type[BaseHTTPRequestHandler]
    url: str

    @property
    def requests(self) -> list[dict[str, Any]]:
        return getattr(self.handler, "requests")


@pytest.fixture()
def multi_mcp(tmp_path: Path) -> Iterator[tuple[TestClient, dict[str, UpstreamHandle], MCPZTConfig]]:
    upstreams = {
        "github": _start_upstream("github"),
        "postgres": _start_upstream("postgres"),
        "filesystem": _start_upstream("filesystem"),
        "crm": _start_upstream("crm"),
    }
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _multi_mcp_config(tmp_path, workspace, upstreams)
    try:
        yield TestClient(create_app_from_config(config)), upstreams, config
    finally:
        for upstream in upstreams.values():
            upstream.server.shutdown()
            upstream.server.server_close()


def test_multi_mcp_filters_capability_lists_per_server(
    multi_mcp: tuple[TestClient, dict[str, UpstreamHandle], MCPZTConfig],
) -> None:
    client, upstreams, _config = multi_mcp

    github_tools = _rpc(client, "github", 1, "tools/list")["result"]["tools"]
    postgres_tools = _rpc(client, "postgres", 2, "tools/list")["result"]["tools"]
    filesystem_resources = _rpc(client, "filesystem", 3, "resources/list")["result"]["resources"]

    assert [tool["name"] for tool in github_tools] == [
        "github.search_issues",
        "github.merge_pull_request",
    ]
    assert [tool["name"] for tool in postgres_tools] == ["postgres.query"]
    assert [resource["uri"] for resource in filesystem_resources] == [
        "file:///workspace/README.md"
    ]
    assert len(upstreams["github"].requests) == 1
    assert len(upstreams["postgres"].requests) == 1
    assert len(upstreams["filesystem"].requests) == 1


def test_multi_mcp_allows_safe_calls_and_routes_to_the_right_upstream(
    multi_mcp: tuple[TestClient, dict[str, UpstreamHandle], MCPZTConfig],
) -> None:
    client, upstreams, _config = multi_mcp

    github = _call_tool(
        client,
        "github",
        10,
        "github.search_issues",
        {"q": "is:open label:security"},
    )
    postgres = _call_tool(
        client,
        "postgres",
        11,
        "postgres.query",
        {"query": "select id, title from issues"},
    )

    assert github["result"]["content"][0]["text"] == "github search ok"
    assert postgres["result"]["rows"] == [{"id": 1, "title": "security review"}]
    assert [request["params"]["name"] for request in upstreams["github"].requests] == [
        "github.search_issues"
    ]
    assert [request["params"]["name"] for request in upstreams["postgres"].requests] == [
        "postgres.query"
    ]
    assert upstreams["filesystem"].requests == []


def test_multi_mcp_blocks_dangerous_arguments_before_upstream(
    multi_mcp: tuple[TestClient, dict[str, UpstreamHandle], MCPZTConfig],
) -> None:
    client, upstreams, _config = multi_mcp

    sql = _call_tool(
        client,
        "postgres",
        20,
        "postgres.query",
        {"query": "delete from issues"},
    )
    file_read = _call_tool(
        client,
        "filesystem",
        21,
        "filesystem.read_file",
        {"path": "/etc/passwd"},
    )

    assert sql["result"]["isError"] is True
    assert "destructive SQL" in sql["result"]["content"][0]["text"]
    assert file_read["result"]["isError"] is True
    assert "outside allowed_roots" in file_read["result"]["content"][0]["text"]
    assert upstreams["postgres"].requests == []
    assert upstreams["filesystem"].requests == []


def test_multi_mcp_requires_human_approval_for_sensitive_action(
    multi_mcp: tuple[TestClient, dict[str, UpstreamHandle], MCPZTConfig],
) -> None:
    client, upstreams, config = multi_mcp

    first = _call_tool(
        client,
        "github",
        30,
        "github.merge_pull_request",
        {"repo": "acme/api", "pull_number": 42, "branch": "main"},
    )

    assert first["error"]["code"] == -32010
    approval_id = first["error"]["data"]["approval_id"]
    assert upstreams["github"].requests == []

    ApprovalStore(config.approvals).set_status(
        approval_id,
        "approved",
        decided_by="security-reviewer@example.com",
        decision_comment="release PR reviewed",
    )
    second = _call_tool(
        client,
        "github",
        31,
        "github.merge_pull_request",
        {
            "repo": "acme/api",
            "pull_number": 42,
            "branch": "main",
            "_mcpzt_approval_id": approval_id,
        },
    )

    assert second["result"]["content"][0]["text"] == "github merge ok"
    assert len(upstreams["github"].requests) == 1
    assert "_mcpzt_approval_id" not in upstreams["github"].requests[0]["params"]["arguments"]


def test_multi_mcp_redacts_sensitive_upstream_output(
    multi_mcp: tuple[TestClient, dict[str, UpstreamHandle], MCPZTConfig],
) -> None:
    client, upstreams, _config = multi_mcp

    response = _call_tool(client, "crm", 40, "crm.get_customer", {"customer_id": "cust_123"})

    assert response["result"] == {
        "customer_id": "cust_123",
        "name": "Ana",
        "email": "[REDACTED]",
        "api_key": "[REDACTED]",
    }
    assert len(upstreams["crm"].requests) == 1


def _multi_mcp_config(
    tmp_path: Path,
    workspace: Path,
    upstreams: dict[str, UpstreamHandle],
) -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "multi-mcp-e2e", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": upstreams["github"].url},
                {"name": "postgres", "transport": "http", "upstream": upstreams["postgres"].url},
                {
                    "name": "filesystem",
                    "transport": "http",
                    "upstream": upstreams["filesystem"].url,
                },
                {"name": "crm", "transport": "http", "upstream": upstreams["crm"].url},
            ],
            "capability_mappings": {
                "github": {
                    "tools": {
                        "github.search_issues": {
                            "action": "code.read",
                            "risk": "low",
                            "access": "read",
                        },
                        "github.merge_pull_request": {
                            "action": "code.merge",
                            "risk": "critical",
                            "access": "write",
                        },
                        "github.delete_repository": {
                            "action": "code.delete",
                            "risk": "critical",
                            "access": "delete",
                        },
                    }
                },
                "postgres": {
                    "tools": {
                        "postgres.query": {
                            "action": "db.read",
                            "risk": "medium",
                            "access": "read",
                        },
                        "postgres.drop_table": {
                            "action": "db.admin",
                            "risk": "critical",
                            "access": "write",
                        },
                    }
                },
                "filesystem": {
                    "tools": {
                        "filesystem.read_file": {
                            "action": "filesystem.read",
                            "risk": "low",
                            "access": "read",
                        }
                    },
                    "resources": {
                        "file:///workspace/README.md": {
                            "action": "filesystem.read",
                            "risk": "low",
                            "access": "read",
                        },
                        "file:///etc/passwd": {
                            "action": "filesystem.read",
                            "risk": "critical",
                            "access": "read",
                        },
                    },
                },
                "crm": {
                    "tools": {
                        "crm.get_customer": {
                            "action": "crm.read",
                            "risk": "medium",
                            "access": "read",
                            "data_classification": "confidential",
                        }
                    }
                },
            },
            "policies": [
                {
                    "id": "allow-github-read",
                    "effect": "allow",
                    "match": {"server": "github", "action": "code.read"},
                },
                {
                    "id": "deny-github-delete",
                    "effect": "deny",
                    "match": {"server": "github", "capability": "github.delete_repository"},
                },
                {
                    "id": "github-critical-needs-approval",
                    "effect": "require_approval",
                    "match": {"server": "github", "risk": "critical"},
                },
                {
                    "id": "show-postgres-query",
                    "effect": "allow",
                    "match": {
                        "server": "postgres",
                        "method": "tools/list",
                        "capability": "postgres.query",
                    },
                },
                {
                    "id": "allow-readonly-sql",
                    "effect": "allow",
                    "match": {"server": "postgres", "method": "tools/call", "action": "db.read"},
                    "validators": [{"name": "sql_read_only"}],
                },
                {
                    "id": "allow-safe-filesystem-resource",
                    "effect": "allow",
                    "match": {
                        "server": "filesystem",
                        "capability_type": "resource",
                        "capability": "file:///workspace/README.md",
                    },
                },
                {
                    "id": "allow-safe-filesystem-read",
                    "effect": "allow",
                    "match": {
                        "server": "filesystem",
                        "capability_type": "tool",
                        "capability": "filesystem.read_file",
                    },
                    "validators": [
                        {
                            "name": "filesystem_path",
                            "options": {
                                "path_arg": "path",
                                "allowed_roots": [str(workspace)],
                                "read_only": True,
                            },
                        }
                    ],
                },
                {
                    "id": "allow-crm-read",
                    "effect": "allow",
                    "match": {"server": "crm", "action": "crm.read"},
                },
                {
                    "id": "redact-crm-pii",
                    "effect": "redact",
                    "match": {"server": "crm", "capability": "crm.get_customer"},
                    "when": {"output.email": {"exists": True}},
                    "output": {"redact_fields": ["email", "api_key"]},
                },
            ],
            "audit": {"destination": "file", "path": str(tmp_path / "audit.jsonl")},
            "approvals": {"path": str(tmp_path / "approvals.json")},
        }
    )


def _start_upstream(name: str) -> UpstreamHandle:
    handler = _handler_for(name)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    return UpstreamHandle(server=server, handler=handler, url=f"http://127.0.0.1:{port}/mcp")


def _handler_for(name: str) -> type[BaseHTTPRequestHandler]:
    class FakeMCPHandler(BaseHTTPRequestHandler):
        requests: list[dict[str, Any]] = []

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            size = int(self.headers.get("content-length", "0"))
            message = json.loads(self.rfile.read(size))
            self.__class__.requests.append(message)
            if "id" not in message:
                self.send_response(202)
                self.end_headers()
                return
            payload = _upstream_response(name, message)
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return FakeMCPHandler


def _upstream_response(name: str, message: dict[str, Any]) -> dict[str, Any]:
    method = message.get("method")
    request_id = message.get("id")
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"tools": _tools_for(name)},
        }
    if method == "resources/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "resources": [
                    {"uri": "file:///workspace/README.md"},
                    {"uri": "file:///etc/passwd"},
                ]
            },
        }
    if method == "tools/call":
        tool_name = message["params"]["name"]
        if tool_name == "github.search_issues":
            return _tool_text(request_id, "github search ok")
        if tool_name == "github.merge_pull_request":
            return _tool_text(request_id, "github merge ok")
        if tool_name == "postgres.query":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"rows": [{"id": 1, "title": "security review"}]},
            }
        if tool_name == "filesystem.read_file":
            return _tool_text(request_id, "filesystem read ok")
        if tool_name == "crm.get_customer":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "customer_id": "cust_123",
                    "name": "Ana",
                    "email": "ana@example.com",
                    "api_key": "sk-test-secret",
                },
            }
    return {"jsonrpc": "2.0", "id": request_id, "result": {}}


def _tools_for(name: str) -> list[dict[str, str]]:
    return {
        "github": [
            {"name": "github.search_issues"},
            {"name": "github.merge_pull_request"},
            {"name": "github.delete_repository"},
        ],
        "postgres": [
            {"name": "postgres.query"},
            {"name": "postgres.drop_table"},
        ],
        "filesystem": [
            {"name": "filesystem.read_file"},
        ],
        "crm": [
            {"name": "crm.get_customer"},
        ],
    }[name]


def _tool_text(request_id: int, text: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": False},
    }


def _rpc(client: TestClient, server: str, request_id: int, method: str) -> dict[str, Any]:
    response = client.post(
        f"/mcp/{server}",
        json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": {}},
    )
    assert response.status_code == 200
    return response.json()


def _call_tool(
    client: TestClient,
    server: str,
    request_id: int,
    name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    response = client.post(
        f"/mcp/{server}",
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    assert response.status_code == 200
    return response.json()
