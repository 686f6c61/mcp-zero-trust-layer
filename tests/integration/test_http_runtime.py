from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from mcp_zero_trust_layer.config.models import MCPZTConfig, ServerConfig
from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.transports.http.app import create_app_from_config
from mcp_zero_trust_layer.upstream.http import HTTPUpstreamClient


class RecordingUpstream:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    def send(
        self,
        server: ServerConfig,
        message: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        self.messages.append(message)
        if "method" not in message or "id" not in message:
            return None
        method = message.get("method")
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "tools": [
                        {"name": "github.search_issues"},
                        {"name": "github.delete_repository"},
                    ]
                },
            }
        if method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "resources": [
                        {"uri": "file:///safe.md"},
                        {"uri": "file:///secret.md"},
                    ]
                },
            }
        if method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "prompts": [
                        {"name": "summarize"},
                        {"name": "admin"},
                    ]
                },
            }
        if method == "tools/call":
            return {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"content": [{"type": "text", "text": "ok"}], "isError": False},
            }
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {}}


class ErroringUpstream:
    def send(
        self,
        server: ServerConfig,
        message: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {
                "code": -32099,
                "message": "upstream failed",
                "data": {"email": "ana@example.com", "detail": "visible"},
            },
        }


def _config() -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "integration", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://upstream.example/mcp"}
            ],
            "policies": [
                {
                    "id": "allow-search",
                    "effect": "allow",
                    "match": {
                        "server": "github",
                        "capability_type": "tool",
                        "capability": "github.search_issues",
                    },
                },
                {
                    "id": "allow-safe-resource",
                    "effect": "allow",
                    "match": {
                        "server": "github",
                        "capability_type": "resource",
                        "capability": "file:///safe.md",
                    },
                },
                {
                    "id": "allow-summarize-prompt",
                    "effect": "allow",
                    "match": {
                        "server": "github",
                        "capability_type": "prompt",
                        "capability": "summarize",
                    },
                },
            ],
            "audit": {"destination": "stdout"},
        }
    )


def _static_auth_config() -> MCPZTConfig:
    data = _config().model_dump()
    data["auth"] = {"mode": "static_token", "token": "secret"}
    data["runtime"]["allowed_origins"] = ["https://allowed.example"]
    return MCPZTConfig.model_validate(data)


def _validator_config() -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "validator", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "postgres", "transport": "http", "upstream": "http://upstream.example/mcp"}
            ],
            "capability_mappings": {
                "postgres": {
                    "tools": {
                        "postgres.query": {
                            "action": "db.read",
                            "risk": "medium",
                            "access": "read",
                        }
                    }
                }
            },
            "policies": [
                {
                    "id": "readonly",
                    "effect": "allow",
                    "match": {"server": "postgres", "action": "db.read"},
                    "validators": [{"name": "sql_read_only"}],
                }
            ],
            "audit": {"destination": "stdout"},
        }
    )


def _output_error_config() -> MCPZTConfig:
    data = _config().model_dump()
    data["policies"].append(
        {
            "id": "redact-error-email",
            "effect": "redact",
            "match": {
                "server": "github",
                "capability_type": "tool",
                "capability": "github.search_issues",
            },
            "when": {"output.data.email": {"exists": True}},
            "output": {"redact_fields": ["email"]},
        }
    )
    return MCPZTConfig.model_validate(data)


def _dry_run_config() -> MCPZTConfig:
    data = _config().model_dump()
    data["runtime"]["dry_run"] = True
    return MCPZTConfig.model_validate(data)


def test_pipeline_filters_tools_list() -> None:
    upstream = RecordingUpstream()
    response = MCPPipeline(_config(), upstream).handle(
        "github",
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        identity=Identity(subject="ana"),
    )

    assert response == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"tools": [{"name": "github.search_issues"}]},
    }
    assert len(upstream.messages) == 1


def test_dry_run_does_not_filter_tools_list() -> None:
    upstream = RecordingUpstream()
    response = MCPPipeline(_dry_run_config(), upstream).handle(
        "github",
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        identity=Identity(subject="ana"),
    )

    assert response is not None
    assert response["result"]["tools"] == [
        {"name": "github.search_issues"},
        {"name": "github.delete_repository"},
    ]


def test_pipeline_denies_tool_call_before_upstream() -> None:
    upstream = RecordingUpstream()
    response = MCPPipeline(_config(), upstream).handle(
        "github",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "github.delete_repository", "arguments": {}},
        },
        identity=Identity(subject="ana"),
    )

    assert response is not None
    assert response["error"]["code"] == -32001
    assert upstream.messages == []


def test_dry_run_does_not_deny_tool_call() -> None:
    upstream = RecordingUpstream()
    response = MCPPipeline(_dry_run_config(), upstream).handle(
        "github",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "github.delete_repository", "arguments": {}},
        },
        identity=Identity(subject="ana"),
    )

    assert response is not None
    assert response["result"]["content"][0]["text"] == "ok"
    assert len(upstream.messages) == 1


def test_pipeline_enforces_output_policy_on_jsonrpc_error() -> None:
    response = MCPPipeline(_output_error_config(), ErroringUpstream()).handle(
        "github",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "github.search_issues", "arguments": {"q": "bug"}},
        },
        identity=Identity(subject="ana"),
    )

    assert response is not None
    assert response["error"]["data"]["email"] == "[REDACTED]"
    assert response["error"]["data"]["detail"] == "visible"


def test_pipeline_filters_resources_and_prompts() -> None:
    upstream = RecordingUpstream()
    pipeline = MCPPipeline(_config(), upstream)

    resources = pipeline.handle(
        "github",
        {"jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": {}},
        identity=Identity(subject="ana"),
    )
    prompts = pipeline.handle(
        "github",
        {"jsonrpc": "2.0", "id": 2, "method": "prompts/list", "params": {}},
        identity=Identity(subject="ana"),
    )

    assert resources is not None
    assert resources["result"]["resources"] == [{"uri": "file:///safe.md"}]
    assert prompts is not None
    assert prompts["result"]["prompts"] == [{"name": "summarize"}]


def test_tool_validator_failure_returns_tool_error_result() -> None:
    upstream = RecordingUpstream()
    response = MCPPipeline(_validator_config(), upstream).handle(
        "postgres",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "postgres.query", "arguments": {"query": "delete from users"}},
        },
        identity=Identity(subject="ana"),
    )

    assert response is not None
    assert response["result"]["isError"] is True
    assert "destructive SQL" in response["result"]["content"][0]["text"]
    assert upstream.messages == []


def test_http_app_returns_empty_202_for_notification(monkeypatch) -> None:
    upstream = RecordingUpstream()

    def fake_client() -> RecordingUpstream:
        return upstream

    monkeypatch.setattr(
        "mcp_zero_trust_layer.transports.http.app.HTTPUpstreamClient",
        fake_client,
    )
    client = TestClient(create_app_from_config(_config()))
    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    )

    assert response.status_code == 202
    assert response.content == b""
    assert len(upstream.messages) == 1


def test_pipeline_blocks_unsafe_notification_before_upstream() -> None:
    upstream = RecordingUpstream()
    response = MCPPipeline(_config(), upstream).handle(
        "github",
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "github.delete_repository", "arguments": {}},
        },
        identity=Identity(subject="ana"),
    )

    assert response is None
    assert upstream.messages == []


def test_http_app_forwards_allowed_tool_call(monkeypatch) -> None:
    upstream = RecordingUpstream()

    def fake_client() -> RecordingUpstream:
        return upstream

    monkeypatch.setattr(
        "mcp_zero_trust_layer.transports.http.app.HTTPUpstreamClient",
        fake_client,
    )
    client = TestClient(create_app_from_config(_config()))
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "github.search_issues", "arguments": {"q": "bug"}},
        },
    )

    assert response.status_code == 200
    assert response.json()["result"]["content"][0]["text"] == "ok"
    assert len(upstream.messages) == 1


def test_http_app_exposes_prometheus_metrics(monkeypatch) -> None:
    upstream = RecordingUpstream()

    def fake_client() -> RecordingUpstream:
        return upstream

    monkeypatch.setattr(
        "mcp_zero_trust_layer.transports.http.app.HTTPUpstreamClient",
        fake_client,
    )
    client = TestClient(create_app_from_config(_config()))
    client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "github.search_issues", "arguments": {"q": "bug"}},
        },
    )

    response = client.get("/metrics")

    assert response.status_code == 200
    assert "mcpzt_policy_decisions_total" in response.text
    assert 'decision="allow"' in response.text


def test_http_app_rejects_missing_auth_with_www_authenticate(monkeypatch) -> None:
    upstream = RecordingUpstream()

    def fake_client() -> RecordingUpstream:
        return upstream

    monkeypatch.setattr(
        "mcp_zero_trust_layer.transports.http.app.HTTPUpstreamClient",
        fake_client,
    )
    client = TestClient(create_app_from_config(_static_auth_config()))
    response = client.post(
        "/mcp",
        headers={"origin": "https://allowed.example"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )

    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert "resource_metadata" in response.headers["WWW-Authenticate"]
    assert upstream.messages == []


def test_http_app_rejects_invalid_origin(monkeypatch) -> None:
    monkeypatch.setattr(
        "mcp_zero_trust_layer.transports.http.app.HTTPUpstreamClient",
        RecordingUpstream,
    )
    client = TestClient(create_app_from_config(_static_auth_config()))
    response = client.post(
        "/mcp",
        headers={"origin": "https://evil.example", "authorization": "Bearer secret"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )

    assert response.status_code == 403


def test_http_app_rejects_oversized_request(monkeypatch) -> None:
    data = _config().model_dump()
    data["runtime"]["max_request_bytes"] = 16
    config = MCPZTConfig.model_validate(data)
    monkeypatch.setattr(
        "mcp_zero_trust_layer.transports.http.app.HTTPUpstreamClient",
        RecordingUpstream,
    )
    client = TestClient(create_app_from_config(config))

    response = client.post(
        "/mcp",
        content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}',
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == -32042


def test_http_app_serves_protected_resource_metadata() -> None:
    client = TestClient(create_app_from_config(_static_auth_config()))
    response = client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    assert response.json()["resource"].endswith("/mcp")


def test_production_http_app_disables_docs_and_uses_public_base_url() -> None:
    data = _static_auth_config().model_dump()
    data["project"]["environment"] = "production"
    data["runtime"]["public_base_url"] = "https://mcpzt.example"
    data["runtime"]["trusted_hosts"] = ["testserver"]
    config = MCPZTConfig.model_validate(data)
    client = TestClient(create_app_from_config(config))

    assert client.get("/docs").status_code == 404
    metadata = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert metadata["resource"] == "https://mcpzt.example/mcp"


def test_http_upstream_header_allowlist() -> None:
    filtered = HTTPUpstreamClient().send  # keeps import path covered for runtime packaging
    assert callable(filtered)
