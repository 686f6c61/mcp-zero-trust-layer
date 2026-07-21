from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mcp_zero_trust_layer.config.models import MCPZTConfig, ServerConfig
from mcp_zero_trust_layer.transports.http.app import (
    PayloadTooLargeError,
    _read_bounded_json,
    create_app_from_config,
    create_http_app,
)


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
        if "id" not in message:
            return None
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}


def _base_config_dict(tmp_path: Path) -> dict[str, Any]:
    return {
        "project": {"name": "transport-cov", "environment": "development"},
        "runtime": {"default_decision": "allow"},
        "auth": {"mode": "none"},
        "servers": [
            {"name": "github", "transport": "http", "upstream": "http://upstream.example/mcp"}
        ],
        "policies": [],
        "audit": {"destination": "file", "path": str(tmp_path / "audit.jsonl")},
    }


def _client(tmp_path: Path, monkeypatch, config_overrides: dict[str, Any] | None = None) -> TestClient:
    data = _base_config_dict(tmp_path)
    if config_overrides:
        data.update(config_overrides)
    monkeypatch.setattr(
        "mcp_zero_trust_layer.transports.http.app.HTTPUpstreamClient",
        RecordingUpstream,
    )
    return TestClient(create_app_from_config(MCPZTConfig.model_validate(data)))


# ---------------------------------------------------------------------------
# app.py
# ---------------------------------------------------------------------------


def test_healthz(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_get_mcp_is_405(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    assert client.get("/mcp").status_code == 405


def test_protected_resource_metadata_root(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.get("/.well-known/oauth-protected-resource")
    assert response.status_code == 200
    assert response.json()["resource"].endswith("/mcp")


def test_metadata_includes_authorization_servers_and_scopes(tmp_path: Path, monkeypatch) -> None:
    client = _client(
        tmp_path,
        monkeypatch,
        {
            "auth": {
                "mode": "jwt",
                "issuer": "https://issuer.example",
                "authorization_servers": ["https://as.example"],
                "required_scopes": ["mcp:read"],
                "audience": "mcpzt",
                "jwks_uri": "https://issuer.example/jwks",
            }
        },
    )
    metadata = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert "https://as.example" in metadata["authorization_servers"]
    assert "https://issuer.example" in metadata["authorization_servers"]
    assert metadata["scopes_supported"] == ["mcp:read"]


def test_post_mcp_with_identity_headers(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers={
            "authorization": "Bearer x",
            "x-mcpzt-subject": "ana",
            "x-mcpzt-client-id": "cursor",
            "x-mcpzt-agent-id": "agent-7",
        },
    )
    assert response.status_code == 200


def test_post_mcp_server_route(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/mcp/github",
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert response.status_code == 200


def test_post_mcp_parse_error(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/mcp",
        content=b"{not json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32700


def test_post_mcp_non_object_payload(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.post("/mcp", json=[1, 2, 3])
    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32600


def test_www_authenticate_includes_scope(tmp_path: Path, monkeypatch) -> None:
    client = _client(
        tmp_path,
        monkeypatch,
        {
            "auth": {"mode": "static_token", "token": "secret", "required_scopes": ["mcp:write"]},
        },
    )
    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert response.status_code == 401
    assert 'scope="mcp:write"' in response.headers["WWW-Authenticate"]


def test_create_app_with_only_stdio_server_picks_first(tmp_path: Path, monkeypatch) -> None:
    data = _base_config_dict(tmp_path)
    data["servers"] = [
        {"name": "local", "transport": "stdio", "command": ["true"]},
    ]
    monkeypatch.setattr(
        "mcp_zero_trust_layer.transports.http.app.HTTPUpstreamClient",
        RecordingUpstream,
    )
    app = create_app_from_config(MCPZTConfig.model_validate(data))
    client = TestClient(app)
    assert client.get("/healthz").status_code == 200


def test_create_http_app_from_file(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "mcpzt.yaml"
    config_path.write_text(
        f"""
project:
  name: file-config
  environment: development
runtime:
  default_decision: allow
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://upstream.example/mcp
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "mcp_zero_trust_layer.transports.http.app.HTTPUpstreamClient",
        RecordingUpstream,
    )
    app = create_http_app(config_path)
    client = TestClient(app)
    assert client.get("/healthz").status_code == 200


# ---- _read_bounded_json helper (edge cases hard to reach via TestClient) ----


class _FakeRequest:
    def __init__(self, headers: dict[str, str], chunks: list[bytes]) -> None:
        self.headers = headers
        self._chunks = chunks

    async def stream(self) -> Any:
        for chunk in self._chunks:
            yield chunk


def test_read_bounded_json_invalid_content_length() -> None:
    request = _FakeRequest({"content-length": "abc"}, [b"{}"])
    with pytest.raises(ValueError):
        asyncio.run(_read_bounded_json(request, 1000))  # type: ignore[arg-type]


def test_read_bounded_json_declared_too_large() -> None:
    request = _FakeRequest({"content-length": "5000"}, [b"{}"])
    with pytest.raises(PayloadTooLargeError):
        asyncio.run(_read_bounded_json(request, 100))  # type: ignore[arg-type]


def test_read_bounded_json_streamed_too_large() -> None:
    request = _FakeRequest({}, [b"aaaa", b"bbbb", b"cccc"])
    with pytest.raises(PayloadTooLargeError):
        asyncio.run(_read_bounded_json(request, 6))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# server.py
# ---------------------------------------------------------------------------


def test_run_http_server_invokes_uvicorn(tmp_path: Path, monkeypatch) -> None:
    from mcp_zero_trust_layer.transports.http import server as server_module

    config_path = tmp_path / "mcpzt.yaml"
    config_path.write_text(
        f"""
project:
  name: run-server
  environment: development
runtime:
  default_decision: allow
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://upstream.example/mcp
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
""",
        encoding="utf-8",
    )

    captured: dict[str, Any] = {}

    def fake_run(app: Any, **kwargs: Any) -> None:
        captured["app"] = app
        captured["kwargs"] = kwargs

    monkeypatch.setattr(server_module.uvicorn, "run", fake_run)
    server_module.run_http_server(config_path, host="127.0.0.1", port=4321, server="github")

    assert captured["kwargs"]["host"] == "127.0.0.1"
    assert captured["kwargs"]["port"] == 4321
    assert captured["app"] is not None


# ---------------------------------------------------------------------------
# stdio/wrapper.py
# ---------------------------------------------------------------------------


def _echo_child(tmp_path: Path) -> Path:
    child = tmp_path / "child.py"
    child.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    if 'id' in msg:\n"
        "        print(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':{'ok':True}}), flush=True)\n",
        encoding="utf-8",
    )
    return child


def _stdio_config(tmp_path: Path, child: Path, audit_destination: str = "file") -> Path:
    audit = tmp_path / "audit.jsonl"
    if audit_destination == "stdout":
        audit_block = "audit:\n  destination: stdout\n"
    else:
        audit_block = f"audit:\n  destination: file\n  path: {audit}\n"
    config = tmp_path / "mcpzt.yaml"
    config.write_text(
        f"""
project:
  name: stdio-cov
  environment: development
runtime:
  mode: stdio
  default_decision: allow
auth:
  mode: none
servers:
  - name: echo
    transport: stdio
    command:
      - {sys.executable}
      - {child}
{audit_block}""",
        encoding="utf-8",
    )
    return config


def test_stdio_wrapper_rejects_stdout_audit(tmp_path: Path) -> None:
    from io import StringIO

    from mcp_zero_trust_layer.transports.stdio import run_stdio_wrapper

    child = _echo_child(tmp_path)
    config = _stdio_config(tmp_path, child, audit_destination="stdout")
    stderr = StringIO()
    result = run_stdio_wrapper(config, stdin=StringIO(""), stdout=StringIO(), stderr=stderr)
    assert result == 2
    assert "cannot use audit.destination: stdout" in stderr.getvalue()


def test_stdio_wrapper_handles_blank_and_invalid_lines(tmp_path: Path) -> None:
    from io import StringIO

    from mcp_zero_trust_layer.transports.stdio import run_stdio_wrapper

    child = _echo_child(tmp_path)
    config = _stdio_config(tmp_path, child)
    stdin = StringIO("\n   \nnot-json\n")
    stdout = StringIO()
    result = run_stdio_wrapper(config, server_name="echo", stdin=stdin, stdout=stdout)
    assert result == 0
    # The invalid line produces a single parse-error response.
    import json

    response = json.loads(stdout.getvalue().strip())
    assert response["error"]["code"] == -32700


def test_stdio_wrapper_unknown_server_raises(tmp_path: Path) -> None:
    from io import StringIO

    from mcp_zero_trust_layer.transports.stdio import run_stdio_wrapper

    child = _echo_child(tmp_path)
    config = _stdio_config(tmp_path, child)
    with pytest.raises(ValueError, match="no matching stdio server"):
        run_stdio_wrapper(
            config, server_name="nonexistent", stdin=StringIO(""), stdout=StringIO()
        )
