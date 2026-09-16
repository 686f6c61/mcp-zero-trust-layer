from __future__ import annotations

import json
import shlex
import tomllib
from pathlib import Path

import pytest
import yaml

from mcp_zero_trust_layer.client_config import render_client_config
from mcp_zero_trust_layer.client_import import import_client_config
from mcp_zero_trust_layer.config.models import MCPZTConfig


def config(mode: str = "none", **auth: str) -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "clients"},
            "auth": {"mode": mode, **auth},
            "servers": [{"name": "demo", "transport": "http", "upstream": "https://upstream/mcp"}],
        }
    )


def render(kind: str, cfg: MCPZTConfig | None = None, **kwargs: str) -> str:
    return render_client_config(
        cfg or config(), kind, base_url="https://gateway.example", server_name=None, **kwargs
    )


@pytest.mark.parametrize(
    "kind,root,url_key",
    [
        ("cursor", "mcpServers", "url"),
        ("vscode", "servers", "url"),
        ("gemini", "mcpServers", "httpUrl"),
    ],
)
def test_native_http_schema_and_secret_reference(kind: str, root: str, url_key: str) -> None:
    entry = json.loads(render(kind, config("static_token", token_env="GATEWAY_TOKEN")))[root][
        "mcpzt-demo"
    ]
    assert entry[url_key] == "https://gateway.example/mcp/demo"
    assert "command" not in entry
    env = "${GATEWAY_TOKEN}" if kind == "gemini" else "${env:GATEWAY_TOKEN}"
    assert entry["headers"] == {"Authorization": f"Bearer {env}"}
    if kind == "vscode":
        assert entry["type"] == "http"


@pytest.mark.parametrize("kind", ["codex", "grok"])
def test_toml_parses_and_references_auth_environment(kind: str, monkeypatch) -> None:
    monkeypatch.setenv("GATEWAY_TOKEN", "must-never-be-read")
    rendered = render(kind, config("static_token", token_env="GATEWAY_TOKEN"))
    assert "must-never-be-read" not in rendered
    entry = tomllib.loads(rendered)["mcp_servers"]["mcpzt-demo"]
    assert entry["url"] == "https://gateway.example/mcp/demo"
    if kind == "codex":
        assert entry["bearer_token_env_var"] == "GATEWAY_TOKEN"
    else:
        assert entry["headers"] == {"Authorization": "Bearer ${GATEWAY_TOKEN}"}


def test_codex_api_key_env_header() -> None:
    entry = tomllib.loads(render("codex", config("api_key", token_env="KEY", header="X-Key")))[
        "mcp_servers"
    ]["mcpzt-demo"]
    assert entry["env_http_headers"] == {"X-Key": "KEY"}


def test_auth_never_silently_omitted() -> None:
    with pytest.raises(ValueError, match="--token-env"):
        render("cursor", config("static_token", token="do-not-embed"))
    with pytest.raises(ValueError, match="cannot safely render"):
        render("claude-desktop", config("static_token", token_env="KEY"))
    with pytest.raises(ValueError, match="variable name"):
        render("grok", token_env="$(bad)")


def test_cli_quotes_names_and_url() -> None:
    cfg = config()
    cfg.servers[0].name = "a;echo owned"
    command = render("claude-code", cfg)
    argv = shlex.split(command)
    assert argv == [
        "claude",
        "mcp",
        "add",
        "mcpzt-a;echo owned",
        "--transport",
        "http",
        "https://gateway.example/mcp/a%3Becho%20owned",
    ]


def imported(tmp_path: Path, payload: dict):
    source = tmp_path / "mcp.json"
    source.write_text(json.dumps(payload))
    return import_client_config(
        source,
        project_name="import",
        audit_path="audit.jsonl",
        approvals_path="approvals.db",
        base_url="http://localhost:8765",
        wrapper_command="mcpzt",
        mcpzt_config_path=tmp_path / "mcpzt.yaml",
    )


def test_import_preserves_host_controls_and_schema(tmp_path: Path) -> None:
    payload = {
        "servers": {
            "local": {
                "type": "stdio",
                "command": "test-server",
                "args": [],
                "sandboxEnabled": True,
                "cwd": "${workspaceFolder}",
                "env": {"TOKEN": "${input:token}"},
            }
        },
        "inputs": [{"id": "token", "type": "promptString", "password": True}],
        "sandbox": {"filesystem": {"allowWrite": ["safe"]}},
    }
    result = imported(tmp_path, payload)
    client = json.loads(result.client_config_json)
    assert client["inputs"] == payload["inputs"]
    assert client["sandbox"] == payload["sandbox"]
    assert "mcpServers" not in client
    entry = client["servers"]["local"]
    assert entry["sandboxEnabled"] is True
    assert entry["cwd"] == "${workspaceFolder}"
    assert entry["env"] == {"TOKEN": "${input:token}"}
    assert yaml.safe_load(result.mcpzt_config_yaml)["servers"][0]["env"] == {"TOKEN": "env:TOKEN"}


def test_import_http_credentials_only_go_upstream(tmp_path: Path) -> None:
    result = imported(
        tmp_path,
        {
            "mcpServers": {
                "api": {
                    "httpUrl": "https://upstream/mcp",
                    "headers": {"Authorization": "Bearer secret"},
                    "includeTools": ["read"],
                }
            }
        },
    )
    client = json.loads(result.client_config_json)["mcpServers"]["api"]
    assert client["httpUrl"] == "http://localhost:8765/mcp/api"
    assert client["includeTools"] == ["read"]
    assert "headers" not in client
    assert "secret" not in result.client_config_json
    assert yaml.safe_load(result.mcpzt_config_yaml)["servers"][0]["upstream_headers"] == {
        "Authorization": "Bearer secret"
    }


@pytest.mark.parametrize(
    "entry,reason",
    [
        ({"command": "${workspaceFolder}/server"}, "interpolation"),
        ({"url": "https://example/mcp", "headers": {"X-Key": "${input:token}"}}, "interpolation"),
        ({"command": "server", "args": "--flag"}, "args"),
        ({"url": "https://example/mcp", "auth": {"CLIENT_ID": "id"}}, "unsupported fields"),
        ({"url": "https://example/sse", "type": "sse"}, "transport"),
        ({"command": "server", "url": "https://example/mcp"}, "one command or URL"),
        ({"command": "server", "type": "http"}, "does not match"),
    ],
)
def test_import_rejects_unsupported_without_silently_dropping(tmp_path, entry, reason) -> None:
    with pytest.raises(ValueError, match=reason):
        imported(tmp_path, {"mcpServers": {"test": entry}})


def test_import_rejects_ambiguous_root(tmp_path) -> None:
    with pytest.raises(ValueError, match="ambiguous"):
        imported(tmp_path, {"mcpServers": {}, "servers": {}})


@pytest.mark.parametrize("kind", ["grok", "codex", "gemini", "vscode", "cursor"])
def test_cli_emits_parseable_unwrapped_configuration(tmp_path: Path, kind: str) -> None:
    from typer.testing import CliRunner

    from mcp_zero_trust_layer.cli.main import app

    path = tmp_path / "gateway.yaml"
    path.write_text(yaml.safe_dump(config("static_token", token_env="TOKEN").model_dump()))
    result = CliRunner().invoke(app, ["client", "config", "--config", str(path), "--kind", kind])
    assert result.exit_code == 0, result.stdout
    parsed = (
        tomllib.loads(result.stdout) if kind in {"grok", "codex"} else json.loads(result.stdout)
    )
    assert parsed


@pytest.mark.parametrize(
    "base_url",
    [
        "ftp://gateway.example",
        "https://user:password@gateway.example",
        "https://gateway.example?q=1",
        "https://gateway.example#frag",
        "https://gateway.example/a b",
        "https:///missing-host",
    ],
)
def test_generator_rejects_unsafe_or_ambiguous_base_url(base_url) -> None:
    with pytest.raises(ValueError, match="base URL"):
        render_client_config(config(), "cursor", base_url=base_url, server_name=None)


def test_generator_rejects_header_injection() -> None:
    with pytest.raises(ValueError, match="header name"):
        render("grok", config("api_key", header="X-Key\r\nInjected: yes", token_env="TOKEN"))


@pytest.mark.parametrize("kind", ["cursor", "codex", "grok"])
def test_static_token_custom_header_matches_gateway(kind, monkeypatch) -> None:
    from mcp_zero_trust_layer.identity import AuthResolver

    cfg = config("static_token", header="X-Gateway-Token", token_env="TOKEN")
    rendered = render(kind, cfg)
    monkeypatch.setenv("TOKEN", "token-value")
    if kind == "cursor":
        headers = json.loads(rendered)["mcpServers"]["mcpzt-demo"]["headers"]
        headers = {
            key: value.replace("${env:TOKEN}", "token-value") for key, value in headers.items()
        }
    elif kind == "grok":
        headers = tomllib.loads(rendered)["mcp_servers"]["mcpzt-demo"]["headers"]
        headers = {key: value.replace("${TOKEN}", "token-value") for key, value in headers.items()}
    else:
        entry = tomllib.loads(rendered)["mcp_servers"]["mcpzt-demo"]
        assert entry["env_http_headers"] == {"X-Gateway-Token": "TOKEN"}
        headers = {"X-Gateway-Token": "token-value"}
    assert AuthResolver(cfg.auth).resolve_http_identity(
        headers=headers, source_ip=None
    ).auth_method == ("static_token")


@pytest.mark.parametrize(
    "payload,reason",
    [
        ([], "JSON object"),
        ({"mcpServers": {}}, "no supported MCP servers"),
        ({"mcpServers": {"x": {"command": "server", "env": {"TOKEN": 1}}}}, "env must map"),
        ({"mcpServers": {"x": {"url": "https://upstream/mcp", "cwd": "/tmp"}}}, "process options"),
        ({"mcpServers": {"x": {"command": "server", "headers": {}}}}, "headers on stdio"),
        ({"mcpServers": {"x": {"command": "server", "type": []}}}, "transport type"),
    ],
)
def test_import_rejects_invalid_config_without_dropping_security_controls(
    tmp_path, payload, reason
):
    with pytest.raises(ValueError, match=reason):
        imported(tmp_path, payload)
