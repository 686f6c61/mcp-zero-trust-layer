from __future__ import annotations

import json
from pathlib import Path

import yaml
import pytest

from mcp_zero_trust_layer.client_import import import_client_config


def test_import_client_config_wraps_stdio_without_writing_env_secret(tmp_path: Path) -> None:
    source = tmp_path / "claude_desktop_config.json"
    source.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "pencil": {
                        "command": "/Applications/Pencil.app/mcp-server",
                        "args": ["--app", "desktop"],
                        "env": {"PENCIL_TOKEN": "secret-token"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    result = import_client_config(
        source,
        project_name="import-test",
        audit_path=str(tmp_path / "audit.jsonl"),
        approvals_path=str(tmp_path / "approvals.sqlite3"),
        base_url="http://127.0.0.1:8765",
        wrapper_command="/usr/local/bin/mcpzt",
        mcpzt_config_path=tmp_path / "mcpzt.yaml",
    )

    mcpzt_config = yaml.safe_load(result.mcpzt_config_yaml)
    client_config = json.loads(result.client_config_json)

    server = mcpzt_config["servers"][0]
    assert server["name"] == "pencil"
    assert server["transport"] == "stdio"
    assert server["command"] == ["/Applications/Pencil.app/mcp-server", "--app", "desktop"]
    assert server["env"] == {"PENCIL_TOKEN": "env:PENCIL_TOKEN"}
    assert "secret-token" not in result.mcpzt_config_yaml
    assert client_config["mcpServers"]["pencil"]["command"] == "/usr/local/bin/mcpzt"
    assert client_config["mcpServers"]["pencil"]["args"] == [
        "wrap",
        "--config",
        str(tmp_path / "mcpzt.yaml"),
        "--server",
        "pencil",
    ]
    assert client_config["mcpServers"]["pencil"]["env"]["PENCIL_TOKEN"] == "secret-token"
    assert result.servers[0].env_keys == ("PENCIL_TOKEN",)


def test_import_client_config_sanitizes_http_logical_names(tmp_path: Path) -> None:
    source = tmp_path / "mcp.json"
    source.write_text(
        json.dumps(
            {
                "servers": {
                    "io.github.github/github-mcp-server": {
                        "type": "http",
                        "url": "https://api.githubcopilot.com/mcp/",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    result = import_client_config(
        source,
        project_name="import-test",
        audit_path=str(tmp_path / "audit.jsonl"),
        approvals_path=str(tmp_path / "approvals.sqlite3"),
        base_url="http://127.0.0.1:8765",
        wrapper_command="mcpzt",
        mcpzt_config_path=tmp_path / "mcpzt.yaml",
    )

    mcpzt_config = yaml.safe_load(result.mcpzt_config_yaml)
    client_config = json.loads(result.client_config_json)

    assert mcpzt_config["servers"][0]["name"] == "io.github.github-github-mcp-server"
    assert mcpzt_config["servers"][0]["transport"] == "http"
    wrapped = client_config["mcpServers"]["io.github.github/github-mcp-server"]
    assert wrapped["command"] == "npx"
    assert wrapped["args"][-1] == "http://127.0.0.1:8765/mcp/io.github.github-github-mcp-server"


def test_import_client_config_rejects_already_wrapped_servers(tmp_path: Path) -> None:
    source = tmp_path / "claude_desktop_config.json"
    source.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "pencil": {
                        "command": "/usr/local/bin/mcpzt",
                        "args": ["wrap", "--config", "/tmp/mcpzt.yaml", "--server", "pencil"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="already points to an MCPZT wrapper"):
        import_client_config(
            source,
            project_name="import-test",
            audit_path=str(tmp_path / "audit.jsonl"),
            approvals_path=str(tmp_path / "approvals.sqlite3"),
            base_url="http://127.0.0.1:8765",
            wrapper_command="mcpzt",
            mcpzt_config_path=tmp_path / "mcpzt.yaml",
        )
