from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from mcp_zero_trust_layer.client_import import import_client_config


def _run(source: Path, tmp_path: Path):
    return import_client_config(
        source,
        project_name="import-test",
        audit_path=str(tmp_path / "audit.jsonl"),
        approvals_path=str(tmp_path / "approvals.sqlite3"),
        base_url="http://127.0.0.1:8765",
        wrapper_command="mcpzt",
        mcpzt_config_path=tmp_path / "mcpzt.yaml",
    )


def test_missing_servers_object(tmp_path: Path) -> None:
    source = tmp_path / "c.json"
    source.write_text(json.dumps({"other": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="mcpServers or servers object"):
        _run(source, tmp_path)


def test_no_supported_servers(tmp_path: Path) -> None:
    source = tmp_path / "c.json"
    source.write_text(
        json.dumps({"mcpServers": {"bad": "not-a-dict", "empty": {"foo": "bar"}}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="no supported MCP servers"):
        _run(source, tmp_path)


def test_mixed_transports_headers_collision_and_args(tmp_path: Path) -> None:
    source = tmp_path / "c.json"
    source.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "http-svc": {"url": "https://x/mcp", "headers": {"H": "v"}},
                    "std svc": {"command": "/bin/foo", "args": "notalist"},
                    "std/svc": {"command": "/bin/bar"},
                    "bad": "not-a-dict",
                    "empty": {"foo": "bar"},
                }
            }
        ),
        encoding="utf-8",
    )
    result = _run(source, tmp_path)
    mcpzt_config = yaml.safe_load(result.mcpzt_config_yaml)
    names = [s["name"] for s in mcpzt_config["servers"]]

    # mixed http + stdio -> gateway runtime mode (line 184)
    assert mcpzt_config["runtime"]["mode"] == "gateway"
    # http server keeps headers (line 110)
    http_server = next(s for s in mcpzt_config["servers"] if s["transport"] == "http")
    assert http_server["upstream_headers"] == {"H": "v"}
    # args not a list -> only the command (line 153)
    foo_server = next(s for s in mcpzt_config["servers"] if s.get("command", [None])[0] == "/bin/foo")
    assert foo_server["command"] == ["/bin/foo"]
    # name collision produces a numeric suffix (lines 172-173)
    assert "std-svc" in names
    assert "std-svc-2" in names
