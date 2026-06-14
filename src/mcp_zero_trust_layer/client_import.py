from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ImportedServer:
    source_name: str
    logical_name: str
    transport: str
    env_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClientImport:
    mcpzt_config_yaml: str
    client_config_json: str
    servers: tuple[ImportedServer, ...]


def import_client_config(
    source: Path,
    *,
    project_name: str,
    audit_path: str,
    approvals_path: str,
    base_url: str,
    wrapper_command: str,
    mcpzt_config_path: Path,
) -> ClientImport:
    data = json.loads(source.expanduser().read_text(encoding="utf-8"))
    source_servers = _source_servers(data)
    used_names: set[str] = set()
    mcpzt_servers: list[dict[str, Any]] = []
    client_servers: dict[str, dict[str, Any]] = {}
    imported: list[ImportedServer] = []

    for source_name, source_server in source_servers.items():
        if not isinstance(source_server, dict):
            continue
        if _is_mcpzt_wrapper(source_server):
            raise ValueError(
                f"server {source_name!r} already points to an MCPZT wrapper; "
                "import the original client config or a backup made before wrapping"
            )
        logical_name = _unique_logical_name(source_name, used_names)
        server_payload = _mcpzt_server(logical_name, source_server)
        if server_payload is None:
            continue
        mcpzt_servers.append(server_payload)
        client_servers[source_name] = _client_server(
            source_server,
            server_payload,
            base_url=base_url,
            wrapper_command=wrapper_command,
            mcpzt_config_path=mcpzt_config_path,
        )
        imported.append(
            ImportedServer(
                source_name=source_name,
                logical_name=logical_name,
                transport=str(server_payload["transport"]),
                env_keys=tuple(sorted((source_server.get("env") or {}).keys())),
            )
        )
    if not imported:
        raise ValueError("no supported MCP servers found; expected command or url entries")

    payload = {
        "project": {"name": project_name, "environment": "development"},
        "runtime": {"mode": _runtime_mode(mcpzt_servers), "default_decision": "deny"},
        "auth": {"mode": "none"},
        "servers": mcpzt_servers,
        "capability_mappings": {},
        "policies": _default_import_policies(),
        "audit": {"destination": "file", "path": audit_path, "hash_chain": True},
        "approvals": {"backend": "sqlite", "path": approvals_path, "default_ttl_seconds": 900},
    }
    return ClientImport(
        mcpzt_config_yaml=yaml.safe_dump(payload, sort_keys=False),
        client_config_json=json.dumps({"mcpServers": client_servers}, indent=2, sort_keys=True),
        servers=tuple(imported),
    )


def _source_servers(data: dict[str, Any]) -> dict[str, Any]:
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        return servers
    servers = data.get("servers")
    if isinstance(servers, dict):
        return servers
    raise ValueError("client config must contain an mcpServers or servers object")


def _mcpzt_server(logical_name: str, source_server: dict[str, Any]) -> dict[str, Any] | None:
    if isinstance(source_server.get("url"), str):
        payload: dict[str, Any] = {
            "name": logical_name,
            "transport": "http",
            "upstream": source_server["url"],
        }
        if isinstance(source_server.get("headers"), dict):
            payload["upstream_headers"] = source_server["headers"]
        return payload
    if isinstance(source_server.get("command"), str):
        env = source_server.get("env") if isinstance(source_server.get("env"), dict) else {}
        return {
            "name": logical_name,
            "transport": "stdio",
            "command": [source_server["command"], *_list_args(source_server.get("args"))],
            "env": {key: f"env:{key}" for key in sorted(env)},
        }
    return None


def _client_server(
    source_server: dict[str, Any],
    mcpzt_server: dict[str, Any],
    *,
    base_url: str,
    wrapper_command: str,
    mcpzt_config_path: Path,
) -> dict[str, Any]:
    if mcpzt_server["transport"] == "stdio":
        client: dict[str, Any] = {
            "command": wrapper_command,
            "args": [
                "wrap",
                "--config",
                str(mcpzt_config_path.expanduser()),
                "--server",
                str(mcpzt_server["name"]),
            ],
        }
        if isinstance(source_server.get("env"), dict) and source_server["env"]:
            client["env"] = source_server["env"]
        return client
    return {
        "command": "npx",
        "args": ["-y", "mcp-remote", f"{base_url.rstrip('/')}/mcp/{mcpzt_server['name']}"],
    }


def _list_args(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _is_mcpzt_wrapper(source_server: dict[str, Any]) -> bool:
    command = source_server.get("command")
    if not isinstance(command, str):
        return False
    command_name = Path(command).name
    args = _list_args(source_server.get("args"))
    return command_name in {"mcpzt", "mcp-zero-trust-layer"} and "wrap" in args


def _unique_logical_name(source_name: str, used: set[str]) -> str:
    base = re.sub(r"[^a-zA-Z0-9_.-]+", "-", source_name).strip("-._")
    base = base or "mcp"
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}-{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _runtime_mode(servers: list[dict[str, Any]]) -> str:
    transports = {server.get("transport") for server in servers}
    if transports == {"stdio"}:
        return "stdio"
    if transports == {"http"}:
        return "gateway"
    return "gateway"


def _default_import_policies() -> list[dict[str, Any]]:
    return [
        {
            "id": "allow-mcp-initialize",
            "effect": "allow",
            "match": {"method": "initialize"},
            "reason": "allow MCP client/server initialization",
        },
        {
            "id": "allow-mcp-ping",
            "effect": "allow",
            "match": {"method": "ping"},
            "reason": "allow MCP keepalive checks",
        },
        {
            "id": "imported-tools-need-approval",
            "effect": "require_approval",
            "match": {"capability_type": "tool"},
            "reason": "safe imported default: require approval until onboarding is reviewed",
        },
        {
            "id": "allow-imported-resource-and-prompt-reads",
            "effect": "allow",
            "match": {"capability_type": "resource"},
            "reason": "allow imported resource reads by default",
        },
        {
            "id": "allow-imported-prompts",
            "effect": "allow",
            "match": {"capability_type": "prompt"},
            "reason": "allow imported prompts by default",
        },
    ]
