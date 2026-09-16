from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

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
    if not isinstance(data, dict):
        raise ValueError("client config must be a JSON object")
    source_servers = _source_servers(data)
    root = "mcpServers" if "mcpServers" in data else "servers"
    used_names: set[str] = set()
    mcpzt_servers: list[dict[str, Any]] = []
    client_servers: dict[str, dict[str, Any]] = {}
    imported: list[ImportedServer] = []

    for source_name, source_server in source_servers.items():
        if not isinstance(source_server, dict):
            raise ValueError(
                f"server {source_name!r}: no supported MCP servers entry (expected object)"
            )
        _validate_import_entry(source_name, source_server)
        if _is_mcpzt_wrapper(source_server):
            raise ValueError(
                f"server {source_name!r} already points to an MCPZT wrapper; "
                "import the original client config or a backup made before wrapping"
            )
        logical_name = _unique_logical_name(source_name, used_names)
        server_payload = _mcpzt_server(logical_name, source_server)
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
    client_payload = deepcopy(data)
    client_payload[root] = client_servers
    return ClientImport(
        mcpzt_config_yaml=yaml.safe_dump(payload, sort_keys=False),
        client_config_json=json.dumps(client_payload, indent=2, sort_keys=True),
        servers=tuple(imported),
    )


def _source_servers(data: dict[str, Any]) -> dict[str, Any]:
    if "mcpServers" in data and "servers" in data:
        raise ValueError("ambiguous client config: both mcpServers and servers are present")
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        return servers
    servers = data.get("servers")
    if isinstance(servers, dict):
        return servers
    raise ValueError("client config must contain an mcpServers or servers object")


def _mcpzt_server(logical_name: str, source_server: dict[str, Any]) -> dict[str, Any]:
    url = source_server.get("httpUrl", source_server.get("url"))
    if isinstance(url, str):
        payload: dict[str, Any] = {
            "name": logical_name,
            "transport": "http",
            "upstream": url,
        }
        if isinstance(source_server.get("headers"), dict):
            payload["upstream_headers"] = source_server["headers"]
        return payload
    raw_env = source_server.get("env")
    env = raw_env if isinstance(raw_env, dict) else {}
    return {
        "name": logical_name,
        "transport": "stdio",
        "command": [source_server["command"], *_list_args(source_server.get("args"))],
        "env": {key: f"env:{key}" for key in sorted(env)},
    }


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
            **deepcopy(source_server),
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
    client = deepcopy(source_server)
    # Original credentials belong only to the upstream, never to the gateway.
    client.pop("headers", None)
    url_key = "httpUrl" if "httpUrl" in client else "url"
    client[url_key] = f"{base_url.rstrip('/')}/mcp/{quote(str(mcpzt_server['name']), safe='')}"
    return client


def _validate_import_entry(name: str, entry: dict[str, Any]) -> None:
    supported = {
        "command",
        "args",
        "env",
        "url",
        "httpUrl",
        "headers",
        "type",
        "cwd",
        "sandboxEnabled",
        "disabled",
        "enabled",
        "autoApprove",
        "alwaysAllow",
        "disabledTools",
        "includeTools",
        "excludeTools",
        "timeout",
        "trust",
        "description",
    }
    unknown = sorted(set(entry) - supported)
    if unknown:
        raise ValueError(
            f"server {name!r}: unsupported fields: {', '.join(unknown)}; review manually"
        )
    if entry.get("type") is not None and (
        not isinstance(entry["type"], str) or entry["type"] not in {"stdio", "http"}
    ):
        raise ValueError(f"server {name!r}: unsupported transport type")
    targets = [key for key in ("command", "url", "httpUrl") if key in entry]
    if len(targets) != 1 or not isinstance(entry[targets[0]], str) or not entry[targets[0]]:
        raise ValueError(f"server {name!r}: no supported MCP servers entry; use one command or URL")
    if "args" in entry and (
        not isinstance(entry["args"], list)
        or any(not isinstance(arg, str) for arg in entry["args"])
    ):
        raise ValueError(f"server {name!r}: args must be a list of strings")
    for field in ("env", "headers"):
        if field in entry and (
            not isinstance(entry[field], dict)
            or any(not isinstance(v, str) for v in entry[field].values())
        ):
            raise ValueError(f"server {name!r}: {field} must map names to strings")
    is_http = targets[0] != "command"
    if is_http and any(key in entry for key in ("args", "env", "cwd", "sandboxEnabled")):
        raise ValueError(f"server {name!r}: unsupported process options on HTTP entry")
    if not is_http and "headers" in entry:
        raise ValueError(f"server {name!r}: unsupported headers on stdio entry")
    if entry.get("type") == ("stdio" if is_http else "http"):
        raise ValueError(f"server {name!r}: transport type does not match target")
    # env and cwd stay in the original host's interpolation context. The command,
    # args, URL and headers move to the gateway, where host variables do not exist.
    for field in ("command", "args", "url", "httpUrl", "headers"):
        value = entry.get(field)
        if value is not None and "${" in json.dumps(value):
            raise ValueError(
                f"server {name!r}: unsupported client interpolation in {field}; "
                "configure the upstream explicitly using MCPZT secret references"
            )


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
