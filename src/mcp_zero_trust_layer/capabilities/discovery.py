from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from mcp_zero_trust_layer import __version__
from mcp_zero_trust_layer.config.models import MCPZTConfig, ServerConfig
from mcp_zero_trust_layer.upstream import UpstreamClient

DISCOVERY_METHODS = {
    "tools": ("tools/list", "tools", "name"),
    "resources": ("resources/list", "resources", "uri"),
    "prompts": ("prompts/list", "prompts", "name"),
}
DISCOVERY_PROTOCOL_VERSION = "2025-03-26"


class CapabilitySnapshot(BaseModel):
    server: str
    discovered_at: str
    tools: list[dict[str, Any]] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    prompts: list[dict[str, Any]] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)


class CapabilityDiff(BaseModel):
    server: str
    added: dict[str, list[str]] = Field(default_factory=dict)
    removed: dict[str, list[str]] = Field(default_factory=dict)
    changed: dict[str, list[str]] = Field(default_factory=dict)

    def has_changes(self) -> bool:
        return any(self.added.values()) or any(self.removed.values()) or any(self.changed.values())


def discover_capabilities(
    config: MCPZTConfig,
    server_name: str,
    upstream: UpstreamClient,
) -> CapabilitySnapshot:
    server = _server(config, server_name)
    snapshot = CapabilitySnapshot(
        server=server.name,
        discovered_at=datetime.now(timezone.utc).isoformat(),
    )
    _initialize_for_discovery(server, upstream, snapshot)
    for field, (method, result_key, _identity_key) in DISCOVERY_METHODS.items():
        request = {"jsonrpc": "2.0", "id": field, "method": method, "params": {}}
        try:
            response = upstream.send(server, request)
        except Exception as exc:  # discovery should collect per-capability errors
            snapshot.errors[field] = str(exc)
            continue
        result = response.get("result") if isinstance(response, dict) else None
        items = result.get(result_key) if isinstance(result, dict) else []
        if isinstance(items, list):
            setattr(snapshot, field, items)
    return snapshot


def _initialize_for_discovery(
    server: ServerConfig,
    upstream: UpstreamClient,
    snapshot: CapabilitySnapshot,
) -> None:
    request = {
        "jsonrpc": "2.0",
        "id": "initialize",
        "method": "initialize",
        "params": {
            "protocolVersion": DISCOVERY_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-zero-trust-layer", "version": __version__},
        },
    }
    try:
        response = upstream.send(server, request)
    except Exception as exc:  # discovery should keep collecting what it can
        snapshot.errors["initialize"] = str(exc)
        return
    if isinstance(response, dict) and response.get("error"):
        snapshot.errors["initialize"] = json.dumps(response["error"], sort_keys=True)
        return
    try:
        upstream.send(
            server,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
    except Exception as exc:
        snapshot.errors["initialized"] = str(exc)


def diff_snapshots(previous: CapabilitySnapshot, current: CapabilitySnapshot) -> CapabilityDiff:
    diff = CapabilityDiff(server=current.server)
    for field, (_method, _result_key, identity_key) in DISCOVERY_METHODS.items():
        previous_items = _indexed(getattr(previous, field), identity_key)
        current_items = _indexed(getattr(current, field), identity_key)
        previous_names = set(previous_items)
        current_names = set(current_items)
        diff.added[field] = sorted(current_names - previous_names)
        diff.removed[field] = sorted(previous_names - current_names)
        diff.changed[field] = sorted(
            name
            for name in previous_names & current_names
            if _fingerprint(previous_items[name]) != _fingerprint(current_items[name])
        )
    return diff


def write_snapshot(snapshot: CapabilitySnapshot, path: str | Path) -> None:
    snapshot_path = Path(path)
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(snapshot.model_dump_json(indent=2) + "\n", encoding="utf-8")


def read_snapshot(path: str | Path) -> CapabilitySnapshot:
    return CapabilitySnapshot.model_validate_json(Path(path).read_text(encoding="utf-8"))


def default_snapshot_path(server_name: str) -> Path:
    return Path(".mcpzt-capabilities") / f"{server_name}.json"


def _server(config: MCPZTConfig, name: str) -> ServerConfig:
    for server in config.servers:
        if server.name == name:
            return server
    raise ValueError(f"unknown server: {name}")


def _indexed(items: list[dict[str, Any]], identity_key: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for item in items:
        identity = item.get(identity_key)
        if isinstance(identity, str):
            indexed[identity] = item
    return indexed


def _fingerprint(item: dict[str, Any]) -> str:
    canonical = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
