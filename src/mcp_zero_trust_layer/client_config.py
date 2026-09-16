"""Render host-specific connection snippets without reading credential values."""

from __future__ import annotations

import json
import re
import shlex
from typing import Any
from urllib.parse import quote, urlsplit

from mcp_zero_trust_layer.config.models import MCPZTConfig

CLIENT_KINDS = (
    "claude-desktop",
    "cursor",
    "vscode",
    "claude-code",
    "gemini",
    "codex",
    "grok",
    "json",
)


def render_client_config(
    config: MCPZTConfig,
    kind: str,
    *,
    base_url: str,
    server_name: str | None,
    token_env: str | None = None,
) -> str:
    if kind not in CLIENT_KINDS:
        raise ValueError(f"kind must be {', '.join(CLIENT_KINDS)}")
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or any(ord(char) < 33 for char in base_url)
    ):
        raise ValueError("base URL must be an HTTP(S) URL without credentials, query or fragment")
    selected = [
        s
        for s in config.servers
        if s.transport == "http" and (server_name is None or s.name == server_name)
    ]
    if not selected:
        raise ValueError("no matching HTTP server configured")
    auth = config.auth
    credential_env = token_env
    if auth.mode in {"static_token", "api_key"}:
        credential_env = credential_env or auth.token_env
        if not credential_env:
            raise ValueError("static authentication needs --token-env; secrets are never embedded")
    if credential_env and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", credential_env):
        raise ValueError("token environment variable must be a valid variable name")
    header = "Authorization" if auth.header.lower() == "authorization" else auth.header
    prefix = "Bearer " if header == "Authorization" and auth.mode != "api_key" else ""
    if credential_env and (not re.fullmatch(r"[A-Za-z0-9-]+", header)):
        raise ValueError("unsupported authentication header name")
    if credential_env and kind in {"claude-desktop", "claude-code", "json"}:
        raise ValueError(
            f"{kind} cannot safely render environment-backed authentication; "
            "use cursor, vscode, gemini, codex or grok, or configure client authentication manually"
        )

    servers: dict[str, dict[str, Any]] = {}
    commands: list[str] = []
    toml: list[str] = []
    for server in selected:
        name = f"mcpzt-{server.name}"
        url = f"{base_url.rstrip('/')}/mcp/{quote(server.name, safe='')}"
        if kind == "claude-code":
            commands.append(shlex.join(["claude", "mcp", "add", name, "--transport", "http", url]))
            continue
        if kind in {"codex", "grok"}:
            toml.extend([f"[mcp_servers.{json.dumps(name)}]", f"url = {json.dumps(url)}"])
            if credential_env:
                if kind == "codex" and prefix:
                    toml.append(f"bearer_token_env_var = {json.dumps(credential_env)}")
                elif kind == "codex":
                    toml.append(
                        f"env_http_headers = {{ {json.dumps(header)} = "
                        f"{json.dumps(credential_env)} }}"
                    )
                else:
                    value = prefix + "${" + credential_env + "}"
                    toml.append(f"headers = {{ {json.dumps(header)} = {json.dumps(value)} }}")
            toml.append("")
            continue
        if kind in {"claude-desktop", "json"}:
            entry: dict[str, Any] = {"command": "npx", "args": ["-y", "mcp-remote", url]}
        else:
            entry = {"httpUrl" if kind == "gemini" else "url": url}
            if kind == "vscode":
                entry["type"] = "http"
            if credential_env:
                reference = (
                    "${env:" + credential_env + "}"
                    if kind in {"cursor", "vscode"}
                    else "${" + credential_env + "}"
                )
                entry["headers"] = {header: prefix + reference}
        servers[name] = entry
    if kind == "claude-code":
        return "\n".join(commands)
    if kind in {"codex", "grok"}:
        return "\n".join(toml).rstrip()
    return json.dumps(
        {"servers" if kind == "vscode" else "mcpServers": servers}, indent=2, sort_keys=True
    )
