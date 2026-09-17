from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from typing import TextIO

from mcp_zero_trust_layer.config import load_config
from mcp_zero_trust_layer.config.models import MCPZTConfig, ServerConfig
from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.protocol import error_response
from mcp_zero_trust_layer.protocol.jsonrpc import strict_json_loads
from mcp_zero_trust_layer.upstream.stdio import StdioProcessUpstream


def run_stdio_wrapper(
    config_path: Path,
    *,
    server_name: str | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    config = load_config(config_path)
    if config.audit.destination == "stdout":
        stderr.write("stdio mode cannot use audit.destination: stdout\n")
        stderr.flush()
        return 2

    server = _select_stdio_server(config, server_name)
    upstream = StdioProcessUpstream(server)
    stderr_thread = threading.Thread(target=upstream.pump_stderr, args=(stderr,), daemon=True)
    stderr_thread.start()
    pipeline = MCPPipeline(config, upstream)
    identity = Identity(
        subject="stdio-client",
        client_id="stdio",
        auth_method=config.auth.mode,
        environment=config.project.environment,
    )

    try:
        while True:
            line = stdin.readline(config.runtime.max_request_bytes + 1)
            if not line:
                break
            if len(line.encode("utf-8")) > config.runtime.max_request_bytes:
                _write_protocol(stdout, error_response(None, -32042, "Request body too large"))
                return 2
            line = line.strip()
            if not line:
                continue
            try:
                message = strict_json_loads(line)
            except json.JSONDecodeError:
                _write_protocol(stdout, error_response(None, -32700, "Parse error"))
                continue
            if not isinstance(message, dict):
                _write_protocol(stdout, error_response(None, -32600, "Invalid Request"))
                continue
            response = pipeline.handle(server.name, message, identity=identity)
            if response is not None:
                _write_protocol(stdout, response)
    finally:
        upstream.close()
    return 0


def _select_stdio_server(config: MCPZTConfig, server_name: str | None) -> ServerConfig:
    servers = [server for server in config.servers if server.transport == "stdio"]
    if server_name:
        servers = [server for server in servers if server.name == server_name]
    if not servers:
        raise ValueError("no matching stdio server configured")
    return servers[0]


def _write_protocol(stdout: TextIO, message: dict[str, object]) -> None:
    stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    stdout.flush()
