from __future__ import annotations

import json
import os
# Stdio MCP upstreams require subprocess; command is an argv list and shell is disabled.
import subprocess  # nosec B404
import sys
from typing import Any, TextIO

from mcp_zero_trust_layer.config.models import ServerConfig
from mcp_zero_trust_layer.config.secrets import SecretError, resolve_secret_value
from mcp_zero_trust_layer.protocol import JSONRPCError


class StdioProcessUpstream:
    def __init__(self, server: ServerConfig):
        if not server.command:
            raise JSONRPCError(-32603, "stdio upstream command is not configured")
        self.server = server
        self.process = subprocess.Popen(  # nosec B603
            server.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_stdio_env(server),
            text=True,
            bufsize=1,
            shell=False,
        )

    def send(
        self,
        server: ServerConfig,
        message: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        _ = server, headers
        if self.process.stdin is None or self.process.stdout is None:
            raise JSONRPCError(-32603, "stdio upstream pipes are not available")
        if self.process.poll() is not None:
            raise JSONRPCError(
                -32030,
                "stdio upstream process exited",
                {"returncode": self.process.returncode},
            )

        line = json.dumps(message, separators=(",", ":"))
        self.process.stdin.write(line + "\n")
        self.process.stdin.flush()

        if "id" not in message or "method" not in message:
            return None

        response_line = self.process.stdout.readline()
        if not response_line:
            raise JSONRPCError(-32030, "stdio upstream closed stdout")
        try:
            response = json.loads(response_line)
        except json.JSONDecodeError as exc:
            raise JSONRPCError(-32603, "invalid JSON from stdio upstream") from exc
        if not isinstance(response, dict):
            raise JSONRPCError(-32603, "invalid JSON-RPC response from stdio upstream")
        return response

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def pump_stderr(self, target: TextIO | None = None) -> None:
        if self.process.stderr is None:
            return
        target = target or sys.stderr
        for line in self.process.stderr:
            target.write(line)
            target.flush()


def _stdio_env(server: ServerConfig) -> dict[str, str] | None:
    if not server.env:
        return None
    env = os.environ.copy()
    for key, value in server.env.items():
        try:
            env[key] = resolve_secret_value(value, field=f"servers.{server.name}.env.{key}")
        except SecretError as exc:
            raise JSONRPCError(-32031, "Stdio secret is not configured", {"error": str(exc)}) from exc
    return env
