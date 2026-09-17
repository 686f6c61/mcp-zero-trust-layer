from __future__ import annotations

import json
import os

# Stdio MCP upstreams require subprocess; command is an argv list and shell is disabled.
import subprocess  # nosec B404
import sys
import time
from typing import Any, TextIO

try:
    import select
except ImportError:  # pragma: no cover - platform fallback
    select = None  # type: ignore[assignment]

from mcp_zero_trust_layer.config.models import ServerConfig
from mcp_zero_trust_layer.config.secrets import SecretError, resolve_secret_value
from mcp_zero_trust_layer.protocol import JSONRPCError
from mcp_zero_trust_layer.protocol.jsonrpc import require_jsonrpc_message, strict_json_loads


class StdioProcessUpstream:
    def __init__(self, server: ServerConfig):
        if not server.command:
            raise JSONRPCError(-32603, "stdio upstream command is not configured")
        self.server = server
        self._read_buffer = bytearray()
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

        deadline = time.monotonic() + self.server.timeout
        try:
            self._write_with_timeout(message, deadline)
            if "id" not in message or "method" not in message:
                return None
            while True:
                response_line = self._readline_with_timeout(deadline)
                if not response_line:
                    raise JSONRPCError(-32030, "stdio upstream closed stdout")
                try:
                    response = strict_json_loads(response_line)
                except (ValueError, UnicodeError) as exc:
                    raise JSONRPCError(-32603, "invalid JSON from stdio upstream") from exc
                try:
                    require_jsonrpc_message(response)
                except JSONRPCError as exc:
                    raise JSONRPCError(-32603, "invalid JSON-RPC response from stdio upstream") from exc
                if "method" in response:
                    if "id" in response:
                        raise JSONRPCError(-32603, "server-initiated stdio requests are unsupported")
                    raise JSONRPCError(-32603, "server-initiated stdio notifications are unsupported")
                if (response.get("id") != message["id"]
                        or type(response.get("id")) is not type(message["id"])
                        or ("result" in response) == ("error" in response)):
                    raise JSONRPCError(-32603, "mismatched or invalid stdio response")
                return response
        except JSONRPCError:
            # Late replies must not be mistaken for the next call's response.
            self.close()
            raise

    def _write_with_timeout(self, message: dict[str, Any], deadline: float) -> None:
        assert self.process.stdin is not None
        if select is None or os.name != "posix":
            raise JSONRPCError(-32603, "bounded stdio transport requires POSIX pipes")
        data = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        fd = self.process.stdin.fileno()
        os.set_blocking(fd, False)
        offset = 0
        try:
            while offset < len(data):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise JSONRPCError(-32002, "stdio upstream timeout", {"server": self.server.name})
                _, ready, _ = select.select([], [fd], [], remaining)
                if not ready:
                    raise JSONRPCError(-32002, "stdio upstream timeout", {"server": self.server.name})
                try:
                    offset += os.write(fd, data[offset:offset + 65536])
                except BlockingIOError:
                    continue
        except OSError as exc:
            raise JSONRPCError(-32030, "stdio upstream pipe write failed") from exc

    def _readline_with_timeout(self, deadline: float | None = None) -> bytes:
        assert self.process.stdout is not None
        deadline = deadline if deadline is not None else time.monotonic() + self.server.timeout
        if select is None or os.name != "posix":
            raise JSONRPCError(-32603, "bounded stdio transport requires POSIX pipes")
        while True:
            newline = self._read_buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self._read_buffer[:newline])
                del self._read_buffer[:newline + 1]
                return line
            if len(self._read_buffer) > self.server.max_response_bytes:
                raise JSONRPCError(-32032, "stdio upstream response too large")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise JSONRPCError(-32002, "stdio upstream timeout", {"server": self.server.name})
            ready, _, _ = select.select([self.process.stdout], [], [], remaining)
            if not ready:
                raise JSONRPCError(-32002, "stdio upstream timeout", {"server": self.server.name})
            chunk = os.read(self.process.stdout.fileno(), min(65536, self.server.max_response_bytes + 1 - len(self._read_buffer)))
            if not chunk:
                if self._read_buffer:
                    raise JSONRPCError(-32603, "incomplete stdio upstream frame")
                return b""
            self._read_buffer.extend(chunk)

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
