from __future__ import annotations

from typing import Any, Protocol

from mcp_zero_trust_layer.config.models import ServerConfig


class UpstreamClient(Protocol):
    def send(
        self,
        server: ServerConfig,
        message: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Send a JSON-RPC message upstream and return the JSON-RPC response."""

