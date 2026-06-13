from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from mcp_zero_trust_layer.identity import Identity


Direction = Literal["inbound", "outbound"]


class RequestContext(BaseModel):
    """Normalized context passed into policy evaluation."""

    server: str
    method: str
    capability_type: Literal["tool", "resource", "prompt", "method"] = "method"
    capability: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    output: Any | None = None
    direction: Direction = "inbound"
    identity: Identity = Field(default_factory=Identity)
    environment: str = "development"
    metadata: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str | None = None
    config_base_dir: str | None = None
