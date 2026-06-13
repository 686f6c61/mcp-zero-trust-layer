from __future__ import annotations

from typing import Any, Literal

from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.policy.engine import PolicyEngine

CapabilityType = Literal["tool", "resource", "prompt"]


def filter_capabilities(
    config: MCPZTConfig,
    server: str,
    capability_type: CapabilityType,
    capabilities: list[dict[str, Any]],
    *,
    identity: Identity | None = None,
    environment: str | None = None,
) -> list[dict[str, Any]]:
    """Return only capabilities visible to the supplied identity/context."""
    if config.runtime.dry_run:
        return capabilities

    method_by_type = {
        "tool": "tools/list",
        "resource": "resources/list",
        "prompt": "prompts/list",
    }
    name_key_by_type = {
        "tool": "name",
        "resource": "uri",
        "prompt": "name",
    }
    engine = PolicyEngine(config)
    visible: list[dict[str, Any]] = []
    name_key = name_key_by_type[capability_type]

    for capability in capabilities:
        capability_name = capability.get(name_key)
        context = RequestContext(
            server=server,
            method=method_by_type[capability_type],
            capability_type=capability_type,
            capability=capability_name,
            identity=identity or Identity(),
            environment=environment or config.project.environment,
            config_base_dir=config.config_base_dir,
        )
        decision = engine.evaluate(context)
        if decision.decision in {"allow", "require_approval", "redact", "limit", "transform", "log"}:
            visible.append(capability)

    return visible
