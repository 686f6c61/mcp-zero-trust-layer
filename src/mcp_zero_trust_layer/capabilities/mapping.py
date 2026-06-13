from __future__ import annotations

from mcp_zero_trust_layer.config.models import CapabilityMetadata, MCPZTConfig
from mcp_zero_trust_layer.core import RequestContext


def lookup_capability_metadata(
    config: MCPZTConfig, context: RequestContext
) -> CapabilityMetadata | None:
    if not context.capability:
        return None

    server_mappings = config.capability_mappings.get(context.server)
    if not server_mappings:
        return None

    if context.capability_type == "tool":
        return server_mappings.tools.get(context.capability)
    if context.capability_type == "resource":
        return server_mappings.resources.get(context.capability)
    if context.capability_type == "prompt":
        return server_mappings.prompts.get(context.capability)
    return None

