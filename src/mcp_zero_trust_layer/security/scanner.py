from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, Field

from mcp_zero_trust_layer.capabilities.discovery import CapabilitySnapshot
from mcp_zero_trust_layer.capabilities.mapping import lookup_capability_metadata
from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.policy import PolicyEngine

Severity = Literal["info", "low", "medium", "high", "critical"]

SUSPICIOUS_TEXT = [
    re.compile(pattern, re.I)
    for pattern in [
        r"ignore (all )?(previous|prior) instructions",
        r"system prompt",
        r"exfiltrat",
        r"send.*secret",
        r"credential",
        r"api[_ -]?key",
        r"password",
    ]
]

DANGEROUS_TOOL_NAME = re.compile(
    r"(delete|drop|truncate|destroy|refund|merge|deploy|exec|shell|write|send_email|"
    r"create_user|update_permission)",
    re.I,
)


class ScanFinding(BaseModel):
    severity: Severity
    rule_id: str
    server: str
    capability_type: str
    capability: str
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class ScanReport(BaseModel):
    server: str
    findings: list[ScanFinding] = Field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(finding.severity in {"high", "critical"} for finding in self.findings)


def scan_snapshot(config: MCPZTConfig, snapshot: CapabilitySnapshot) -> ScanReport:
    engine = PolicyEngine(config)
    findings: list[ScanFinding] = []
    for item in snapshot.tools:
        findings.extend(_scan_tool(config, snapshot, engine, item))

    for item in snapshot.resources:
        findings.extend(_scan_resource(snapshot, item))

    for item in snapshot.prompts:
        findings.extend(_scan_prompt(snapshot, item))

    return ScanReport(server=snapshot.server, findings=findings)


def _scan_tool(
    config: MCPZTConfig,
    snapshot: CapabilitySnapshot,
    engine: PolicyEngine,
    item: dict[str, Any],
) -> list[ScanFinding]:
    name = item.get("name")
    if not isinstance(name, str):
        return []
    context = _tool_context(config, snapshot.server, name)
    findings = _tool_metadata_findings(config, snapshot.server, name, context)
    findings.extend(_tool_text_findings(snapshot.server, name, item))
    findings.extend(_dangerous_tool_findings(snapshot.server, name, engine.evaluate(context)))
    return findings


def _tool_context(config: MCPZTConfig, server: str, name: str) -> RequestContext:
    return RequestContext(
        server=server,
        method="tools/call",
        capability_type="tool",
        capability=name,
        identity=Identity(subject="scanner", environment=config.project.environment),
        environment=config.project.environment,
    )


def _tool_metadata_findings(
    config: MCPZTConfig,
    server: str,
    name: str,
    context: RequestContext,
) -> list[ScanFinding]:
    if lookup_capability_metadata(config, context) is not None:
        return []
    return [
        ScanFinding(
            severity="medium",
            rule_id="missing-capability-metadata",
            server=server,
            capability_type="tool",
            capability=name,
            message="tool has no capability_mappings metadata",
        )
    ]


def _tool_text_findings(server: str, name: str, item: dict[str, Any]) -> list[ScanFinding]:
    matched_patterns = [pattern.pattern for pattern in SUSPICIOUS_TEXT if pattern.search(_searchable_text(item))]
    if not matched_patterns:
        return []
    return [
        ScanFinding(
            severity="high",
            rule_id="suspicious-capability-text",
            server=server,
            capability_type="tool",
            capability=name,
            message="tool description or schema contains suspicious security-sensitive text",
            evidence={"patterns": matched_patterns[:5]},
        )
    ]


def _dangerous_tool_findings(server: str, name: str, decision: Any) -> list[ScanFinding]:
    if not DANGEROUS_TOOL_NAME.search(name):
        return []
    if decision.decision == "allow":
        return [
            ScanFinding(
                severity="high",
                rule_id="dangerous-tool-allowed",
                server=server,
                capability_type="tool",
                capability=name,
                message="dangerous-looking tool is directly allowed without approval",
                evidence={"policy_id": decision.policy_id, "decision": decision.decision},
            )
        ]
    if decision.decision == "require_approval":
        return [
            ScanFinding(
                severity="low",
                rule_id="dangerous-tool-requires-approval",
                server=server,
                capability_type="tool",
                capability=name,
                message="dangerous-looking tool is gated by approval",
                evidence={"policy_id": decision.policy_id},
            )
        ]
    return []


def _scan_resource(snapshot: CapabilitySnapshot, item: dict[str, Any]) -> list[ScanFinding]:
    uri = item.get("uri")
    if not isinstance(uri, str) or not _contains_suspicious_text(item):
        return []
    return [
        ScanFinding(
            severity="medium",
            rule_id="suspicious-resource-text",
            server=snapshot.server,
            capability_type="resource",
            capability=uri,
            message="resource metadata contains suspicious security-sensitive text",
        )
    ]


def _scan_prompt(snapshot: CapabilitySnapshot, item: dict[str, Any]) -> list[ScanFinding]:
    name = item.get("name")
    if not isinstance(name, str) or not _contains_suspicious_text(item):
        return []
    return [
        ScanFinding(
            severity="high",
            rule_id="suspicious-prompt-text",
            server=snapshot.server,
            capability_type="prompt",
            capability=name,
            message="prompt metadata contains suspicious instruction text",
        )
    ]


def _contains_suspicious_text(item: dict[str, Any]) -> bool:
    text = _searchable_text(item)
    return any(pattern.search(text) for pattern in SUSPICIOUS_TEXT)


def _searchable_text(item: dict[str, Any]) -> str:
    return json.dumps(item, sort_keys=True, default=str)
