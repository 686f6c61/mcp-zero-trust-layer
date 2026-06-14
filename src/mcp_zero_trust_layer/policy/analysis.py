from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from mcp_zero_trust_layer.capabilities.discovery import CapabilitySnapshot
from mcp_zero_trust_layer.capabilities.mapping import lookup_capability_metadata
from mcp_zero_trust_layer.config.models import MCPZTConfig, PolicyConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.policy.engine import PolicyEngine

CapabilityType = Literal["tool", "resource", "prompt"]
AnalysisSeverity = Literal["info", "low", "medium", "high", "critical"]

METHOD_BY_TYPE: dict[CapabilityType, str] = {
    "tool": "tools/call",
    "resource": "resources/read",
    "prompt": "prompts/get",
}
LIST_METHOD_BY_TYPE: dict[CapabilityType, str] = {
    "tool": "tools/list",
    "resource": "resources/list",
    "prompt": "prompts/list",
}


class PolicyCoverageItem(BaseModel):
    server: str
    capability_type: CapabilityType
    capability: str
    mapped: bool
    source: Literal["config", "snapshot"]
    decision: str
    policy_id: str | None = None
    risk: str | None = None
    access: str | None = None
    action: str | None = None
    resource_type: str | None = None


class PolicyCoverageReport(BaseModel):
    items: list[PolicyCoverageItem] = Field(default_factory=list)


class PolicyRiskFinding(BaseModel):
    severity: AnalysisSeverity
    rule_id: str
    server: str
    capability_type: CapabilityType | None = None
    capability: str | None = None
    policy_id: str | None = None
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class PolicyRiskReport(BaseModel):
    findings: list[PolicyRiskFinding] = Field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(finding.severity in {"high", "critical"} for finding in self.findings)


class UnusedPolicyItem(BaseModel):
    policy_id: str
    effect: str
    message: str


class UnusedPolicyReport(BaseModel):
    policies: list[UnusedPolicyItem] = Field(default_factory=list)


def build_policy_coverage(
    config: MCPZTConfig,
    *,
    snapshot: CapabilitySnapshot | None = None,
) -> PolicyCoverageReport:
    engine = PolicyEngine(config)
    items: list[PolicyCoverageItem] = []
    for capability in _capabilities(config, snapshot=snapshot):
        context = _context_for_capability(config, capability)
        metadata = lookup_capability_metadata(config, context)
        decision = engine.evaluate(context)
        items.append(
            PolicyCoverageItem(
                server=capability["server"],
                capability_type=capability["capability_type"],
                capability=capability["capability"],
                mapped=metadata is not None,
                source=capability["source"],
                decision=decision.decision,
                policy_id=decision.policy_id,
                risk=metadata.risk if metadata else None,
                access=metadata.access if metadata else None,
                action=metadata.action if metadata else None,
                resource_type=metadata.resource_type if metadata else None,
            )
        )
    return PolicyCoverageReport(items=items)


def find_policy_risks(
    config: MCPZTConfig,
    *,
    snapshot: CapabilitySnapshot | None = None,
) -> PolicyRiskReport:
    coverage = build_policy_coverage(config, snapshot=snapshot)
    findings: list[PolicyRiskFinding] = []
    if config.runtime.default_decision == "allow":
        findings.append(
            PolicyRiskFinding(
                severity="high",
                rule_id="default-allow",
                server="*",
                message="runtime.default_decision allows unmatched capabilities",
            )
        )

    for item in coverage.items:
        findings.extend(_coverage_risks(config, item))
    return PolicyRiskReport(findings=findings)


def find_unused_policies(
    config: MCPZTConfig,
    *,
    snapshot: CapabilitySnapshot | None = None,
) -> UnusedPolicyReport:
    contexts = _analysis_contexts(config, snapshot=snapshot)
    structurally_matched: set[str] = set()
    engine = PolicyEngine(config)
    for context in contexts:
        explanation = engine.explain(context)
        for policy in explanation.get("policies", []):
            match = policy.get("match") if isinstance(policy, dict) else None
            if isinstance(match, dict) and match.get("matched") is True:
                policy_id = policy.get("policy_id")
                if isinstance(policy_id, str):
                    structurally_matched.add(policy_id)

    unused = [
        UnusedPolicyItem(
            policy_id=policy.id,
            effect=policy.effect,
            message="policy did not structurally match any mapped or discovered capability",
        )
        for policy in config.policies
        if policy.id not in structurally_matched and not _policy_is_global(policy)
    ]
    return UnusedPolicyReport(policies=unused)


def _coverage_risks(config: MCPZTConfig, item: PolicyCoverageItem) -> list[PolicyRiskFinding]:
    findings: list[PolicyRiskFinding] = []
    if not item.mapped:
        findings.append(
            PolicyRiskFinding(
                severity="medium",
                rule_id="missing-capability-mapping",
                server=item.server,
                capability_type=item.capability_type,
                capability=item.capability,
                message="capability has no semantic mapping",
            )
        )
    if item.risk in {"high", "critical"} and item.decision == "allow":
        findings.append(
            PolicyRiskFinding(
                severity="critical" if item.risk == "critical" else "high",
                rule_id="high-risk-direct-allow",
                server=item.server,
                capability_type=item.capability_type,
                capability=item.capability,
                policy_id=item.policy_id,
                message="high-risk capability is directly allowed without approval",
                evidence={"risk": item.risk, "access": item.access},
            )
        )
    if item.decision == "allow" and item.policy_id:
        policy = _policy_by_id(config, item.policy_id)
        if (
            policy
            and item.capability_type == "tool"
            and item.access in {"write", "delete", "admin", "execute"}
            and not policy.input
            and not policy.validators
        ):
            findings.append(
                PolicyRiskFinding(
                    severity="high",
                    rule_id="side-effect-allow-without-input-constraints",
                    server=item.server,
                    capability_type=item.capability_type,
                    capability=item.capability,
                    policy_id=policy.id,
                    message="side-effecting tool is allowed without input or validator constraints",
                    evidence={"access": item.access},
                )
            )
    if item.decision == config.runtime.default_decision and item.policy_id is None:
        severity: AnalysisSeverity = "medium" if item.decision == "deny" else "high"
        findings.append(
            PolicyRiskFinding(
                severity=severity,
                rule_id=f"default-{item.decision}-decision",
                server=item.server,
                capability_type=item.capability_type,
                capability=item.capability,
                message=f"capability falls through to default {item.decision}",
            )
        )
    return findings


def _capabilities(
    config: MCPZTConfig,
    *,
    snapshot: CapabilitySnapshot | None,
) -> list[dict[str, Any]]:
    if snapshot is not None:
        return _snapshot_capabilities(snapshot)

    capabilities: list[dict[str, Any]] = []
    for server_name, mappings in config.capability_mappings.items():
        for capability_type, mapped in [
            ("tool", mappings.tools),
            ("resource", mappings.resources),
            ("prompt", mappings.prompts),
        ]:
            capabilities.extend(
                {
                    "server": server_name,
                    "capability_type": capability_type,
                    "capability": capability,
                    "source": "config",
                }
                for capability in sorted(mapped)
            )
    return capabilities


def _snapshot_capabilities(snapshot: CapabilitySnapshot) -> list[dict[str, Any]]:
    capabilities: list[dict[str, Any]] = []
    for capability_type, items, identity_key in [
        ("tool", snapshot.tools, "name"),
        ("resource", snapshot.resources, "uri"),
        ("prompt", snapshot.prompts, "name"),
    ]:
        for item in items:
            identity = item.get(identity_key)
            if isinstance(identity, str):
                capabilities.append(
                    {
                        "server": snapshot.server,
                        "capability_type": capability_type,
                        "capability": identity,
                        "source": "snapshot",
                    }
                )
    return capabilities


def _analysis_contexts(
    config: MCPZTConfig,
    *,
    snapshot: CapabilitySnapshot | None,
) -> list[RequestContext]:
    contexts: list[RequestContext] = []
    for capability in _capabilities(config, snapshot=snapshot):
        inbound = _context_for_capability(config, capability)
        list_context = inbound.model_copy(update={"method": LIST_METHOD_BY_TYPE[inbound.capability_type]})
        contexts.append(inbound)
        contexts.append(list_context)
        contexts.append(inbound.model_copy(update={"direction": "outbound", "output": {}}))
    return contexts


def _context_for_capability(config: MCPZTConfig, capability: dict[str, Any]) -> RequestContext:
    capability_type = capability["capability_type"]
    return RequestContext(
        server=capability["server"],
        method=METHOD_BY_TYPE[capability_type],
        capability_type=capability_type,
        capability=capability["capability"],
        identity=Identity(subject="policy-analysis", environment=config.project.environment),
        environment=config.project.environment,
        config_base_dir=config.config_base_dir,
    )


def _policy_by_id(config: MCPZTConfig, policy_id: str) -> PolicyConfig | None:
    return next((policy for policy in config.policies if policy.id == policy_id), None)


def _policy_is_global(policy: PolicyConfig) -> bool:
    match = policy.match
    return not any(
        [
            match.server,
            match.method,
            match.capability_type,
            match.capability,
            match.capabilities,
            match.action,
            match.risk,
            match.access,
            match.resource_type,
            match.tag,
            match.tags,
            match.data_classification,
        ]
    )
