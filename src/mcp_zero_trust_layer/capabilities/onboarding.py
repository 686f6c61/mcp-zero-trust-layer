from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from mcp_zero_trust_layer.capabilities.discovery import CapabilitySnapshot
from mcp_zero_trust_layer.config.models import CapabilityMetadata, MCPZTConfig, ServerConfig

CapabilityKind = Literal["tools", "resources", "prompts"]

DESTRUCTIVE_RE = re.compile(r"(delete|drop|truncate|destroy|remove|purge|wipe)", re.I)
CRITICAL_RE = re.compile(r"(refund|payment|transfer|merge|deploy|release|permission|admin)", re.I)
WRITE_RE = re.compile(
    r"(write|update|create|send|email|invite|publish|commit|push|insert|modify|edit|set)",
    re.I,
)
EXECUTE_RE = re.compile(r"(exec|shell|run_command|command|script)", re.I)
READ_RE = re.compile(r"(get|list|search|read|find|fetch|query|select|show|describe)", re.I)
CONFIDENTIAL_RE = re.compile(
    r"(customer|user|email|phone|secret|token|key|credential|password|payment|invoice)",
    re.I,
)


class OnboardServerReport(BaseModel):
    server: str
    tools: int = 0
    resources: int = 0
    prompts: int = 0
    errors: dict[str, str] = Field(default_factory=dict)


class OnboardReport(BaseModel):
    servers: list[OnboardServerReport] = Field(default_factory=list)
    generated_policies: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class OnboardResult(BaseModel):
    config_yaml: str
    report: OnboardReport


def build_onboard_config(
    base_config: MCPZTConfig,
    snapshots: Iterable[CapabilitySnapshot],
) -> OnboardResult:
    snapshots = list(snapshots)
    capability_mappings = _capability_mappings(snapshots)
    policies = _policies_for_snapshots(snapshots)
    payload = {
        "project": base_config.project.model_dump(mode="json"),
        "runtime": base_config.runtime.model_dump(mode="json"),
        "auth": base_config.auth.model_dump(mode="json"),
        "servers": [_server_payload(server) for server in base_config.servers],
        "capability_mappings": capability_mappings,
        "policies": policies,
        "audit": base_config.audit.model_dump(mode="json"),
        "approvals": base_config.approvals.model_dump(mode="json"),
        "metrics": base_config.metrics.model_dump(mode="json"),
    }
    config_yaml = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)
    report = OnboardReport(
        servers=[
            OnboardServerReport(
                server=snapshot.server,
                tools=len(snapshot.tools),
                resources=len(snapshot.resources),
                prompts=len(snapshot.prompts),
                errors=snapshot.errors,
            )
            for snapshot in snapshots
        ],
        generated_policies=[str(policy["id"]) for policy in policies],
        recommendations=_recommendations(snapshots),
    )
    return OnboardResult(config_yaml=config_yaml, report=report)


def infer_capability_metadata(
    capability: str,
    *,
    capability_type: CapabilityKind,
    item: dict[str, Any] | None = None,
) -> CapabilityMetadata:
    item = item or {}
    text = _searchable_text(capability, item)
    access = _infer_access(text, capability_type, item)
    risk = _infer_risk(text, access)
    tags = ["generated"]
    if access in {"delete", "admin"}:
        tags.append("destructive")
    if access in {"write", "delete", "execute", "admin"}:
        tags.append("side-effect")
    data_classification = "confidential" if CONFIDENTIAL_RE.search(text) else None
    return CapabilityMetadata(
        action=f"{_resource_type(capability, text)}.{access}",
        risk=risk,
        access=access,
        resource_type=_resource_type(capability, text),
        tags=tags,
        data_classification=data_classification,
    )


def parse_server_specs(specs: list[str]) -> list[ServerConfig]:
    servers: list[ServerConfig] = []
    for spec in specs:
        if "=" not in spec:
            raise ValueError("--server must use name=url, for example github=http://localhost:3001/mcp")
        name, upstream = spec.split("=", 1)
        name = name.strip()
        upstream = upstream.strip()
        if not name or not upstream:
            raise ValueError("--server must include both a name and an upstream URL")
        servers.append(ServerConfig(name=name, transport="http", upstream=upstream))
    return servers


def _capability_mappings(snapshots: list[CapabilitySnapshot]) -> dict[str, dict[str, Any]]:
    mappings: dict[str, dict[str, Any]] = {}
    for snapshot in snapshots:
        mappings[snapshot.server] = {
            "tools": _mapped_capabilities(snapshot.tools, identity_key="name", capability_type="tools"),
            "resources": _mapped_capabilities(
                snapshot.resources,
                identity_key="uri",
                capability_type="resources",
            ),
            "prompts": _mapped_capabilities(
                snapshot.prompts,
                identity_key="name",
                capability_type="prompts",
            ),
        }
    return mappings


def _mapped_capabilities(
    items: list[dict[str, Any]],
    *,
    identity_key: str,
    capability_type: CapabilityKind,
) -> dict[str, dict[str, Any]]:
    mapped: dict[str, dict[str, Any]] = {}
    for item in items:
        identity = item.get(identity_key)
        if isinstance(identity, str):
            mapped[identity] = infer_capability_metadata(
                identity,
                capability_type=capability_type,
                item=item,
            ).model_dump(mode="json", exclude_none=True)
    return mapped


def _policies_for_snapshots(snapshots: list[CapabilitySnapshot]) -> list[dict[str, Any]]:
    policies: list[dict[str, Any]] = _control_plane_policies()
    for snapshot in snapshots:
        server = snapshot.server
        policies.extend(
            [
                {
                    "id": f"{server}-hide-destructive",
                    "effect": "hide",
                    "match": {"server": server, "tag": "destructive"},
                    "reason": "generated onboarding policy: destructive capabilities are hidden",
                },
                {
                    "id": f"{server}-critical-needs-approval",
                    "effect": "require_approval",
                    "match": {"server": server, "risk": "critical"},
                    "reason": "generated onboarding policy: critical capabilities need approval",
                },
                {
                    "id": f"{server}-high-needs-approval",
                    "effect": "require_approval",
                    "match": {"server": server, "risk": "high"},
                    "reason": "generated onboarding policy: high-risk capabilities need approval",
                },
                {
                    "id": f"{server}-allow-low-risk-read",
                    "effect": "allow",
                    "match": {"server": server, "risk": "low", "access": "read"},
                    "reason": "generated onboarding policy: low-risk reads are allowed",
                },
                {
                    "id": f"{server}-redact-confidential-output",
                    "effect": "redact",
                    "match": {"server": server, "data_classification": "confidential"},
                    "output": {
                        "redact_fields": [
                            "email",
                            "phone",
                            "api_key",
                            "token",
                            "secret",
                            "password",
                        ]
                    },
                    "reason": "generated onboarding policy: redact common confidential fields",
                },
            ]
        )
        policies.extend(_sql_policies(server, snapshot.tools))
    return _dedupe_policies(policies)


def _control_plane_policies() -> list[dict[str, Any]]:
    return [
        {
            "id": "allow-mcp-initialize",
            "effect": "allow",
            "match": {"method": "initialize"},
            "reason": "generated onboarding policy: allow MCP client/server initialization",
        },
        {
            "id": "allow-mcp-ping",
            "effect": "allow",
            "match": {"method": "ping"},
            "reason": "generated onboarding policy: allow MCP keepalive checks",
        },
    ]


def _sql_policies(server: str, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    query_tools = [
        item.get("name")
        for item in tools
        if isinstance(item.get("name"), str)
        and re.search(r"(sql|query|postgres|database|db)", _searchable_text(item["name"], item), re.I)
    ]
    policies: list[dict[str, Any]] = []
    for tool in query_tools:
        policies.append(
            {
                "id": f"{server}-{_policy_slug(tool)}-read-only-sql",
                "effect": "allow",
                "match": {"server": server, "capability": tool},
                "validators": [{"name": "sql_read_only", "options": {"query_arg": "query"}}],
                "reason": "generated onboarding policy: SQL-like query tools are read-only",
            }
        )
    return policies


def _dedupe_policies(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped = []
    for policy in policies:
        policy_id = str(policy["id"])
        if policy_id in seen:
            continue
        seen.add(policy_id)
        deduped.append(policy)
    return deduped


def _recommendations(snapshots: list[CapabilitySnapshot]) -> list[str]:
    recommendations = [
        "Review generated mappings before production; names and descriptions are only hints.",
        "Run mcpzt policy coverage, mcpzt policy risks and mcpzt scan before enforcement.",
        "Replace auth.mode none with api_key, jwt or oidc before sharing the gateway.",
    ]
    if any(snapshot.errors for snapshot in snapshots):
        recommendations.append("Some discovery calls returned errors; review snapshot errors manually.")
    return recommendations


def _server_payload(server: ServerConfig) -> dict[str, Any]:
    return server.model_dump(mode="json", exclude_none=True)


def _infer_access(text: str, capability_type: CapabilityKind, item: dict[str, Any]) -> str:
    if capability_type != "tools":
        return "read"
    annotations = item.get("annotations") if isinstance(item.get("annotations"), dict) else {}
    if annotations.get("destructiveHint") is True:
        return "delete" if DESTRUCTIVE_RE.search(text) else "write"
    if annotations.get("readOnlyHint") is True:
        return "read"
    if DESTRUCTIVE_RE.search(text):
        return "delete"
    if EXECUTE_RE.search(text):
        return "execute"
    if CRITICAL_RE.search(text):
        return "admin"
    if WRITE_RE.search(text):
        return "write"
    return "read"


def _infer_risk(text: str, access: str) -> str:
    if access == "read":
        return "medium" if CONFIDENTIAL_RE.search(text) else "low"
    if DESTRUCTIVE_RE.search(text) or access == "delete":
        return "critical"
    if CRITICAL_RE.search(text) or access in {"admin", "execute"}:
        return "critical"
    if WRITE_RE.search(text) or access == "write":
        return "high"
    if CONFIDENTIAL_RE.search(text):
        return "medium"
    if READ_RE.search(text):
        return "low"
    return "medium"


def _resource_type(capability: str, text: str) -> str:
    lowered = text.lower()
    if any(word in lowered for word in ["sql", "query", "postgres", "database", "db"]):
        return "database"
    if any(word in lowered for word in ["repo", "pull_request", "issue", "github"]):
        return "repository"
    if any(word in lowered for word in ["file", "path", "directory", "filesystem"]):
        return "file"
    if any(word in lowered for word in ["customer", "crm", "contact"]):
        return "customer"
    if any(word in lowered for word in ["payment", "invoice", "refund"]):
        return "payment"
    parts = re.split(r"[._:/-]+", capability)
    return next((part for part in reversed(parts) if part and not part.isdigit()), "capability")


def _searchable_text(capability: str, item: dict[str, Any]) -> str:
    return f"{capability} {item}"


def _policy_slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return slug or "capability"
