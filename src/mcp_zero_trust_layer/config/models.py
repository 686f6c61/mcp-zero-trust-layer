from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


Environment = Literal["development", "local", "staging", "production", "test"]
Effect = Literal["allow", "deny", "hide", "require_approval", "redact", "limit", "transform", "log"]
Risk = Literal["low", "medium", "high", "critical"]


class ProjectConfig(BaseModel):
    name: str = "mcp-zero-trust-project"
    environment: Environment = "development"


class RuntimeConfig(BaseModel):
    mode: Literal["proxy", "stdio", "gateway", "middleware"] = "proxy"
    default_decision: Literal["allow", "deny"] = "deny"
    dry_run: bool = False
    allow_dry_run_in_production: bool = False
    allow_auth_none_in_production: bool = False
    allowed_origins: list[str] = Field(default_factory=list)
    trusted_hosts: list[str] = Field(default_factory=list)
    public_base_url: str | None = None
    max_request_bytes: int = 1_048_576


class AuthConfig(BaseModel):
    mode: Literal["none", "static_token", "api_key", "jwt", "oidc"] = "none"
    token: str | None = None
    token_env: str | None = None
    header: str = "authorization"
    trust_identity_headers: bool = False
    issuer: str | None = None
    audience: str | None = None
    jwks_url: str | None = None
    algorithms: list[str] = Field(default_factory=lambda: ["RS256"])
    authorization_servers: list[str] = Field(default_factory=list)
    required_scopes: list[str] = Field(default_factory=list)
    subject_claim: str = "sub"
    email_claim: str = "email"
    scopes_claim: str = "scope"
    groups_claim: str = "groups"
    roles_claim: str = "roles"
    client_id_claim: str = "client_id"
    agent_id_claim: str = "agent_id"

    @model_validator(mode="after")
    def validate_token_sources(self) -> "AuthConfig":
        if self.token and self.token_env:
            raise ValueError("auth.token and auth.token_env are mutually exclusive")
        return self


class ServerConfig(BaseModel):
    name: str
    transport: Literal["http", "stdio"]
    upstream: str | None = None
    upstream_headers: dict[str, str] = Field(default_factory=dict)
    command: list[str] = Field(default_factory=list)
    timeout: float = 30.0
    max_response_bytes: int = 10_485_760

    @model_validator(mode="after")
    def validate_target(self) -> "ServerConfig":
        if self.transport == "http" and not self.upstream:
            raise ValueError(f"server {self.name!r} with transport http requires upstream")
        if self.transport == "stdio" and not self.command:
            raise ValueError(f"server {self.name!r} with transport stdio requires command")
        return self


class CapabilityMetadata(BaseModel):
    action: str | None = None
    risk: Risk | None = None
    access: Literal["read", "write", "delete", "execute", "admin"] | None = None
    resource_type: str | None = None
    tags: list[str] = Field(default_factory=list)
    data_classification: str | None = None
    owner: str | None = None


class ServerCapabilityMappings(BaseModel):
    tools: dict[str, CapabilityMetadata] = Field(default_factory=dict)
    resources: dict[str, CapabilityMetadata] = Field(default_factory=dict)
    prompts: dict[str, CapabilityMetadata] = Field(default_factory=dict)


class PolicyMatch(BaseModel):
    server: str | None = None
    method: str | None = None
    capability_type: Literal["tool", "resource", "prompt", "method"] | None = None
    capability: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    action: str | None = None
    risk: Risk | None = None
    access: str | None = None
    resource_type: str | None = None
    tag: str | None = None
    tags: list[str] = Field(default_factory=list)
    data_classification: str | None = None
    environment: str | None = None
    user: str | None = None
    group: str | None = None
    role: str | None = None
    client_id: str | None = None
    agent_id: str | None = None


class OutputPolicy(BaseModel):
    redact_fields: list[str] = Field(default_factory=list)
    deny_if_matches: list[str] = Field(default_factory=list)
    max_bytes: int | None = None
    include_fields: list[str] = Field(default_factory=list)


class InputPolicy(BaseModel):
    allowed_fields: list[str] = Field(default_factory=list)
    required_fields: list[str] = Field(default_factory=list)
    forbidden_fields: list[str] = Field(default_factory=list)
    allowed_values: dict[str, list[Any]] = Field(default_factory=dict)
    max_field_bytes: dict[str, int] = Field(default_factory=dict)
    max_list_items: dict[str, int] = Field(default_factory=dict)


class ValidatorConfig(BaseModel):
    name: str
    options: dict[str, Any] = Field(default_factory=dict)


class PolicyConfig(BaseModel):
    id: str
    effect: Effect
    match: PolicyMatch = Field(default_factory=PolicyMatch)
    when: dict[str, Any] = Field(default_factory=dict)
    input: InputPolicy | None = None
    validators: list[ValidatorConfig] = Field(default_factory=list)
    output: OutputPolicy | None = None
    reason: str | None = None

    @field_validator("validators", mode="before")
    @classmethod
    def normalize_validators(cls, value: Any) -> Any:
        if value is None:
            return []
        normalized = []
        for item in value:
            if isinstance(item, str):
                normalized.append({"name": item})
            else:
                normalized.append(item)
        return normalized


class AuditConfig(BaseModel):
    destination: Literal["file", "stdout"] = "file"
    path: str = "./mcpzt-audit.jsonl"
    strict: bool = True
    hash_chain: bool = True


class ApprovalsConfig(BaseModel):
    path: str = "./mcpzt-approvals.json"
    default_ttl_seconds: int = 900
    webhook_url: str | None = None
    webhook_strict: bool = False
    webhook_timeout: float = 5.0


class MetricsConfig(BaseModel):
    enabled: bool = True
    path: str = "/metrics"


class PolicyEngineConfig(BaseModel):
    adapter: Literal["builtin", "opa"] = "builtin"
    endpoint: str | None = None
    timeout: float = 5.0
    fail_closed: bool = True


class MCPZTConfig(BaseModel):
    config_base_dir: str | None = Field(default=None, exclude=True)
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    servers: list[ServerConfig]
    capability_mappings: dict[str, ServerCapabilityMappings] = Field(default_factory=dict)
    policies: list[PolicyConfig] = Field(default_factory=list)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    approvals: ApprovalsConfig = Field(default_factory=ApprovalsConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
    policy_engine: PolicyEngineConfig = Field(default_factory=PolicyEngineConfig)

    @model_validator(mode="after")
    def validate_config(self) -> "MCPZTConfig":
        self._validate_unique_names()
        self._validate_production_settings()
        self._validate_policy_engine_settings()
        return self

    def _validate_unique_names(self) -> None:
        server_names = [server.name for server in self.servers]
        if len(server_names) != len(set(server_names)):
            raise ValueError("server names must be unique")

        policy_ids = [policy.id for policy in self.policies]
        if len(policy_ids) != len(set(policy_ids)):
            raise ValueError("policy ids must be unique")

    def _validate_production_settings(self) -> None:
        if self.project.environment != "production":
            return
        if self.runtime.default_decision != "deny":
            raise ValueError("production requires runtime.default_decision: deny")
        if self.runtime.dry_run and not self.runtime.allow_dry_run_in_production:
            raise ValueError(
                "production cannot use runtime.dry_run: true unless "
                "runtime.allow_dry_run_in_production is true"
            )
        if self.auth.mode == "none" and not self.runtime.allow_auth_none_in_production:
            raise ValueError(
                "production cannot use auth.mode: none unless "
                "runtime.allow_auth_none_in_production is true"
            )
        if not self.runtime.public_base_url and not self.runtime.trusted_hosts:
            raise ValueError("production requires runtime.public_base_url or runtime.trusted_hosts")
        self._validate_production_jwt_claims()

    def _validate_production_jwt_claims(self) -> None:
        if self.auth.mode not in {"jwt", "oidc"}:
            return
        if not self.auth.issuer:
            raise ValueError(f"production {self.auth.mode} auth requires auth.issuer")
        if not self.auth.audience:
            raise ValueError(f"production {self.auth.mode} auth requires auth.audience")

    def _validate_policy_engine_settings(self) -> None:
        if self.policy_engine.adapter == "opa" and not self.policy_engine.endpoint:
            raise ValueError("policy_engine.adapter: opa requires policy_engine.endpoint")
