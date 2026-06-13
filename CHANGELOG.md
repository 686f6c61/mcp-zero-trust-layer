# Changelog

All notable changes to MCP Zero Trust Layer will be documented here.

The project follows SemVer during the `0.x` line with the caveat that minor versions may still change configuration shape before `1.0`.

## 0.1.0 - Unreleased

### Added

- PyPI-ready Python package with `mcpzt` and `mcp-zero-trust-layer` CLI entry points.
- Versionable YAML config with validation and JSON Schema export.
- HTTP JSON proxy runtime for MCP Streamable HTTP POST requests.
- Stdio wrapper runtime with protocol-only stdout.
- Multi-MCP HTTP routing with `/mcp/{server_name}`.
- Policy engine with deny, hide, require approval, redact, limit, transform, allow and log effects.
- `mcpzt policy explain` for request-context diagnostics, matched policies and per-policy match failures.
- Native policy `input` blocks for allowed fields, required fields, forbidden fields, allowed values, max field bytes and max list items.
- Optional OPA policy adapter for external policy decisions over normalized MCPZT context.
- Exact and semantic capability matching over server, method, tool/resource/prompt, action, risk, access, tags, data classification and identity.
- Request validators for read-only SQL, filesystem paths, URLs, email, regex, required fields, forbidden fields and max field size.
- Output enforcement for redaction, deny patterns, max bytes and include-only views.
- Local approval store and approval CLI.
- Approval webhook notifications for created, approved and denied approval lifecycle events.
- Prometheus-format decision metrics exposed by the HTTP runtime.
- Capability discovery and diff commands.
- Deterministic `mcpzt scan` command for capability snapshot risk checks.
- MCP client config generation through `mcpzt client config`.
- Bundled policy packs for GitHub read-only, Postgres read-only and filesystem-safe examples.
- Multi-MCP example config covering GitHub, Postgres, filesystem and CRM use cases.
- Static token, API key, JWT and OIDC/JWKS authentication.
- Secret references with `auth.token_env`, `env:`, `${VAR}`, `file:`, `op://`, `aws-sm://` and `vault://`.
- Explicit HTTP upstream credential headers through `servers[].upstream_headers`.
- OAuth protected resource metadata endpoints for HTTP deployments.
- JSONL audit logging with recursive secret redaction, strict/non-strict write modes and hash-chain verification.
- `mcpzt doctor` for local and config diagnostics.
- Dockerfile, production Docker Compose recipe, Helm starter chart, CI workflow and PyPI Trusted Publishing workflow.

### Changed

- Reworked README into a fuller narrative guide with longer explanatory sections, fewer compact bullet lists and more context around product intent, operations, security and release workflow.
- Expanded README with request evaluation flow, copy-paste policy examples, manual HTTP examples, multi-MCP walkthrough, deployment patterns and troubleshooting.
- Added [docs/MULTI_MCP_USE_CASES.md](docs/MULTI_MCP_USE_CASES.md) to document real multi-server scenarios and their expected behavior.
- Added [examples/multi-mcp/mcpzt.yaml](examples/multi-mcp/mcpzt.yaml) as a versionable multi-MCP starter config.
- Docker builds now install with `constraints.txt` for reproducible image dependency resolution.
- Public package documentation now excludes internal construction docs, planning docs and security audit notes.
- Expanded public docs for multi-MCP usage, production deployment and PyPI release operations with fuller explanations and release safety checks.
- Expanded public docs with policy explanation, parameter contracts, secret-manager references, approval webhooks, metrics, audit verification, scanner usage and deployment recipes.

### Security

- Production config requires default deny and explicit auth unless overridden.
- Production rejects `runtime.dry_run: true` unless an explicit production override is set.
- Production requires `runtime.public_base_url` or `runtime.trusted_hosts`.
- Production JWT/OIDC requires issuer and audience.
- HTTP upstream headers are allowlisted.
- Static tokens and API keys use constant-time comparison.
- Static token and API key auth ignore caller-supplied `x-mcpzt-*` identity headers by default.
- Incoming client `Authorization` is not forwarded to upstreams unless configured explicitly as an upstream header.
- Side-effecting JSON-RPC notifications are evaluated by policy instead of being forwarded blindly.
- HTTP request bodies are bounded by `runtime.max_request_bytes`.
- HTTP upstream responses are bounded by `servers[].max_response_bytes`.
- HTTP upstream error bodies are truncated and redacted before being returned to clients.
- Output enforcement applies to JSON-RPC `error` payloads as well as `result` payloads.
- Approval store writes use file locking and atomic replace.
- Approval decisions record approver, timestamp and optional comment, and emit audit events.
- FastAPI docs, Redoc and OpenAPI routes are disabled in production.
- URL validator resolves hostnames and blocks private, loopback, link-local and cloud metadata IPs by default.
- Audit decision events include whether the upstream was called.
- Audit events can be hash-chain verified with `mcpzt audit verify`.
- Metrics avoid request arguments and output payloads to reduce monitoring data leakage.
- Filesystem validator relative roots can resolve from the loaded config directory.

### Tests

- Added full multi-MCP integration test coverage with local HTTP MCP upstreams.
- Multi-MCP tests cover capability filtering, safe routing, SQL blocking, filesystem blocking, approvals, approval stripping and CRM output redaction.
- Added tests for policy explanation, input policies, OPA adapter behavior, audit hash-chain verification, metrics exposure, client config generation and scanner findings.
- Current suite: 82 tests passing.

### Notes

- GET SSE streams are not offered in `0.1.0`; the HTTP endpoint returns 405 for GET, which is allowed for servers that do not offer an SSE stream.
- Request-scoped upstream SSE passthrough is intentionally outside this first release.
