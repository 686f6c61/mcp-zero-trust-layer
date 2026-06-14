# Changelog

All notable changes to MCP Zero Trust Layer will be documented here.

The project follows SemVer during the `0.x` line with the caveat that minor versions may still change configuration shape before `1.0`.

## 0.2.0 - 2026-06-14

### Added

- Added `mcpzt onboard` to discover one or more MCP upstreams and generate a conservative starter config with capability mappings, reviewable policies, snapshots and an onboarding report.
- Added SQLite approval storage through `approvals.backend: sqlite` while preserving the existing approval CLI and approval retry contract.
- Added `mcpzt approve serve`, a self-hosted approval review UI with human-readable approval review and JSON approval endpoints.
- Added `mcpzt audit search` for filtering JSONL audit logs by event type, server, decision, policy ID, correlation ID, approval ID and time window.
- Added `mcpzt policy coverage`, `mcpzt policy risks` and `mcpzt policy unused` for policy coverage review, risk detection and stale-policy analysis.
- Added a production-shaped OIDC gateway example with group-based policies, upstream credentials, SQLite approvals and output redaction.
- Added `mcpzt client import` to wrap existing Claude Desktop, Cursor and VS Code MCP client configs with MCPZT-generated policy and client files.
- Added real MCP discovery handshakes during capability discovery so upstreams that require `initialize` can be onboarded correctly.

### Changed

- Updated generated starter configs to make the approval backend explicit.
- Updated onboarding inference to use MCP tool annotations such as `readOnlyHint` and `destructiveHint` when classifying capabilities.
- Updated stdio upstream execution to pass configured environment variables through explicit secret references.
- Updated HTTP upstream handling to retain MCP session IDs across requests to the same logical server.
- Updated production guidance to use SQLite approvals for long-running single-instance gateways and to document the approval UI security posture.
- Expanded rollout guidance with onboarding, policy coverage analysis, audit search and approval UI workflows.
- Updated Docker Compose and Helm release defaults to the `0.2.0` image tag and aligned the Helm example with SQLite approvals.
- Extended PyPI release preflight guidance with onboarding and policy-analysis smoke checks.

### Tests

- Added coverage for SQLite approvals, approval UI review, audit search, onboarding config generation and policy analysis commands.
- Added CLI regression coverage for SQLite approval listing, audit search, policy coverage, onboarding from `--server name=url` and imported client configs.

## 0.1.3 - 2026-06-14

### Added

- Added `mcpzt demo` to generate a runnable local demo with a fake MCP upstream, policy config, demo client and shell runner.
- Added `mcpzt approve list --format json` for automation-friendly approval review.
- Added `mcpzt config lint` with table and JSON output for insecure or fragile configuration patterns.
- Added stricter doctor modes with `mcpzt doctor --strict` and `mcpzt doctor --production`.
- Added release workflow steps for official GHCR container publishing and post-publish PyPI install verification.

### Changed

- Updated public install and deployment guidance for the current `0.x` line instead of hard-coding stale point-release language.
- Updated Docker Compose and Helm defaults to use the official `ghcr.io/686f6c61/mcp-zero-trust-layer` image path.
- Clarified that `claude-code` client config output is a shell command, while `json` is the machine-readable format.
- Kept generated demo audit and approval state inside the demo directory when running `run_demo.sh`.
- Avoided creating an approval lock file when listing an empty, not-yet-created approval store.

## 0.1.2 - 2026-06-14

### Changed

- Refactored policy evaluation, request routing, capability scanning, input validation and CLI diagnostics into smaller internal units with clearer responsibilities.
- Kept policy matching and policy explanation behavior aligned by sharing the same match-failure logic.
- Improved the approval review CLI so `mcpzt approve list` prints full approval IDs that can be copied directly into `mcpzt approve allow` or `mcpzt approve deny`.
- Simplified Docker image construction while preserving the non-root runtime user.
- Added reusable static-analysis project configuration for local and CI quality gates.

### Tests

- Added regression coverage to keep approval IDs fully visible in `mcpzt approve list`.
- Current release validation suite: 85 tests passing.

### Security

- Hardened the Helm deployment defaults by disabling automatic service account token mounting for the application pod.
- Added explicit ephemeral-storage requests and limits to the Helm chart defaults.
- Made subprocess execution for stdio MCP upstreams and secret-provider CLIs explicit with `shell=False`.
- Added a timeout when reading secrets through external secret-provider CLIs so secret resolution fails closed instead of hanging indefinitely.
- Kept URL validation protections for private, loopback, link-local and cloud metadata destinations while making the validator internals easier to review.

## 0.1.1 - 2026-06-13

### Fixed

- Fixed capability discovery filtering when an allowed policy includes call-time validators or required input fields. `tools/list`, `resources/list` and `prompts/list` now use policy matching to decide visibility without running validators that need request arguments.
- Preserved call-time enforcement for the same policies: validators and `input` contracts still run for actual calls such as `tools/call`, so the fix restores discoverability without weakening runtime protection.

### Tests

- Added regression coverage for tools protected by `sql_read_only` validators and tools with `input.required_fields` so they remain visible during discovery.

## 0.1.0 - 2026-06-13

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
