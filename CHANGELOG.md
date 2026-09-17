# Changelog

All notable changes to MCP Zero Trust Layer will be documented here.

The project follows SemVer during the `0.x` line with the caveat that minor versions may still change configuration shape before `1.0`.

## 0.6.0 - 2026-09-17

### Fixed

- Repository examples now explicitly allow MCP initialization/ping without authorizing similarly named tools. The filesystem example uses actual tool names from a pinned official peer and constrains writes before approval; its documented launch directory matches validator roots.
- OIDC CRM redaction no longer grants inbound access to users outside the support group. CRM redaction applies even when a sensitive API key is returned without an email field.
- Published multi-MCP YAML is exercised directly by integration tests. Generated HTTP demos perform the MCP handshake and assert outcomes; generated ledger configs are tested end to end through the stdio gateway with the real MCP SDK.

### Added

- Read-only external corroboration with a bounded Stripe test-mode refund-status adapter. Configured account, tenant, destination, tool, receipt scope, request preimage and correlation metadata are checked before a result can be corroborated. No business write, redirect, automatic retry or receipt-selected endpoint.
- V2 export envelopes retain original v1 signed evidence and append separately signed observer reports. Explicit unknown/pending/contradicted/corroborated results, timestamps and trust assumptions; historical changes never rewrite the destination receipt. Transactional append prevents concurrent history forks.
- Operator `evidence check` and `check-demo`, offline observer verification and v2 schemas. The adversarial demo includes timeout recovery, a signed lie, subsequent failure, mismatched amounts, pending and missing source records.
- Regression cases, real local HTTP tests and an opt-in read-only Stripe sandbox test. A skipped sandbox test is not a live-provider certification.

### Changed

- Export defaults to v2; use `--version 1` for older verifiers, deliberately omitting external observations. The v1 wire format, signatures and verifier support are retained. Show includes external history when the observer trust file is supplied.
- Verifier output explicitly identifies destination-attested effects and absent original gateway observations. Offline checks authenticate observer statements, never claim provider signatures, current external state, administrative independence or complete history.

### Release verification

- CI validates public documentation packaging and excludes internal plans/audits. Post-publication checks compare PyPI artifact bytes with the approved build and run v2 evidence verification from PyPI and the exact published GHCR image.

### Limits

The adapter corroborates provider-reported refund status in test mode, not settlement, causation or global execution uniqueness. Provider metadata can be changed by authorized actors. Observer timestamps are not independently trusted; suffix truncation needs external checkpoints to detect. See `docs/EXTERNAL_CHECKS.md`.

## 0.5.0 - 2026-09-17

### Added

- Experimental opt-in destination receipts: JCS/SHA-256 commitments, separate Ed25519 gateway and destination signatures, strict schemas, and pinned role/tenant/audience/effect-scope trust.
- Offline evidence verification with explicit claim and content-check results; local operator show/export/reconcile/schema commands. Bundles never auto-trust embedded keys or fetch remote verification URLs.
- Durable SQLite operations, atomic approval consumption/reservation, persistent idempotency scope across signing-key rotation, and an at-least-once audit outbox. Timeouts remain unknown; reconciliation never repeats a business operation. Pending receipts can advance monotonically; conflicting terminal evidence blocks export.
- A real stdio refund-ledger demo with separate keys and transactional receipt material. Its effect is a local SQLite row, not a payment-provider operation.
- Adversarial and transport tests covering actual process death, concurrent repetition, content substitution, output filtering, offline schema verification and MCP SDK metadata interoperability.

### Changed

- Reject duplicate JSON keys and explicit nonfinite constants at protocol ingress. Evidence additionally requires the documented bounded JCS numeric/Unicode profile.
- Evidence is off by default. Enabled servers require enforce mode, strict audit, a cooperating destination and the same private SQLite database for approvals and evidence. Earlier approvals must be recreated when enabling the profile.
- Internal plans and audit working material are excluded from Git tracking, packages and Docker build context; previously published history is unchanged.

### Limits

Destination signatures attest statements under configured trust. They do not prove honesty, global exactly-once execution, independent timestamps, complete logs or effects at unintegrated external systems. The full contract and migration instructions are in `docs/EVIDENCE.md`.

## 0.4.0 - 2026-09-16

### Fixed

- Enforce explicit external policy denials without relying on an optional policy ID. Unsupported approval methods fail closed. JWT authorization attributes no longer fall back to untrusted caller headers.
- Bind opaque HTTP sessions to authenticated identities and servers, isolate stateless calls, expire/close mappings, and reject malformed or unsolicited JSON-RPC messages.
- Serialize SQLite review/consume transitions, preserve reviewer evidence and authenticate approval reads. Approval UI decisions now use audit and notifications.
- Persist strict audit intent before dispatch, record correlated outcomes including unknown completion, flush file writes while locked, and generate valid per-instance stdout chains.
- Bound stdio writes/reads by a complete-frame deadline and size limits; correlate response IDs and explicitly reject unsupported server messages. Paginate discovery and validate negotiated versions.
- Correct SQL literal/comment parsing, recipient/domain validation and nested input allowlists. SQL is deliberately conservative and still requires read-only upstream database credentials.
- Preserve supported imported client security settings; reject options that cannot safely be transferred rather than silently dropping them.

### Added

- Native VS Code/Cursor/Gemini HTTP config and Grok Build/Codex TOML, environment-backed credential references, and a dated provider compatibility guide.
- Full approval request/config binding and audit approval IDs, argument hashes and direction. Existing pre-0.4 approvals must be recreated.
- Regression tests for concurrency, fail-closed behavior, session isolation, parser boundaries and real MCP SDK interoperability. Release publication now uses the same Python 3.11–3.14 lint/type/coverage gates as CI and an isolated wheel smoke test.
- Updated constrained cryptography dependency to 50.0.0.

### Supported profile

HTTP is JSON POST, not SSE passthrough. Stdio is serial POSIX without server-initiated messages or concurrent cancellation. Session state is process-local. Audit proves gateway evidence under its trust assumptions, not independent downstream execution. See `docs/SUPPORTED_PROFILE.md` for migration and limits; cloud-provider calls have not been certified by these local tests.

## 0.3.0 - 2026-07-21

This release is a security-hardening pass with full remediation of an internal audit, plus a large test and typing investment. Several changes affect behavior of approvals and the approval UI; review the Security section before upgrading a live deployment.

### Added

- Added `output.redact_patterns` for value-level output redaction. Regular expressions are applied to string values at any depth, so secrets and PII embedded inside MCP tool-result text (for example an email inside `content[].text`) can be redacted where there is no discrete field to target.
- Added `audit.hmac_key` and `audit.hmac_key_env` for a keyed audit hash chain. When set, each event hash is an HMAC-SHA256 so an attacker with write access to the log cannot recompute a valid chain after tampering. `mcpzt audit verify` uses the configured key automatically.
- Added a monotonic `sequence` number to audit events to help detect gaps.
- Added `approvals.require_separation_of_duties` (default `true`): the identity that triggered a call cannot approve its own request.
- Added `mypy` type checking as a required CI gate, with `types-PyYAML` and a project mypy configuration.

### Changed

- Approvals are now single use. A valid retry is executed and the approval is atomically marked `consumed` in the same locked step; the same `approval_id` can no longer be replayed within its TTL.
- The approval UI (`mcpzt approve serve`) now authenticates every decision through the project `auth` configuration and derives `decided_by` from the authenticated identity instead of the request body.
- Approval status transitions are validated: terminal decisions (`denied`, `expired`, `consumed`) are immutable and cannot be flipped back to `approved`.
- The approval binding now includes `method` in addition to server, capability, identity and argument hash.
- The HTTP runtime offloads the synchronous pipeline to a worker thread so a slow upstream no longer stalls the event loop for other requests.
- Upstream MCP sessions are cached per downstream session key instead of per server, so sessions are not shared across distinct downstream clients, and the cache is guarded by a lock.
- Hardened ruff configuration (import sorting, bugbear, pyupgrade, comprehension and simplification rules) and enforced 100% coverage in CI with `--cov-fail-under=100`.
- Retyped the policy engine to use `CapabilityMetadata | None` and `Identity` instead of `object`, and resolved typing issues across the package.
- `mcpzt demo` now selects free host ports for the fake upstream and gateway instead of hard-coding `3001`/`8765`, the fake upstream fails loudly if it cannot bind, and the runner polls health instead of sleeping. This avoids the demo silently colliding with an already-listening service.

### Security

- Hardened the `sql_read_only` validator against parser-differential bypasses: it now rejects stacked statements, MySQL executable comments (`/*! ... */`), a broader destructive-keyword list, and host-reaching functions such as `load_extension`, `COPY ... TO PROGRAM` and `ATTACH`.
- Made the `filesystem_path` validator fail safer: broader sensitive-path defaults (`~/.ssh`, `~/.aws`, `/proc`, `/sys`, `/root`) and case-insensitive comparison so `/ETC` is caught on case-insensitive filesystems.
- Hardened URL/SSRF checks: decimal, hex and octal IP encodings are normalized and blocked, and reserved, multicast and CGNAT ranges are treated as private.
- Validators now fail closed on unexpected errors, DNS resolution has a timeout, and invalid regex patterns no longer raise.
- The audit log is written with `0600` permissions and appended under an exclusive lock so concurrent writers cannot fork the hash chain.
- Broadened audit and approval redaction to cover more key names and secret-shaped values (`AKIA` access keys, JWTs, PEM private keys, base64 bearer tokens).
- `input` allowed-fields validation is now recursive, so an allowed parent no longer permits arbitrary nested keys.
- Approval webhook delivery failures are always logged to stderr, so an alerting-channel outage is never silent.
- Capability-condition evaluation and stdio upstream reads are bounded, avoiding hangs on a stuck upstream.

### Tests

- Raised test coverage to 100% (498 tests) and enforced it in CI.
- Added regression coverage for approval single-use replay, approval UI authentication and separation of duties, the SQL and filesystem validator bypasses, keyed audit chains, value-pattern output redaction and recursive input allowlists.

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
