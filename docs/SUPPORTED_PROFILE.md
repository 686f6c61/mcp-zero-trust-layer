# Supported runtime profile (0.5.0)

0.5.0 adds opt-in [destination receipts](EVIDENCE.md). Their scope is cooperating `tools/call` destinations over the existing HTTP JSON/POSIX stdio transports. The protocol does not add SSE or universal effect confirmation. Enabled servers require strict enforce mode and a shared private SQLite approvals/evidence database; see the evidence guide before migration. Default off-mode retains the existing approval binding. Duplicate-key JSON and explicit NaN/infinity are rejected on protocol ingress.

MCPZT is a model-independent policy gateway, not a complete implementation of every MCP host or transport capability. Tests cover local SDK interoperability and client configuration formats; cloud providers have not been certified end to end.

## HTTP

The gateway supports Streamable HTTP POST with JSON responses, bounded request/response bodies, and explicit protocol-version validation for 2024-11-05, 2025-03-26, 2025-06-18 and 2025-11-25. GET SSE is not offered (405). An upstream SSE response is rejected explicitly, not passed through outside inspection. Server-initiated requests and unsolicited response envelopes from clients are unsupported.

Initialize creates an opaque gateway session bound to the authenticated subject/client/agent and logical server. The upstream session is private to that scope. Return the gateway `Mcp-Session-Id` on subsequent requests. Missing sessions operate statelessly and cannot reuse previous upstream state; foreign/unknown sessions return 404. Sessions expire after one hour idle, are limited to 10,000 per process, and can be closed with DELETE. Upstream 404 invalidates the gateway session. A late response cannot recreate a deleted upstream cache entry.

Session state is process-local. Run one gateway worker or provide session-affine routing; restarting a worker invalidates sessions. DELETE terminates the gateway mapping, not a promise to cancel an already-running upstream action. Clients sharing one static credential have the same principal unless trusted identity is supplied by a protected reverse proxy; use per-user JWT/OIDC identities for distinct authorization principals. Never expose trusted identity headers directly to untrusted callers.

## Stdio

The bounded stdio runtime requires POSIX pipes and supports sequential client requests and matching JSON responses. It applies one monotonic deadline across write and full response read and bounds response and inbound message sizes. Windows stdio fails explicitly. HTTP mode is not subject to that POSIX-pipe limitation.

Server-initiated requests and notifications (including progress/logging) are rejected explicitly and close the child session. They are not silently forwarded past output policy. There is no concurrent cancellation or bidirectional dispatcher. Use JSON/serial upstreams without these features; do not advertise this subset as transparent support for arbitrary MCP servers. The SDK integration suite tests a real FastMCP server and verifies the rejection of interleaved progress.

## Approvals and audit

Approvals apply to tools/call, resources/read and prompts/get. A require_approval decision on other methods fails closed instead of forwarding without review. No generic approval/retry protocol is advertised for arbitrary extensions. Provider-native approval dialogs do not substitute for MCPZT approval retries.

Approvals bind identity, method/capability, logical server and arguments plus a digest of the full forwarded params and configured server/policies/adapter. Old approvals without that binding cannot authorize a 0.4.0 pipeline call: request a new approval after upgrading. Changing these configuration values invalidates pending approvals. Runtime environment-secret rotation and remote OPA policy contents are not attested by that configuration digest.

Strict audit durably writes a dispatch intent before forwarding and records a correlated response/unknown outcome afterwards. An outcome-write failure cannot roll back the upstream action. Response received is not proof of external side-effect completion; timeouts can leave completion unknown. Do not automatically retry non-idempotent actions on transport or audit errors.

Approval IDs, argument hashes, request bindings, direction and correlation IDs link gateway events without logging raw secret arguments. Hash/HMAC chains provide tamper evidence under their stated key/storage trust assumptions, not independent public-key receipts or proof of execution at the destination. Completeness needs retained checkpoints/external anchors; a valid chain alone cannot establish that no suffix was removed.

File audit writers flush under the lock; strict mode also fsyncs. stdout chains have one logger-instance/process boundary and must not be merged as one chain across processes/restarts. File audit/JSON approval concurrency requires POSIX file locking; use SQLite approval storage and a supported deployment rather than assume the Windows fallback provides multiprocess exclusion.

## Validation boundaries

See [VALIDATOR_LIMITS.md](VALIDATOR_LIMITS.md). SQL screening is a conservative subset and does not replace read-only database permissions. Path/URL checks also cannot control a remote tool's filesystem, DNS resolution or subsequent redirects; scope upstream credentials and network access accordingly.
