# Production Guide

This guide describes how to run MCP Zero Trust Layer around real MCP servers. It is public operational documentation, so it focuses on deployment posture, safety checks and day-two operations rather than internal build planning.

MCPZT should be treated as an enforcement point. It is not a replacement for least-privilege upstream credentials, private networking, source-system authorization or good incident response. The secure production shape is layered: clients authenticate to MCPZT, MCPZT enforces MCP-aware policy, upstream servers stay private, and the underlying systems still enforce their own permissions.

## Production Goal

The goal is to make every MCP interaction answerable. For each request, an operator should be able to say who or what called MCPZT, which logical MCP server was targeted, which tool/resource/prompt was requested, which policy matched, whether validators passed, whether human approval was required, whether upstream was called, and whether output was redacted or blocked.

That is the difference between "an agent has access to tools" and "an organization can govern agent-to-tool access".

## Baseline Config

Start production configs from a conservative baseline.

```yaml
project:
  name: mcpzt-prod
  environment: production

runtime:
  mode: proxy
  default_decision: deny
  dry_run: false
  public_base_url: https://mcpzt.example
  trusted_hosts:
    - mcpzt.example
  allowed_origins:
    - https://your-mcp-client.example
  max_request_bytes: 1048576

auth:
  mode: oidc
  issuer: https://issuer.example
  audience: mcpzt
  required_scopes:
    - mcp:read

servers:
  - name: github
    transport: http
    upstream: https://github-mcp.internal/mcp
    max_response_bytes: 10485760

audit:
  destination: file
  path: /var/log/mcpzt/audit.jsonl
  strict: true
  hash_chain: true

approvals:
  path: /var/lib/mcpzt/approvals.json
  default_ttl_seconds: 900

metrics:
  enabled: true
  path: /metrics
```

This baseline is intentionally strict. `default_decision: deny` means new or unmapped capabilities do not execute accidentally. `dry_run: false` means policy is enforced, not merely logged. `public_base_url` and `trusted_hosts` make externally visible URLs and host validation explicit. `allowed_origins` protects browser-reachable deployments from unexpected origins. OIDC gives policies a real identity source. Audit writes fail closed when `audit.strict: true`.

Production config validation rejects several unsafe combinations by default, including fail-open default allow, production dry run, missing auth, and missing public base or trusted host controls unless an explicit production override is set.

## Deployment Shapes

MCPZT can be deployed in more than one production shape. The right shape depends on how your MCP servers run today.

For a local HTTP proxy, the real MCP server already speaks HTTP and MCPZT listens on another local port. The client points to MCPZT instead of the upstream. This is useful for developer machines and small internal services.

```bash
mcpzt run --config /etc/mcpzt/mcpzt.yaml --host 127.0.0.1 --port 8765
```

For an internal gateway, one MCPZT instance protects several HTTP MCP servers. Clients call routes such as `/mcp/github`, `/mcp/postgres` and `/mcp/crm`. Upstream MCP servers stay on private DNS, a private subnet, localhost, or another network segment that clients cannot reach directly.

For a sidecar deployment, MCPZT and the upstream MCP server run in the same pod, container group or host. The upstream binds to localhost, while MCPZT is the only process exposed to clients. This is often the simplest high-control shape when one team owns one MCP server.

For command-based MCP servers, use stdio mode.

```bash
mcpzt wrap --config /etc/mcpzt/mcpzt.yaml --server filesystem
```

In stdio mode, never write audit logs to stdout. Stdout is reserved for MCP protocol messages. Use file audit or stderr.

The repository also ships deployment recipes under `deploy/`. `deploy/docker-compose.prod.yaml` is useful for a single-node or small internal deployment where local persistent state is acceptable. `deploy/helm` is a Kubernetes starting point for a sidecar or gateway shape. The Helm values default to one replica because approvals and audit state are file-backed in this release. Horizontal scale should wait until the approval store and audit destination are backed by shared infrastructure with correct locking and retention semantics.

## HTTP Security Posture

Terminate TLS at a trusted reverse proxy or load balancer unless MCPZT itself is running behind a platform that handles TLS. Forward only the MCP endpoint and the health endpoint you intentionally expose. Keep upstream MCP endpoints private so clients cannot bypass MCPZT.

The HTTP app exposes `GET /healthz` for simple health checks. Production disables FastAPI `/docs`, `/redoc` and `/openapi.json` automatically.

The MCP specification's Streamable HTTP guidance calls out three security expectations that matter in practice: validate `Origin` headers, bind local servers to localhost when running locally, and use proper authentication. MCPZT gives you controls for all three. Use `runtime.allowed_origins` for browser-reachable deployments, bind local runs to `127.0.0.1`, and configure `auth` for anything beyond isolated development.

Set byte limits deliberately. `runtime.max_request_bytes` limits inbound client bodies. `servers[].max_response_bytes` limits upstream responses. These limits protect MCPZT from oversized payloads on both sides of the trust boundary.

## Authentication And Identity

Use `oidc` or `jwt` for team and production deployments. They let policies match stable identity fields such as subject, client ID, agent ID, groups, roles and scopes. Static tokens and API keys are useful for local development or simple internal gateways, but they do not carry rich identity by themselves.

For static token or API key modes, MCPZT ignores caller-supplied `x-mcpzt-*` identity headers by default. Only set `auth.trust_identity_headers: true` behind a trusted gateway that strips inbound spoofed headers and injects trusted identity headers.

Prefer environment-backed secrets.

```yaml
auth:
  mode: api_key
  header: x-api-key
  token_env: MCPZT_API_KEY
```

JWT and OIDC production configs should set issuer and audience.

```yaml
auth:
  mode: oidc
  issuer: https://issuer.example
  audience: mcpzt
  jwks_url: https://issuer.example/.well-known/jwks.json
  required_scopes:
    - mcp:read
```

Required scopes are recommended. They distinguish a token that is valid in general from a token intended to call MCPZT.

## Client Credentials And Upstream Credentials

Client credentials and upstream credentials are separate trust boundaries. MCPZT authenticates incoming clients through `auth`. It does not forward arbitrary incoming `Authorization` headers to upstream MCP servers.

If an HTTP upstream needs a credential, configure it explicitly.

```yaml
servers:
  - name: github
    transport: http
    upstream: https://github-mcp.internal/mcp
    upstream_headers:
      Authorization: Bearer ${GITHUB_MCP_TOKEN}
      X-API-Key: env:GITHUB_MCP_API_KEY
```

Use `auth.token_env`, `env:VARIABLE_NAME` or `${VARIABLE_NAME}` for portable secret references. Inline secrets are acceptable only for local throwaway tests. `mcpzt doctor --config mcpzt.yaml` checks referenced environment variables and fails when required secrets are missing.

File and external secret-manager references are also supported. `file:/run/secrets/name` works well with mounted Docker or Kubernetes secrets. `op://...`, `aws-sm://...` and `vault://...` integrate with the 1Password, AWS and Vault CLIs. MCPZT resolves these values at runtime and does not print them. `doctor` checks that mounted files exist and that the required external CLI is installed.

```yaml
auth:
  mode: api_key
  header: x-api-key
  token: file:/run/secrets/mcpzt-api-key

servers:
  - name: crm
    transport: http
    upstream: https://crm-mcp.internal/mcp
    upstream_headers:
      Authorization: Bearer vault://secret/data/mcp/crm#token
```

## Policy Design

Production policies should start with default deny and explicit allow rules. A broad allow policy is easier to write, but a narrow allow policy is easier to defend during incident review.

Use capability mappings to attach security meaning to raw MCP names. A raw tool name such as `github.merge_pull_request` becomes more useful when mapped to `action: code.merge`, `risk: critical`, `access: write` and `resource_type: repository`. Policies can then match semantic intent instead of only string names.

Use deny or hide policies for capabilities that should never be used in the current project. Use `require_approval` for capabilities that are legitimate but too sensitive for automatic execution. Use validators when risk depends on arguments. Use output policies when a safe request can still return sensitive data.

Use `input` blocks for simple parameter contracts that should be obvious during review. This is where you define allowed fields, required fields, forbidden fields, allowed values and maximum field sizes for one tool. It keeps common argument constraints close to the policy they protect.

Examples of production-grade intent:

```yaml
policies:
  - id: deny-repository-delete
    effect: deny
    match:
      server: github
      capability: github.delete_repository

  - id: main-branch-merge-needs-approval
    effect: require_approval
    match:
      server: github
      capability: github.merge_pull_request
    when:
      args.branch:
        equals: main

  - id: allow-readonly-sql
    effect: allow
    match:
      server: postgres
      action: db.read
    validators:
      - name: sql_read_only
        options:
          query_arg: query

  - id: safe-issue-search-shape
    effect: allow
    match:
      server: github
      capability: github.search_issues
    input:
      allowed_fields:
        - query
        - limit
      required_fields:
        - query
      max_field_bytes:
        query: 512
```

The database example should still use read-only database credentials upstream. MCPZT validation catches unsafe requests before upstream, but source-system permissions should also limit blast radius.

When a production decision does not match expectations, use `mcpzt policy explain`. It prints the normalized context, mapped metadata, per-policy match failures and the selected decision. That is safer than weakening policy while debugging because it shows exactly which match field or condition failed.

```bash
mcpzt policy explain \
  --config /etc/mcpzt/mcpzt.yaml \
  --server github \
  --method tools/call \
  --capability github.merge_pull_request \
  --arguments '{"branch":"main"}'
```

External policy evaluation is possible through the OPA adapter. In that mode, MCPZT posts the normalized context and mapped metadata to an OPA endpoint and consumes a decision result. Use this only when you already operate OPA well; the built-in engine is simpler to audit for most first deployments.

```yaml
policy_engine:
  adapter: opa
  endpoint: http://opa.openpolicyagent.svc.cluster.local/v1/data/mcpzt/decision
  fail_closed: true
```

## Rollout Pattern

Start in a development environment with `dry_run: true` while you learn what the upstream exposes. Run discovery, map capabilities, add deny and allow rules, and use `mcpzt policy test` for representative requests.

```bash
mcpzt discover --server github --config mcpzt.yaml
mcpzt policy test \
  --config mcpzt.yaml \
  --server github \
  --method tools/call \
  --capability github.search_issues
```

Before switching to enforcement, run:

```bash
mcpzt config validate --config mcpzt.yaml
mcpzt doctor --config mcpzt.yaml
python -m pytest
```

Move from dry run to enforcement only after audit output matches expectations. Then move upstream MCP servers behind private network controls so clients cannot bypass MCPZT.

Before merging a capability change, run the deterministic scanner. It catches missing metadata, suspicious prompt-like text in descriptions or schemas, and dangerous-looking tools that are directly allowed without approval. Use it as a CI gate for snapshots, not as a substitute for human policy review.

```bash
mcpzt scan --config mcpzt.yaml --snapshot .mcpzt-capabilities/github.json
```

## Auditing And Monitoring

Audit events are JSONL. Secret-like keys and bearer-style values are redacted recursively before write. Store audit logs on protected storage and keep them out of source control.

```bash
mcpzt audit tail --config /etc/mcpzt/mcpzt.yaml
```

With `audit.hash_chain: true`, each event carries `previous_event_hash` and `event_hash`. This gives operators a simple tamper-evidence check for local JSONL audit files. It does not replace append-only storage or centralized logging, but it makes reorder, edit and partial corruption easier to detect.

```bash
mcpzt audit verify --config /etc/mcpzt/mcpzt.yaml
```

For production, ship audit JSONL to the existing log pipeline. Monitor at least these event classes: denied requests, validator failures, approval-required decisions, approved retries, output redactions, output blocks, upstream errors and audit write failures.

Operationally useful questions should be answerable from audit:

Which identity called which MCP server? Which policy allowed or denied the request? Did upstream receive the request? Was approval required? Was output modified? Did a validator stop a dangerous argument before side effects?

Set `audit.strict: true` in regulated or sensitive environments. If the audit destination is unavailable, failing closed is usually safer than allowing unlogged tool execution.

When metrics are enabled, MCPZT exposes Prometheus-format counters at `metrics.path`, which defaults to `/metrics`. The counter labels include server, method, decision and policy ID. They intentionally do not include arguments or output data. Alert on unusual deny spikes, approval spikes, validator failures and unexpected default decisions.

## Approvals

Approvals are for actions that are allowed in principle but should not execute automatically. A policy with `effect: require_approval` creates the request. MCPZT does not create approvals from hidden heuristics.

```bash
mcpzt approve list --config /etc/mcpzt/mcpzt.yaml
mcpzt approve show <approval-id> --config /etc/mcpzt/mcpzt.yaml
mcpzt approve allow <approval-id> \
  --config /etc/mcpzt/mcpzt.yaml \
  --by ana@example.com \
  --comment "reviewed release PR"
```

Approved retries are bound to the original identity, server, capability, policy and argument hash. If the retry changes the arguments, the previous approval is invalid. The approval ID is stripped before the request reaches upstream.

The local JSON approval store uses file locking and atomic replace. For larger multi-instance deployments, keep the approval path on storage with correct locking semantics or plan a database-backed approval backend before scaling horizontally.

Approval webhooks can notify a separate review experience or operations workflow. They receive redacted approval data for creation and decision events. Keep webhook endpoints internal, authenticate them at the network or gateway layer, and decide deliberately whether webhook failure should be best-effort or strict.

```yaml
approvals:
  path: /var/lib/mcpzt/approvals.json
  webhook_url: env:MCPZT_APPROVAL_WEBHOOK_URL
  webhook_strict: false
```

## Network And URL Validators

The URL validator blocks localhost, private IPs, link-local addresses and cloud metadata hosts by default. It also resolves hostnames before allowing them. This reduces SSRF risk for URL-fetching MCP tools.

Treat this as a guardrail, not a complete egress strategy. Production deployments should also restrict outbound network access at the host, container, VPC, service mesh or proxy layer.

## Capability Drift

MCP servers can change after package upgrades, config changes or upstream feature releases. Capability drift is a security event because a new tool may create a new path to data or side effects.

Use discovery snapshots and diffs.

```bash
mcpzt discover --server github --config /etc/mcpzt/mcpzt.yaml
mcpzt diff --server github --config /etc/mcpzt/mcpzt.yaml
mcpzt scan --config /etc/mcpzt/mcpzt.yaml --snapshot .mcpzt-capabilities/github.json
```

Review new capabilities before mapping them to allowed actions. Unknown capabilities should remain denied under `runtime.default_decision: deny`.

## Incident Response

If a suspicious action occurs, start with audit. Find the correlation ID, identity, server, capability, policy ID, decision, validator results and `upstream_called` state. If `upstream_called` is false, MCPZT stopped the request before the real server. If it is true, investigate the upstream service and source system as well.

For credential concerns, rotate both client-facing credentials and upstream credentials. They are separate by design and should be rotated independently. If an approval decision is suspicious, deny pending approvals, preserve the approval store and audit logs, and review whether the approval policy was too broad.

For capability drift concerns, run `mcpzt diff` against each affected server and temporarily add deny or hide policies for newly exposed high-risk tools.

## Production Preflight

Before exposing MCPZT to real users, confirm that the following are true.

The config validates in production mode. `mcpzt doctor` has no failures. Authentication is enabled. OIDC/JWT configs have issuer and audience. `runtime.default_decision` is deny. `runtime.dry_run` is false. Host and origin controls are set where relevant. Request and response byte limits are conservative. Upstream MCP servers are private. Audit logs are protected, strict and hash-chain verification has been tested. Metrics are scraped or intentionally disabled. Approval storage is protected. Approval webhooks, if configured, have been tested. Capability snapshots exist for important servers. `mcpzt scan` has been run on those snapshots. Representative allow, deny, validator, output and approval cases have been tested.

## Standards Notes

MCPZT follows the MCP Streamable HTTP shape for JSON POST responses. In this release, GET streams are not offered and return HTTP 405. Request-scoped upstream SSE passthrough is intentionally outside the first release.

Public references:

- MCP Streamable HTTP transport: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- MCP authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- PyPA packaging guide: https://packaging.python.org/en/latest/guides/writing-pyproject-toml/
- PyPI Trusted Publishing: https://docs.pypi.org/trusted-publishers/
