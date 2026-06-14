# MCP Zero Trust Layer

MCP Zero Trust Layer, usually shortened to MCPZT, is an open-source and self-hosted security layer for MCP servers. It sits between an MCP client and one or more real MCP servers, then decides what the client can discover, call, send, receive, approve and audit.

The purpose is not to create a new MCP ecosystem or a hosted control plane. The purpose is to give developers and platform teams a practical enforcement point they can put in front of existing MCP servers without rewriting those servers.

```text
MCP client / agent
  |
  v
MCP Zero Trust Layer
  |
  |  identity
  |  policy
  |  argument validators
  |  human approvals
  |  output enforcement
  |  audit
  v
real MCP server
  |
  v
database / repository / filesystem / CRM / payment API / internal system
```

This README is the public practical entry point: what the project does, how to run it, how to configure it, and how to reason about common policy patterns. It intentionally avoids linking to internal planning material so the published package stays focused on usage, operations and security.

## The Short Version

An MCP server can expose very powerful capabilities. A tool named `search_issues` may be harmless, while a tool named `merge_pull_request`, `delete_repository`, `run_sql`, `send_email`, `read_secret` or `create_refund` may have real operational impact. If a client can connect directly to the MCP server, the client may be able to list and call more tools than the user or organization intended.

MCPZT adds a policy layer in front of that server. It can hide capabilities from `tools/list`, block calls before they reach the upstream, validate arguments, require human approval for high-risk actions, redact sensitive output, and write audit logs explaining every important decision.

The important design point is that MCPZT is not a SaaS requirement. It runs locally, in Docker, in CI, as an internal gateway, as a sidecar, or as a stdio wrapper around command-based MCP servers. Configuration is plain YAML, so it can be reviewed in pull requests and versioned with the project it protects.

## Status

Current line: `0.x` developer preview. Use `mcpzt version`, the PyPI project page or the GitHub releases page to confirm the exact installed version.

The core path is implemented. The package has a CLI, YAML config validation, HTTP proxy mode, stdio wrapper mode, multi-MCP routing, policy evaluation, policy explanation, policy coverage analysis, parameter-level controls, validators, approvals, a self-hosted approval UI, file and SQLite approval storage, output enforcement, capability discovery, onboarding config generation, deterministic scanning, searchable audit logs with hash-chain verification, Prometheus metrics, authentication modes, secret references, client config generation, examples, deployment recipes, Docker packaging and PyPI-ready build metadata.

The HTTP runtime supports MCP Streamable HTTP POST with JSON responses. GET SSE streams are not implemented in this release; the endpoint returns HTTP 405 for GET, which is allowed when a server does not offer an SSE stream. Request-scoped upstream SSE passthrough is intentionally left for a later release because streaming needs a separate security design.

Security hardening is already part of the preview. Production configs reject fail-open `dry_run` by default, require default deny, require a public base URL or trusted hosts, and require issuer/audience for JWT and OIDC. Shared-key auth does not trust caller-supplied identity headers unless explicitly configured. Request and upstream response sizes are bounded. Upstream error bodies are truncated and redacted. Output policies apply to JSON-RPC `result` and `error` payloads. Approval decisions are auditable. Production disables FastAPI docs and OpenAPI routes.

## Why This Project Exists

MCP makes it easy for agents and AI applications to reach real systems. That is the point, and it is powerful. The risk is that many MCP servers are created as local developer tools first, then later connected to systems that deserve more careful authorization. A filesystem MCP may move from reading a scratch directory to reading a repository. A database MCP may move from exploring a sample database to touching production-like data. A GitHub MCP may expose both search and merge operations.

Traditional security controls still matter. OAuth can identify a user or client. Firewalls can restrict network access. Upstream credentials can be scoped. None of that automatically answers MCP-specific questions such as "should this agent see this tool?", "is this SQL query read-only?", "does this tool call need approval?", "did a new tool appear in the upstream?", or "should this returned customer email be redacted before the model sees it?".

MCPZT is built for that missing layer. It treats every MCP interaction as something to evaluate. It understands MCP methods such as `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list` and `prompts/get`, and it maps those messages into a consistent policy context.

The result is a boring but useful control point. Boring is good here. You want a deterministic layer that can explain why it allowed a call, why it denied a call, why it created an approval, and whether the upstream server was actually contacted.

## Installation

For most users, install MCPZT from PyPI into an isolated environment. This gives you the `mcpzt` command without cloning the repository.

```bash
python -m pip install mcp-zero-trust-layer
mcpzt version
```

For one-off usage without keeping a permanent environment, use `uvx` or `pipx run`. This is a good fit when you want to initialize a config, validate a repository, generate client config or run a local wrapper from a clean install.

```bash
uvx mcp-zero-trust-layer version
pipx run mcp-zero-trust-layer version
```

For local development from this repository, create a virtual environment and install the package in editable mode.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

The CLI exposes two command names. `mcpzt` is the short name for daily use, and `mcp-zero-trust-layer` is the full package-style name.

```bash
mcpzt version
mcp-zero-trust-layer version
```

Docker is also supported. Use the published GHCR image for release deployments, or build a local image when testing changes from a checkout. The Dockerfile installs the package with `constraints.txt`, which keeps image builds reproducible while leaving PyPI dependency ranges flexible for library users.

```bash
docker run --rm ghcr.io/686f6c61/mcp-zero-trust-layer:<version> version
docker build -t mcpzt:local .
docker run --rm mcpzt:local version
```

You can validate an example config inside Docker without giving the container write access to the project.

```bash
docker run --rm \
  -v "$PWD/examples/multi-mcp:/cfg:ro" \
  mcpzt:local config validate --config /cfg/mcpzt.yaml
```

After any install path, run a small verification sequence. It proves that the CLI starts, config generation works, the schema validates and the client config generator can produce JSON without touching a real MCP server.

```bash
mcpzt init --config /tmp/mcpzt.yaml --force
mcpzt config validate --config /tmp/mcpzt.yaml
mcpzt config lint --config /tmp/mcpzt.yaml
mcpzt client config --config /tmp/mcpzt.yaml --kind json
```

If you want to see the gateway behave end to end before connecting a real MCP, generate the local demo. It creates a fake upstream MCP server, a policy file, a tiny client and a runner script. The demo shows capability filtering, an allowed call, a denied call and output redaction.

```bash
mcpzt demo --output mcpzt-demo
./mcpzt-demo/run_demo.sh
```

## How To Think About MCPZT

MCPZT is its own system, but it is normally used to protect MCP servers that already exist. You usually do not import it into the upstream MCP server or rewrite that server around MCPZT. Instead, you run MCPZT as a separate enforcement layer and point the MCP client at MCPZT instead of pointing it directly at the real server.

The simplest mental model is:

```text
MCP client / agent
  |
  v
MCP Zero Trust Layer
  |
  v
existing MCP server
```

That means MCPZT has a product identity of its own, with its own CLI, config file, audit log, approvals, metrics and deployment lifecycle. At the same time, its job is not to replace GitHub MCP, Postgres MCP, filesystem MCP, CRM MCP or any other upstream. Its job is to govern access to them.

There are three common ways to use it.

For local or development use, install MCPZT with `uvx`, `pipx`, `pip` or an editable install. This is the easiest way to create configs, test policies, inspect explanations, run discovery and wrap local stdio MCP servers.

For gateway use, run MCPZT as a service. MCP clients call routes such as `/mcp/github`, `/mcp/postgres` or `/mcp/crm`, and MCPZT forwards only allowed traffic to private upstream MCP servers. This is the shape for teams that want one control point protecting several MCPs.

For sidecar use, run MCPZT next to one MCP server, often in the same host, container group or Kubernetes pod. The real MCP server listens only on localhost or a private interface, and MCPZT is the only process exposed to clients. This is the cleanest shape when a team owns one sensitive MCP and wants policy, approval and audit around it without changing the upstream server code.

Docker is one way to run the gateway or sidecar shapes. It is not required for local CLI use, and it does not mean MCPZT must become part of the upstream MCP server image. Docker gives you a reproducible, isolated runtime for the enforcement layer.

## First Run

Start by creating a config file. The generated file is meant to be readable rather than magical. It gives you a project, runtime settings, an auth mode, one upstream server, starter capability mappings, starter policies, audit output and approval storage.

```bash
mcpzt init
```

Validate the config before running a proxy or wrapper. This catches structural errors early, and in production it also catches intentionally unsafe settings.

```bash
mcpzt config validate --config mcpzt.yaml
```

Run the linter next. Validation answers "is this config structurally valid?". Linting answers the more operational question: "does this config look too permissive, fragile or easy to misuse?". A development config with `auth.mode: none` may produce warnings; a production config should be clean under strict mode.

```bash
mcpzt config lint --config mcpzt.yaml
mcpzt config lint --strict --config mcpzt.yaml
```

The JSON Schema can be exported for editor integration, CI validation or documentation.

```bash
mcpzt config schema --output mcpzt.schema.json
```

`doctor` is the practical sanity check. It validates the config, checks configured commands, checks secret environment references, warns about weak local choices, and fails when it sees dangerous production posture. For CI or release preparation, use strict mode so warnings become a failing signal.

```bash
mcpzt doctor --config mcpzt.yaml
mcpzt doctor --strict --config mcpzt.yaml
mcpzt doctor --production --strict --config mcpzt.yaml
```

For a real MCP server, you can start with onboarding instead of writing every mapping by hand. `mcpzt onboard` discovers the upstream capabilities, infers conservative metadata from names and descriptions, writes a complete starter config, and saves discovery snapshots for review. The generated file is meant to be read and edited by humans. It is a starting point, not a promise that every inferred risk label is perfect.

```bash
mcpzt onboard \
  --server github=http://127.0.0.1:3001/mcp \
  --server crm=http://127.0.0.1:3002/mcp \
  --output mcpzt.yaml
```

If you already have a config with servers, run onboarding against that file. MCPZT will preserve the declared servers and runtime shape, then generate mappings and initial policies from the discovered capabilities.

```bash
mcpzt onboard --config existing-mcpzt.yaml --output onboarded-mcpzt.yaml
```

The onboarding policy set is deliberately cautious. Low-risk reads are allowed, high and critical capabilities require approval, destructive capabilities are hidden, SQL-like tools get a read-only validator, and confidential-looking outputs get a redaction policy. Before using the result in enforcement, run coverage and risk analysis and review the YAML in a pull request.

```bash
mcpzt policy coverage --config mcpzt.yaml
mcpzt policy risks --config mcpzt.yaml
mcpzt policy unused --config mcpzt.yaml
```

Before connecting a real MCP client, test policy decisions from the CLI. This is one of the fastest ways to understand whether a policy is matching what you think it is matching.

```bash
mcpzt policy test \
  --config examples/github-readonly/mcpzt.yaml \
  --server github \
  --method tools/call \
  --capability github.search_issues
```

When a decision is surprising, use `policy explain` instead of guessing. It prints the normalized request context, mapped capability metadata, the policies that matched, the policies that did not match, the reason each policy was discarded, and the final selected decision. This is especially useful when a semantic mapping such as `risk: critical` or an identity claim such as `group: security` is not doing what you expected.

```bash
mcpzt policy explain \
  --config examples/github-readonly/mcpzt.yaml \
  --server github \
  --method tools/call \
  --capability github.merge_pull_request \
  --arguments '{"branch":"main"}'
```

For validators, pass representative arguments. This command simulates a destructive SQL query against the Postgres example. The expected decision is `deny`, and the output includes validation errors explaining why.

```bash
mcpzt policy test \
  --config examples/postgres-readonly/mcpzt.yaml \
  --server postgres \
  --method tools/call \
  --capability postgres.query \
  --arguments '{"query":"delete from users"}'
```

Once the config behaves as expected, run MCPZT as an HTTP proxy.

```bash
mcpzt run --config examples/github-readonly/mcpzt.yaml --host 127.0.0.1 --port 8765
```

If your MCP client expects a JSON config, generate one after the proxy is reachable. The generator points each logical MCP server at MCPZT, not at the upstream. For clients that use `mcp-remote`, this keeps the client setup small while preserving MCPZT as the enforcement point.

```bash
mcpzt client config \
  --config examples/multi-mcp/mcpzt.yaml \
  --base-url http://127.0.0.1:8765 \
  --kind claude-desktop
```

Choose the output kind for the client you are configuring. `claude-desktop`, `cursor` and `vscode` produce JSON client config shapes. `claude-code` produces ready-to-run `claude mcp add` commands because that client is commonly configured from its CLI. `json` produces the raw neutral object, which is useful for scripts, tests and custom client generators.

```bash
mcpzt client config --config mcpzt.yaml --kind cursor
mcpzt client config --config mcpzt.yaml --kind vscode
mcpzt client config --config mcpzt.yaml --kind claude-code
mcpzt client config --config mcpzt.yaml --kind json
```

For command-based MCP servers, use the stdio wrapper. This mode keeps stdout reserved for MCP protocol traffic, so audit output must go to a file rather than stdout.

```bash
mcpzt wrap --config examples/filesystem-safe/mcpzt.yaml --server filesystem
```

If you already have MCP servers configured in Claude Desktop, Cursor or VS Code, you do not need to rewrite those entries by hand. Import the existing client config and let MCPZT generate two local files: an MCPZT policy config and a wrapped client config. With `--discover`, MCPZT starts the real upstream MCP servers, performs the MCP initialization handshake, lists their tools/resources/prompts, infers starter metadata and writes reviewable policies.

```bash
mcpzt client import \
  --source "$HOME/Library/Application Support/Claude/claude_desktop_config.json" \
  --mcpzt-config .mcpzt/client-import/claude/mcpzt.yaml \
  --client-output .mcpzt/client-import/claude/claude_desktop_config.mcpzt.json \
  --discover
```

For a stdio MCP server, the generated client entry keeps the original server name but changes the command so the client launches `mcpzt wrap --config ... --server ...`. MCPZT then launches the original upstream command behind the policy layer. For an HTTP MCP server, the generated client entry points at the MCPZT gateway route for that logical server.

Environment variables from the original client config are preserved for stdio servers without being copied into the MCPZT YAML as literal secrets. The generated MCPZT config stores `env:VARIABLE_NAME` references, while the generated client config keeps passing the original environment variables to the MCPZT wrapper process. Keep generated client configs local and out of source control when they contain credentials.

After reviewing the generated files, back up the original client config, replace it with the generated wrapped config, and restart the client. Run the approval UI beside Claude when you want to review high-risk tool calls interactively.

```bash
cp "$HOME/Library/Application Support/Claude/claude_desktop_config.json" \
  "$HOME/Library/Application Support/Claude/claude_desktop_config.json.backup"
cp .mcpzt/client-import/claude/claude_desktop_config.mcpzt.json \
  "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
mcpzt approve serve --config .mcpzt/client-import/claude/mcpzt.yaml
```

## How A Request Is Evaluated

Every request goes through the same basic shape. The transport receives a JSON-RPC message and validates that it is an MCP-style message. MCPZT identifies the logical server, method, capability type, capability name and arguments. It resolves identity from the configured auth mode. It loads metadata from `capability_mappings`, then evaluates policies against the normalized context.

If the selected policy denies the request, the upstream server is never called. If a validator fails, the upstream server is never called. If a policy requires approval, MCPZT creates an approval request, returns an `approval_id`, and waits for an approved retry. Only when the policy decision and validators allow execution does MCPZT forward the request to the real MCP server.

After the upstream responds, MCPZT can evaluate output policies before returning data to the client. This is important because a safe request can still produce sensitive output. For example, `crm.get_customer` may be allowed, while returned fields such as `email`, `phone` or `api_key` should be redacted before an agent receives them.

List requests are handled with the same philosophy. For `tools/list`, `resources/list` and `prompts/list`, MCPZT asks the upstream for its list, then filters that list according to policy. The upstream may expose `delete_repository`, but the agent does not need to see that tool if policy hides it.

Unknown or future MCP methods do not get a special bypass. With `runtime.default_decision: deny`, an unknown method must still match a policy before it is allowed.

## Configuration Explained

The smallest useful HTTP proxy config declares a project, a runtime mode, an auth mode, an upstream server, at least one policy and an audit destination.

```yaml
project:
  name: example
  environment: development

runtime:
  mode: proxy
  default_decision: deny
  dry_run: false

auth:
  mode: none

servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp

policies:
  - id: allow-github-search
    effect: allow
    match:
      server: github
      capability_type: tool
      capability: github.search_issues

audit:
  destination: file
  path: ./mcpzt-audit.jsonl
```

The `project.environment` field matters because production validation is stricter than development validation. Development can use `auth.mode: none` and `dry_run: true` while you explore. Production rejects unsafe defaults unless you explicitly opt out with a dedicated override. That friction is intentional.

The `runtime.default_decision` field is the fallback when no policy matches. For serious use, keep it at `deny`. If a tool is not explicitly allowed, hidden or approval-gated, it should not execute by accident.

The `servers` section declares logical MCP servers. A project can have one server or many. Each server gets a name, a transport and either an HTTP upstream URL or a stdio command. The logical name is what policies match and what HTTP routes use.

The `capability_mappings` section is optional but powerful. It lets you attach security meaning to raw MCP capability names. Instead of writing every policy against exact tool names, you can say that `github.search_issues` is `code.read` and `github.merge_pull_request` is `code.merge` with `critical` risk. Policies can then match semantic fields such as `action`, `risk`, `access`, `resource_type`, `tags` and `data_classification`.

The `policies` section is the heart of the config. Each policy has an ID, an effect, a match block, optional conditions, optional validators and optional output rules. Policy IDs appear in audit logs and approval records, so choose names that a human can understand during review.

The `audit` section controls where JSONL decision records go. For stdio mode, do not use stdout for audit logs because stdout is reserved for MCP protocol messages.

## Policy Model

Policies are evaluated over a normalized context rather than raw HTTP details. That context includes the logical server, MCP method, capability type, capability name, arguments, output, identity and mapped metadata.

The available effects are `deny`, `hide`, `require_approval`, `redact`, `limit`, `transform`, `allow` and `log`. In plain language, `deny` blocks a request, `hide` removes capabilities from list responses and blocks matching calls, `require_approval` creates a review step, `redact` changes output, `limit` constrains output, `transform` reshapes output, `allow` permits the request, and `log` records without changing behavior.

Precedence is intentionally conservative. Deny and hide policies win over approval. Approval wins over allow. If nothing matches and the default decision is deny, the request stops. This makes policy files easier to review because a broad allow can still be constrained by a narrow deny.

Conditions under `when` let you look inside arguments, identity, metadata or output. For example, you can require approval only when `args.branch` equals `main`, or redact output only when `output.email` exists.

Policies can also include an `input` block for simple, human-readable parameter rules. This is different from named validators. Validators are reusable checks such as SQL safety or URL safety. The `input` block is for per-tool shape control: which fields may be present, which fields are required, which fields are forbidden, which values are acceptable, and how large fields or lists may become.

## Policy Examples

This section is deliberately longer than a reference table. The goal is to show how policies feel in real projects.

### Allow Read-Only GitHub Tools

A common first policy is read-only repository access. The mapping gives semantic meaning to each GitHub tool. The policy then allows the semantic action rather than every tool by name.

```yaml
capability_mappings:
  github:
    tools:
      github.search_issues:
        action: code.read
        risk: low
        access: read
      github.get_pull_request:
        action: code.read
        risk: low
        access: read

policies:
  - id: allow-github-read
    effect: allow
    match:
      server: github
      action: code.read
```

This pattern is easier to maintain when the upstream grows. If a new read-only GitHub tool appears, you can map it to `code.read` and let the existing policy cover it after review. If a write tool appears, it remains denied by default until you map and allow it.

### Require Approval For Main Branch Merges

Some actions are legitimate but should not happen automatically. Merging a pull request into `main` is a good example. You may want the agent to prepare the action, but a human should approve the exact repository, pull request and branch.

```yaml
capability_mappings:
  github:
    tools:
      github.merge_pull_request:
        action: code.merge
        risk: critical
        access: write

policies:
  - id: github-main-merge-needs-approval
    effect: require_approval
    match:
      server: github
      capability: github.merge_pull_request
    when:
      args.branch:
        equals: main
```

When this policy matches, the first call does not reach the upstream MCP server. MCPZT creates an approval request and returns an `approval_id`. The retry must include that approval ID and must match the same server, capability, identity and argument hash.

### Hide Destructive Tools

Sometimes a tool should not even be visible to the agent. Hiding is useful when the tool is too risky for the current project or when seeing the tool may invite unnecessary agent behavior.

```yaml
policies:
  - id: hide-repository-delete
    effect: hide
    match:
      server: github
      capability: github.delete_repository
```

If the upstream returns `github.delete_repository` from `tools/list`, MCPZT removes it from the list response. If the client tries to call it anyway, the call is blocked.

### Allow SQL Reads But Block Writes

Database tools are risky because a single tool can accept both safe and destructive statements. A tool named `postgres.query` can run `select * from issues`, but it might also accept `delete from issues`. This is exactly where validators help.

```yaml
capability_mappings:
  postgres:
    tools:
      postgres.query:
        action: db.read
        risk: medium
        access: read

policies:
  - id: allow-readonly-sql
    effect: allow
    match:
      server: postgres
      action: db.read
    validators:
      - name: sql_read_only
        options:
          query_arg: query
```

The policy allows the tool only after the validator accepts the query. The built-in SQL validator allows `SELECT`, `WITH` and `EXPLAIN`, and blocks destructive keywords such as `DROP`, `DELETE`, `UPDATE`, `INSERT`, `ALTER` and `TRUNCATE`.

The validator is a guardrail, not a substitute for database permissions. In production, use both: MCPZT validation and read-only database credentials for the upstream MCP server.

### Restrict Filesystem Reads To A Project Directory

Filesystem MCPs are useful and dangerous for the same reason: they can see local files. The policy below allows reads only inside `./workspace/docs`.

```yaml
policies:
  - id: allow-project-docs-read
    effect: allow
    match:
      server: filesystem
      capability: filesystem.read_file
    validators:
      - name: filesystem_path
        options:
          path_arg: path
          allowed_roots:
            - ./workspace/docs
          read_only: true
```

Relative roots are resolved from the config file directory when the config is loaded from disk. That makes behavior stable even if MCPZT is launched from a different working directory.

### Allow Internal Email Only

Email tools are another example where arguments matter. Sending to an internal domain may be acceptable, while sending to an external address may need approval or a hard block.

```yaml
policies:
  - id: allow-internal-email
    effect: allow
    match:
      server: email
      capability: email.send
    validators:
      - name: email
        options:
          recipients_arg: to
          allowed_domains:
            - company.example
          block_attachments: true
```

This example allows the send only when all recipients belong to `company.example` and no attachments are present.

### Constrain Tool Parameters Directly

Some tools are risky not because the tool itself is always dangerous, but because a few parameters change the blast radius. A search tool might be safe when it only receives a query and a limit, but not when the client can send arbitrary hidden flags. The `input` block keeps that kind of policy readable in YAML.

```yaml
policies:
  - id: allow-safe-issue-search
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
      forbidden_fields:
        - raw_token
      allowed_values:
        limit:
          - 10
          - 25
          - 50
      max_field_bytes:
        query: 512
```

This style is meant to be reviewable by humans. During a pull request, a reviewer can see that `query` is required, `raw_token` is forbidden, and `limit` is constrained to known values without reading Python code.

### Block SSRF-Prone URLs

URL-fetching tools are often vulnerable to accidental or prompted SSRF. The URL validator blocks localhost, private IPs, link-local IPs and cloud metadata hosts by default. It also resolves hostnames by default so a hostname pointing at a private IP is blocked.

```yaml
policies:
  - id: allow-public-fetch
    effect: allow
    match:
      server: browser
      capability: browser.fetch
    validators:
      - name: url
        options:
          url_arg: url
          allowed_schemes:
            - https
          block_private_ips: true
          resolve_dns: true
```

This should still be paired with network egress controls. MCPZT can catch many bad inputs before upstream, but the network should also enforce where the upstream can connect.

### Redact Customer Data

Output policies are useful when a tool should be callable but some returned fields should not be shown to the model or client.

```yaml
policies:
  - id: redact-customer-pii
    effect: redact
    match:
      server: crm
      capability: crm.get_customer
    when:
      output.email:
        exists: true
    output:
      redact_fields:
        - email
        - phone
        - api_key
```

This policy allows `crm.get_customer` to run, then redacts sensitive fields from the upstream response. Output policies apply to JSON-RPC errors too, which matters when upstream servers put details or traces inside error payloads.

### Match Identity From JWT Or OIDC

Identity-based policies are best with JWT or OIDC, because the identity comes from signed claims rather than caller-supplied headers.

```yaml
auth:
  mode: oidc
  issuer: https://issuer.example
  audience: mcpzt
  jwks_url: https://issuer.example/.well-known/jwks.json
  required_scopes:
    - mcp:read

policies:
  - id: security-team-can-request-refunds
    effect: require_approval
    match:
      server: stripe
      capability: stripe.refund
      group: security
```

For `static_token` and `api_key`, MCPZT ignores `x-mcpzt-*` identity headers by default. Only enable `auth.trust_identity_headers: true` behind a trusted gateway that strips spoofed inbound headers and injects trusted ones.

### Roll Out In Dry Run

Dry run is useful when learning what a policy would do. In dry run, MCPZT evaluates and audits decisions, but it does not enforce blocks or hide capabilities.

```yaml
project:
  environment: development

runtime:
  default_decision: deny
  dry_run: true
```

Do not treat dry run as production enforcement. Production rejects `dry_run: true` unless an explicit production override is set, and `mcpzt doctor` still reports production dry run as a failure.

## Validators

Validators run before upstream calls and are tied to policies. They are intentionally deterministic and local. They do not call a model, and they do not contact external services except for DNS resolution in the URL validator.

`sql_read_only` checks a SQL string and blocks destructive statements. `filesystem_path` resolves and constrains paths. `url` blocks unsafe schemes and network targets. `email` checks recipients and attachments. `regex` checks a field with allow or deny patterns. `required_forbidden_fields` enforces structural argument expectations. `max_field_bytes` prevents oversized field values.

The `input` policy block covers the common structural cases directly on the policy. Named validators remain useful when the rule has domain logic, such as parsing SQL, resolving filesystem paths or rejecting private network URLs.

Validators are strongest when paired with upstream least privilege. A filesystem MCP should still be launched with the narrowest directory it needs. A database MCP should still use read-only credentials for read-only use cases. MCPZT is the policy layer in front, not the only control in the system.

## Output Enforcement

Output enforcement is the second half of the product. It is not enough to decide what an agent can ask for. You often also need to decide what an agent can receive back.

MCPZT evaluates output after the upstream responds. If a matching output policy denies the response, the client receives a controlled MCPZT error instead of the upstream data. If a matching output policy redacts the response, selected fields are replaced with `[REDACTED]`. If a policy limits output size or includes only selected fields, MCPZT transforms the response before returning it.

Output enforcement applies to JSON-RPC `result` and JSON-RPC `error`. That detail matters because upstream servers sometimes include stack traces, SQL errors, internal IDs or tokens in error payloads.

## Approvals

Approvals are for actions that are allowed in principle but should not execute automatically. MCPZT creates an approval only because a policy evaluates to `require_approval`; it does not invent approvals from hidden heuristics.

The first call stops before upstream and returns a controlled JSON-RPC error containing an `approval_id`. A human can inspect the approval request with the CLI. The approval record includes the policy, server, capability, identity and a hash of the arguments. When the client retries with `_mcpzt_approval_id`, MCPZT verifies that the retry still matches the original approval.

```bash
mcpzt approve list --config mcpzt.yaml
mcpzt approve list --format json --config mcpzt.yaml
mcpzt approve show <approval-id> --config mcpzt.yaml
mcpzt approve allow <approval-id> --config mcpzt.yaml --by ana@example.com --comment "reviewed"
mcpzt approve deny <approval-id> --config mcpzt.yaml --by ana@example.com --comment "not approved"
```

The table output is meant for humans. The JSON output is meant for review tools, operational scripts and any UI that wants to render pending approval requests without scraping terminal formatting.

The approval ID is stripped before forwarding the request upstream. The real MCP server does not need to understand MCPZT approvals.

The local approval store uses a file lock and atomic replace. Approval decisions record approver, timestamp and optional comment, and approval lifecycle events are written to audit.

Approval lifecycle events can also be sent to an HTTP webhook. This is useful for Slack bridges, ticketing systems, internal review UIs or security automation. The webhook receives redacted approval data and can be configured as best-effort or strict.

```yaml
approvals:
  path: ./mcpzt-approvals.json
  default_ttl_seconds: 900
  webhook_url: env:MCPZT_APPROVAL_WEBHOOK_URL
  webhook_strict: false
```

With `webhook_strict: false`, MCPZT keeps enforcing policy even if the notification endpoint is temporarily unavailable. With strict mode, webhook delivery failure is treated as an operational failure.

For local projects and very small deployments, the default JSON approval store is simple and transparent. For team environments, use the SQLite backend. It keeps the same approval model and CLI, but stores approvals in a database file with indexed reads and writes. This is a better default for long-lived gateways, approval dashboards and operational review.

```yaml
approvals:
  backend: sqlite
  path: /var/lib/mcpzt/approvals.sqlite3
  default_ttl_seconds: 900
```

The approval UI is optional. It is self-hosted and reads the same approval store as the gateway. Run it on localhost for local review, or put it behind your existing internal authentication layer for team use.

```bash
mcpzt approve serve --config mcpzt.yaml --host 127.0.0.1 --port 8770
```

The UI is deliberately small: it lists pending approvals, shows server, capability, policy and subject, and lets an operator approve or deny. For deeper workflow integration, use `mcpzt approve list --format json`, the approval API exposed by the UI, or approval webhooks.

## Trying HTTP Manually

You can exercise the HTTP proxy with `curl`. Start MCPZT first.

```bash
mcpzt run --config examples/github-readonly/mcpzt.yaml --host 127.0.0.1 --port 8765
```

List tools through MCPZT. In a real run, the upstream MCP server must also be running at the URL declared in the config.

```bash
curl -s http://127.0.0.1:8765/mcp/github \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

Call a safe tool.

```bash
curl -s http://127.0.0.1:8765/mcp/github \
  -H 'content-type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "github.search_issues",
      "arguments": {"q": "is:open label:security"}
    }
  }'
```

Call a tool that requires approval.

```bash
curl -s http://127.0.0.1:8765/mcp/github \
  -H 'content-type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "github.merge_pull_request",
      "arguments": {"repo": "acme/api", "pull_number": 42, "branch": "main"}
    }
  }'
```

The response contains an `approval_id`. Approve it with the CLI.

```bash
mcpzt approve allow appr_xxx --config examples/github-readonly/mcpzt.yaml --by ana@example.com
```

Then retry with `_mcpzt_approval_id` inside the tool arguments.

```bash
curl -s http://127.0.0.1:8765/mcp/github \
  -H 'content-type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "github.merge_pull_request",
      "arguments": {
        "repo": "acme/api",
        "pull_number": 42,
        "branch": "main",
        "_mcpzt_approval_id": "appr_xxx"
      }
    }
  }'
```

If the retry changes the repository, pull request, branch or identity, the approval is no longer valid. That strictness is what prevents approving one action and executing another.

## Multi-MCP Example

MCPZT can protect several MCP servers in one project. The multi-MCP example is intentionally realistic: GitHub for repository operations, Postgres for SQL, filesystem for project file reads, and CRM for confidential customer data.

```bash
mcpzt config validate --config examples/multi-mcp/mcpzt.yaml
```

The integration test starts local fake MCP HTTP upstreams and drives the real MCPZT HTTP app. It checks that each logical server is routed independently and that policies remain scoped to the correct MCP.

```bash
python -m pytest tests/integration/test_multi_mcp_use_cases.py -q
```

The test verifies that GitHub search and Postgres `SELECT` reach the correct upstreams, while SQL `DELETE` and `/etc/passwd` reads are blocked before upstream. It verifies that a GitHub merge requires approval, that the approved retry reaches upstream, and that the approval ID is removed before forwarding. It also verifies that CRM output redacts `email` and `api_key`.

Full documentation is in [docs/MULTI_MCP_USE_CASES.md](docs/MULTI_MCP_USE_CASES.md). The versionable config is [examples/multi-mcp/mcpzt.yaml](examples/multi-mcp/mcpzt.yaml).

## Authentication And Secrets

MCPZT supports `none`, `static_token`, `api_key`, `jwt` and `oidc`. Local development can start with `none`, but team or production deployments should use JWT or OIDC when possible.

Static bearer auth is simple for local internal use.

```yaml
auth:
  mode: static_token
  token_env: MCPZT_AUTH_TOKEN
```

API key auth lets you choose the header.

```yaml
auth:
  mode: api_key
  header: x-api-key
  token_env: MCPZT_API_KEY
```

JWT and OIDC are better when policies need real identity, groups, roles, client IDs or scopes.

```yaml
auth:
  mode: oidc
  issuer: https://issuer.example
  audience: mcpzt
  jwks_url: https://issuer.example/.well-known/jwks.json
  required_scopes:
    - mcp:read
```

Client credentials and upstream credentials are separate. MCPZT authenticates the client, then uses explicitly configured upstream headers if the real MCP server also needs a credential.

```yaml
servers:
  - name: github
    transport: http
    upstream: https://github-mcp.internal/mcp
    upstream_headers:
      Authorization: Bearer ${GITHUB_MCP_TOKEN}
      X-API-Key: env:GITHUB_MCP_API_KEY
```

Incoming client `Authorization` is not forwarded to upstreams unless you configure it as an upstream header. This prevents accidental credential reuse across trust boundaries.

Secret references can come from environment variables, local files or common secret-manager CLIs. Environment references are the simplest and most portable. File references are convenient for mounted Kubernetes secrets or local secret files. `op://`, `aws-sm://` and `vault://` references let teams integrate with 1Password CLI, AWS Secrets Manager CLI and Vault CLI without baking provider SDKs into the runtime path.

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
      Authorization: Bearer aws-sm://prod/mcp/crm#token
```

`mcpzt doctor --config mcpzt.yaml` checks referenced environment variables, mounted secret files and the presence of external secret-manager CLIs. It does not print resolved secret values.

## Auditing

Audit events are JSONL. They are designed to be easy to ship to an existing log pipeline and easy to inspect locally with normal command-line tools.

Each policy decision includes timestamp, event ID, correlation ID, identity, server, method, capability, decision, policy ID, reason, redacted arguments, dry-run state, approval requirement and whether upstream was called.

```bash
mcpzt audit tail --config mcpzt.yaml
```

Secret-like keys and bearer-style strings are redacted recursively before write. Redaction applies to audit records and to sanitized upstream errors. In production, keep audit logs on protected storage and keep `audit.strict: true` so audit write failures fail closed.

Use audit search when you need to investigate a specific operational question. It reads the configured JSONL audit file and filters by event type, server, decision, policy ID, correlation ID, approval ID and time window. Table output is useful during live review; JSON output is better for scripts and incident notebooks.

```bash
mcpzt audit search --config mcpzt.yaml --server github --decision deny
mcpzt audit search --config mcpzt.yaml --policy-id critical-actions-need-approval
mcpzt audit search --config mcpzt.yaml --approval-id appr_xxx --format json
```

By default, audit events include a hash chain. Each event stores the previous event hash and its own hash over canonical JSON. This does not replace secure log storage, but it makes accidental or malicious alteration visible during review.

```bash
mcpzt audit verify --config mcpzt.yaml
```

The HTTP runtime also exposes Prometheus-style metrics when `metrics.enabled: true`. The metrics endpoint counts decisions by server, method, decision and policy ID. It deliberately avoids request arguments and output fields so monitoring does not become a second copy of sensitive data.

```yaml
metrics:
  enabled: true
  path: /metrics
```

## Capability Discovery And Drift

MCP servers can change over time. A package upgrade or config change can expose new tools. MCPZT includes discovery and diff commands so teams can treat that as a review event.

```bash
mcpzt discover --server github --config mcpzt.yaml
```

After a snapshot exists, compare the current upstream with the saved version.

```bash
mcpzt diff --server github --config mcpzt.yaml
```

A new low-risk read tool may only need a mapping and an allow policy. A new high-risk write tool should trigger policy review, approval requirements, or a deny/hide policy.

Run the deterministic scanner against a snapshot or a live server before accepting drift. The scanner flags suspicious descriptions or schemas, missing capability metadata and dangerous-looking tools that are directly allowed without approval. It exits with code `2` when high or critical findings exist, which makes it practical for CI.

```bash
mcpzt scan --config mcpzt.yaml --snapshot .mcpzt-capabilities/github.json
```

The scanner is intentionally deterministic. It is not a model-based security review and it should not be treated as a full threat model. Its job is to catch obvious MCP capability risks early and consistently.

Policy analysis answers a slightly different question. Discovery and scan ask what the upstream exposes and whether those capabilities look risky. Coverage asks how your current policy resolves each known capability. Risks flags direct allows for high-risk capabilities, side-effecting tools without input constraints, missing mappings and default-decision fallthrough. Unused policy analysis points out policies that do not structurally match any mapped or discovered capability, which often catches stale names after an upstream change.

```bash
mcpzt policy coverage --config mcpzt.yaml --snapshot .mcpzt-capabilities/github.json
mcpzt policy risks --config mcpzt.yaml --snapshot .mcpzt-capabilities/github.json
mcpzt policy unused --config mcpzt.yaml --snapshot .mcpzt-capabilities/github.json
```

Use JSON output in CI when you want to archive the analysis or gate a release.

```bash
mcpzt policy risks --config mcpzt.yaml --format json
```

## Deployment Patterns

MCPZT is intentionally not tied to one shape. In every shape, the same idea holds: MCPZT is a separate enforcement layer in front of one or more upstream MCP servers. You can run it directly as a Python CLI, as a long-running service, in Docker, in Kubernetes, or as a stdio wrapper, depending on where the upstream MCP lives.

In a local developer wrapper, MCPZT launches a command-based MCP server and sits between the desktop client and the child process. This is useful for filesystem-style MCPs or local tools started by clients such as desktop assistants or IDEs.

```yaml
runtime:
  mode: stdio

servers:
  - name: filesystem
    transport: stdio
    command:
      - npx
      - -y
      - "@modelcontextprotocol/server-filesystem"
      - ./workspace
```

In local HTTP proxy mode, the real MCP server already speaks HTTP. MCPZT listens on another local port, and the MCP client points to MCPZT instead of the upstream server. This is useful when you already have an MCP server running and want to add policy without changing its code.

```yaml
runtime:
  mode: proxy

servers:
  - name: github
    transport: http
    upstream: http://127.0.0.1:3001/mcp
```

In an internal gateway deployment, one MCPZT instance protects several internal MCP servers. This is where multi-MCP routing is useful. Clients call `/mcp/github`, `/mcp/postgres` or `/mcp/crm`, while the real upstreams stay private. Docker or Kubernetes often makes sense here because MCPZT is being operated as infrastructure with its own lifecycle.

```yaml
servers:
  - name: github
    transport: http
    upstream: https://github-mcp.internal/mcp

  - name: postgres
    transport: http
    upstream: https://postgres-mcp.internal/mcp

  - name: crm
    transport: http
    upstream: https://crm-mcp.internal/mcp
```

In a sidecar deployment, the real MCP server binds to localhost inside the same host, container group or pod. MCPZT is the only process exposed to clients. This is often the simplest production shape when each team owns one MCP service and wants to keep the upstream server unchanged.

The repository includes public deployment recipes under `deploy/`. The Docker Compose production example runs the container with a read-only filesystem, dropped Linux capabilities and explicit environment-backed secrets. The Helm chart is a starting point for Kubernetes sidecar or gateway deployments. It defaults to one replica because approval state is local by default, even when using SQLite. Scale-out deployments should use storage with correct locking semantics and deliberate operational ownership before increasing replicas.

```bash
docker run --rm ghcr.io/686f6c61/mcp-zero-trust-layer:<version> version
docker compose -f deploy/docker-compose.prod.yaml up
helm install mcpzt deploy/helm
```

The official image is published to GitHub Container Registry from the release workflow. The Compose and Helm examples use that image path so operators can start from a known release artifact instead of rebuilding locally. Teams that need custom certificates, internal package mirrors or pinned base images can still build their own image from the Dockerfile.

## Production Posture

A production config should be explicit and conservative. Use `project.environment: production`, keep `runtime.default_decision: deny`, keep `runtime.dry_run: false`, configure `runtime.public_base_url` or `runtime.trusted_hosts`, configure authentication, set origin restrictions where relevant, keep upstream servers private, keep audit strict, and commit capability snapshots.

For JWT or OIDC production configs, set `auth.issuer` and `auth.audience`. Required scopes are strongly recommended because they let you distinguish a token that is valid in general from a token intended to use MCPZT.

Use conservative byte limits. `runtime.max_request_bytes` limits inbound client requests. `servers[].max_response_bytes` limits upstream responses. These limits protect MCPZT from oversized payloads coming from either side.

FastAPI `/docs`, `/redoc` and `/openapi.json` are disabled automatically when `project.environment: production`.

The production guide has the full checklist: [docs/PRODUCTION.md](docs/PRODUCTION.md).

## Examples In This Repository

The examples are meant to be read as starting points, not as perfect production configs. [examples/github-readonly](examples/github-readonly/mcpzt.yaml) allows read-only GitHub operations and requires approval for critical actions. [examples/postgres-readonly](examples/postgres-readonly/mcpzt.yaml) allows SQL reads while blocking destructive statements. [examples/filesystem-safe](examples/filesystem-safe/mcpzt.yaml) restricts filesystem access and requires approval for writes. [examples/protected-http-upstream](examples/protected-http-upstream/mcpzt.yaml) shows how client auth and upstream credentials stay separate. [examples/oidc-gateway](examples/oidc-gateway/mcpzt.yaml) shows a production-shaped OIDC gateway with group-based policies, SQLite approvals and output redaction. [examples/multi-mcp](examples/multi-mcp/mcpzt.yaml) protects GitHub, Postgres, filesystem and CRM MCPs in one config.

## Documentation Map

Use [docs/MULTI_MCP_USE_CASES.md](docs/MULTI_MCP_USE_CASES.md) for the tested multi-server scenario. Use [docs/PRODUCTION.md](docs/PRODUCTION.md) for deployment posture. Use [docs/PYPI_RELEASE.md](docs/PYPI_RELEASE.md) for release flow. Security reporting is in [SECURITY.md](SECURITY.md), contribution guidance is in [CONTRIBUTING.md](CONTRIBUTING.md), and release notes are in [CHANGELOG.md](CHANGELOG.md).

## Development

Run the complete test suite and linter before changing behavior.

```bash
python -m pytest
ruff check .
```

Run only the multi-MCP scenario when working on routing, filtering, approvals or output enforcement.

```bash
python -m pytest tests/integration/test_multi_mcp_use_cases.py -q
```

Build package artifacts and validate PyPI metadata.

```bash
python -m build
twine check dist/*
```

Before release, also run `mcpzt config validate --config examples/multi-mcp/mcpzt.yaml`, `mcpzt config lint --config examples/multi-mcp/mcpzt.yaml`, `mcpzt demo --output /tmp/mcpzt-demo --force`, and a clean wheel smoke test. The release workflow repeats the important parts in CI and performs a post-publish install check from PyPI.

## Packaging

Package metadata lives in [pyproject.toml](pyproject.toml). Runtime dependency ranges stay flexible for PyPI users. Docker builds use [constraints.txt](constraints.txt) for reproducibility. Generated package artifacts are written to [dist](dist).

The source distribution includes bundled policy packs from `src/mcp_zero_trust_layer/packs`, public documentation under `docs`, YAML examples under `examples`, and deployment recipes under `deploy`. Internal planning docs, local configs, audit logs, approval stores, virtual environments and generated build artifacts are intentionally excluded.

## Troubleshooting

If `mcpzt config validate` fails, read the validation message literally. Most config problems are missing server fields, duplicate policy IDs, invalid transport settings, or production settings that are intentionally blocked. Production is stricter than development by design.

If the agent cannot see a tool, start with `tools/list` through MCPZT and then inspect your policy mappings. The tool may be hidden by a deny or hide policy, it may have no matching allow policy, or the upstream may be returning a capability name different from the one in your config. `mcpzt discover --server <name>` helps reveal the upstream's actual names.

If a safe call is denied, reproduce it with `mcpzt policy test`. Provide the same server, method, capability and arguments. The result tells you the selected decision, policy ID, reason and validator errors.

If an approval retry still fails, compare the retry with the original request. Approvals are bound to identity, server, capability, policy and argument hash. Changing the arguments after approval invalidates the approval.

If the upstream never receives a request, check audit for `upstream_called: false`. That usually means MCPZT blocked the call before forwarding because of policy, approval or validation.

If the upstream receives a request but the client gets redacted data, look for output policies using `effect: redact`, `effect: limit` or `effect: transform`. Output policies run after upstream and before client response.

## Limitations In 0.x

HTTP GET SSE streams are not implemented. Request-scoped upstream SSE passthrough is intentionally outside this first release. The file and SQLite approval stores are suitable for local, sidecar and simple self-hosted use; horizontally scaled gateways need deliberate shared-state design. The URL validator is a strong guardrail but not a replacement for network egress controls. MCPZT reduces MCP tool risk, but it does not claim complete protection against prompt injection or all forms of agent misuse.

## License

Apache-2.0. See [LICENSE](LICENSE).
