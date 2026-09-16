# Security audit findings (2026-09-16)

Read-only audit of current implementation; reproductions use synthetic identities, mock HTTP and temporary local files. Run `.venv/bin/python docs/audit/reproduce_security.py` from repo root. Script prints observed violations; it is an audit artifact, not a passing regression suite.

## P1: JWT/OIDC unsigned header fallback can satisfy privileged client/agent policies

`identity/auth.py:188-192` accepts `x-mcpzt-client-id` and `x-mcpzt-agent-id` when the respective signed JWT claim is absent, regardless of `trust_identity_headers: false`. PolicyEngine uses these identities for authorization. Verified: ordinary signed subject alice + unsigned agent-id privileged-agent reaches a tool allowed only for that agent. Also project/machine/session metadata is always caller-controlled. Require signed claims for authorization identity, or explicit trusted proxy mode; separate untrusted tracing metadata. README identity claims guarantee (589) needs correction until fixed.

## P1: HTTP upstream session leakage across authenticated clients

`upstream/http.py:49-59,69-71,96-100`: cache key `(server.name, incoming MCP session or empty string)` lacks authenticated identity. HTTP response does not propagate upstream session headers. All normal sessionless callers therefore use the empty-string bucket. Verified mock server: Alice receives upstream alice-session, Bob's next initialize is sent WITH alice-session. Upstream session data, notifications and cancellation can cross users; extent depends on upstream behavior. Require gateway-issued opaque downstream sessions bound to authenticated principal; never share empty session cache; preserve controlled negotiated headers. Do not simply trust arbitrary incoming upstream session IDs.

## P1: Approval effect silently ignored for non-call methods

`core/pipeline.py:241-260` only rejects deny/hide then forwards; `_handle_list_request` also lacks approval handling. Verified blanket require_approval policy still forwards resources/subscribe immediately. `_context_for_message` also discards params of generic methods, so argument policies on those methods inspect an empty dictionary. Apply authorization effects consistently to every supported request and preserve method parameters. README 295-297 promise contradicted.

## P1: OPA fail-closed outbound decisions become fail-open

`policy/adapters.py:56-65` returns deny with no policy_id on adapter failure; boolean false does likewise. `core/pipeline.py:328` only enforces outbound denial with truthy policy_id. Verified inbound OPA true, outbound connection failure => sensitive response returned unchanged. Lists also ignore deny without policy_id. Policy ID must be optional attribution, never an enforcement prerequisite. Handle default built-in list behavior separately from explicit external deny.

## P1: SQL comment stripping hides stacked destructive statement

`validators/basic.py:227-229` removes `--...` without tracking SQL literals. Verified `SELECT '--'; DELETE FROM demo;` passes sql_read_only; SQLite executescript deletes the demo row. Although database credentials are documented as primary protection, the explicit promise to block stacked/destructive statements is violated. Use dialect-aware tokenization/parser and reject ambiguous input; never strip comments independently of quotes. Separate normal SELECT side-effect function limitation (`SELECT nextval('invoice_seq')` also passes) from this concrete lexical bypass.

## P2: Email allowed-domain validator accepts multiple addresses hidden in one string

`validators/basic.py:151-168`: determines domain using final @ only. Verified `attacker@evil.test, trusted@company.test` passes allowed_domains=[company.test]. An upstream that parses recipient header strings sends to both. Parse mailboxes with a strict parser, reject CR/LF and malformed lists, validate every recipient including separately configured cc/bcc. Impact conditional on upstream parsing.

## P2: Nested allowed_fields bypass through array/scalar shape

`validators/input_policy.py:38-47`: allowed parent path recurses only if dict, then accepts other shapes. Verified allowed_fields=[customer.name] accepts customer=[{secret:leak}]. A scalar customer also bypasses nested leaf constraint. Reject incompatible ancestor shapes or implement explicit typed array path semantics. Schema-validation must reflect what actual upstream consumes.

## Known boundary, not claimed as a new standalone vulnerability

Path/DNS validation happens in gateway namespace and before upstream execution. Remote paths, symlink races, redirects, DNS rebinding need upstream confinement/egress control; current implementation does not pin target resolution. SQL SELECT functions can have side effects; read-only DB credentials remain necessary. Existing README acknowledges these guardrail limits, unlike the concrete violations above.
