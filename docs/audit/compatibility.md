# Client, provider and protocol compatibility audit

Audited 2026-09-16. Scope: repository implementation and current official documentation. No live vendor/model execution was performed; documented vendor support is not an end-to-end compatibility certification.

## Conclusion

MCPZT is model-agnostic: it neither invokes language models nor maintains a model catalog. Compatibility depends on the MCP host/client, transport, authentication and approval workflow. Adding Grok means adding Grok Build client setup and xAI remote-MCP integration examples, not inserting model names into policy logic. A current compatibility matrix is more useful than a list of model versions that the gateway does not inspect.

## Confirmed findings

### C-01 — VS Code generator emits the wrong root (medium)

`src/mcp_zero_trust_layer/cli/main.py:1722` groups VS Code with clients that use `mcpServers`. VS Code `.vscode/mcp.json` uses `servers`. Calling `_render_client_config(..., 'vscode', ...)` in the project virtualenv produced root `['mcpServers']`. This contradicts the advertised client-specific output.

Official reference: https://code.visualstudio.com/docs/agents/reference/mcp-configuration

### C-02 — Import changes schema and drops client security settings (high impact, local configuration)

`src/mcp_zero_trust_layer/client_import.py:85` always serializes only `mcpServers`, even after accepting a VS Code `servers` source. `_client_server` reconstructs entries from command/args/env; it does not preserve original client controls. A temporary VS Code input containing `servers`, top-level `inputs` and `sandbox`, and `sandboxEnabled: true` produced only `mcpServers` with the wrapper command. The source file itself was not modified during this audit. Following README instructions to replace the original config with this generated file would lose these settings; correcting the root alone is insufficient.

Preserve unrelated top-level and per-server client options when their semantics remain valid, explicitly transform transport-specific fields, and fail with a reviewable diagnostic on unsupported options rather than silently dropping them. Variable expressions in command/args and HTTP headers also need deliberate conversion: they are moved from a client interpolation context into MCPZT YAML, whose resolver does not implement every client's `${env:...}`, `${input:...}` or `${workspaceFolder}` syntax.

Official security-setting reference: https://code.visualstudio.com/docs/agent-customization/mcp-servers

### C-03 — Generated setup lacks explicit gateway credentials (medium)

`_render_client_config` emits a remote URL via an unversioned `npx -y mcp-remote`, or `claude mcp add` without auth options. It does not provide a native mechanism to reference a configured gateway bearer/API-key secret. OAuth-capable clients may negotiate configured OAuth, but static bearer/API-key setups need additional manual configuration. Native HTTP configurations should use environment-based secrets and distinguish gateway credentials from upstream credentials.

### C-04 — Approval retries are a custom integration contract (medium compatibility gap)

MCPZT requires an approved retry with `_mcpzt_approval_id`. Standard remote-MCP clients do not necessarily expose arbitrary top-level tool-call metadata or retry mechanics to applications/models. A successful `tools/list` is insufficient evidence that high-risk workflows work. Each supported integration needs a demonstrated request -> approval -> exact retry -> execution sequence, or explicit documentation that an application-side adapter is required.

OpenAI API approvals and MCPZT approvals are separate mechanisms. xAI's official remote-MCP page explicitly says OpenAI-compatible `require_approval` is unsupported there. Do not conflate a provider approval dialog with MCPZT's approval store.

### C-05 — Discovery is incomplete for paginated servers (medium)

`src/mcp_zero_trust_layer/capabilities/discovery.py:45` calls each list method once and ignores `nextCursor`. Capability snapshots, onboarding and drift scans consequently miss subsequent pages. It also hardcodes `2025-03-26`, does not verify the negotiated initialize version, and does not explicitly pass that negotiated version in subsequent HTTP discovery requests. This is not evidence that every older server is incompatible; it is missing protocol negotiation and enumeration coverage.

### C-06 — Stdio is a serial request/next-line adapter (high interoperability gap)

`src/mcp_zero_trust_layer/upstream/stdio.py:63` reads the next stdout line as the response without matching JSON-RPC IDs or dispatching upstream notifications/requests. An upstream notification before its response can therefore be returned as the response; the actual response then contaminates the next call. Server-initiated sampling, elicitation, progress and list-change messages require multiplexing or explicit unsupported-feature handling. The wrapper also cannot read cancellation while synchronously waiting for an upstream response. These limits are broader than the README's disclosed HTTP SSE limitation.

### C-07 — HTTP compatibility requires qualification

README correctly discloses JSON POST only, optional GET SSE absent, and upstream SSE unsupported. Upstream code nevertheless advertises `Accept: application/json, text/event-stream` and then parses the full body as JSON. A conforming upstream that chooses SSE will fail. MCPZT must either implement inspected SSE safely or document/enforce a JSON-response upstream profile with clear errors. GET returning 405 is allowed by the MCP specification and is not itself a finding.

HTTP session isolation is covered by the separate security audit. The app also does not reject invalid/unsupported `MCP-Protocol-Version` with the specified HTTP 400 response. Do not describe this subset as full MCP protocol conformance.

## Current official ecosystem matrix

| Integration | Current official configuration | Repository status / next step |
| --- | --- | --- |
| Grok Build | `grok mcp add --transport http NAME URL`; TOML `[mcp_servers.NAME]`, `url`, `headers`; also stdio | Missing generator and docs. Add CLI/TOML rendering and offline schema/quoting tests. |
| xAI/Grok API | Remote MCP via native SDK or OpenAI-compatible Responses API; `server_url`, `server_label`, `authorization`, optional allowed tools | Missing example. Use a reachable authenticated HTTPS gateway. `require_approval` is not supported by xAI's compatible API; explain MCPZT retry requirements. |
| VS Code / Copilot | `.vscode/mcp.json`, `servers`, native HTTP `url` | Existing kind is wrong; preserve sandbox/input controls on import. |
| Cursor | `mcpServers`, native remote `url` and `headers` | Existing generator routes through `mcp-remote`; native HTTP removes unnecessary adapter dependency. Import must preserve valid client options. |
| Claude Desktop / Claude Code | Existing stdio wrapper or Claude Code HTTP command | Existing outputs need auth and actual approval lifecycle validation, not blanket model support claims. |
| Claude API | Separate remote MCP connector, server URL/auth plus MCP toolset | Document separately from Desktop/Code; provider API integration is not desktop JSON. |
| Gemini CLI | `mcpServers`; Streamable HTTP uses `httpUrl`, SSE uses `url` | Missing generator; importer currently interprets `url` as HTTP and does not accept `httpUrl`, so cannot claim generic Gemini support. |
| Codex | TOML `[mcp_servers.NAME]`, HTTP `url`, `bearer_token_env_var`, header configuration | Missing generator/docs. No model list necessary. |
| OpenAI Responses API | `type: mcp`, `server_url`, `server_label`, `authorization`; provider approval protocol | Missing example; distinguish provider approval from MCPZT approval. |

Official sources reviewed:

- Grok Build: https://docs.x.ai/build/features/mcp-servers
- xAI remote MCP: https://docs.x.ai/developers/tools/remote-mcp
- xAI public stateless docs MCP (potential read-only integration fixture): https://docs.x.ai/developers/docs-mcp
- VS Code: https://code.visualstudio.com/docs/agents/reference/mcp-configuration
- Cursor: https://cursor.com/docs/mcp
- Gemini CLI: https://geminicli.com/docs/tools/mcp-server/
- Claude API connector: https://platform.claude.com/docs/en/agents-and-tools/mcp-connector
- Codex: https://developers.openai.com/codex/mcp/
- OpenAI remote MCP: https://developers.openai.com/api/docs/guides/tools-connectors-mcp
- MCP transports: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

## Recommended acceptance criteria

1. Offline fixtures for each supported client schema, authentication references, shell quoting, and import preservation. Include Grok Build, Gemini CLI and Codex; retain neutral JSON output as a documented generic shape.
2. A real MCP SDK local server smoke suite: initialize, version negotiation, initialized notification, paginated discovery, allow/deny, tool error, approval retry, and stdio notification before response. Include a stateful HTTP server and JSON/SSE behavior separately.
3. A dated support matrix distinguishing generated, protocol-tested, and live vendor-tested integrations. Do not label every model as tested because it can use an MCP client.
4. Paid/cloud provider smoke checks should be optional, explicitly configured and report model/client version. No live provider calls were made during this audit.
