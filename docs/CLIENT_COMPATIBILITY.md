# Clients, providers and model compatibility

Documentation reviewed against official sources on 2026-09-16.

MCPZT enforces MCP calls, independently of the language model selected by the host. It does not invoke a model API or maintain a model registry. Changing from Claude to Gemini, GPT or Grok inside a compatible MCP host does not require a new policy engine. The host's transport, authentication and approval behavior determine compatibility.

## Generate a connection snippet

Start the gateway, then generate and review a snippet. Merge it into the client's existing configuration; `client config` generates a snippet, not a replacement for unrelated client settings.

```bash
mcpzt client config --config mcpzt.yaml --kind grok --base-url https://gateway.example
mcpzt client config --config mcpzt.yaml --kind codex --base-url https://gateway.example
mcpzt client config --config mcpzt.yaml --kind gemini --base-url https://gateway.example
mcpzt client config --config mcpzt.yaml --kind vscode --base-url https://gateway.example
mcpzt client config --config mcpzt.yaml --kind cursor --base-url https://gateway.example
```

| `--kind` | Output | Configuration target |
| --- | --- | --- |
| `grok` | Native HTTP TOML, `[mcp_servers.NAME]` | Grok Build `~/.grok/config.toml` or project `.grok/config.toml` |
| `codex` | Native HTTP TOML, `[mcp_servers.NAME]` | Codex `~/.codex/config.toml` or project `.codex/config.toml` |
| `gemini` | JSON `mcpServers`, `httpUrl` | Gemini CLI settings JSON |
| `vscode` | JSON `servers`, `type: http`, `url` | VS Code `.vscode/mcp.json` |
| `cursor` | JSON `mcpServers`, `url` | Cursor `.cursor/mcp.json` |
| `claude-code` | Shell-quoted `claude mcp add` commands | Run reviewed commands in a shell |
| `claude-desktop` | JSON stdio bridge through `npx mcp-remote` | Claude Desktop client config |
| `json` | Legacy neutral JSON stdio bridge | Custom consumers that expect the documented `mcpServers` shape |

These renderers have offline schema, escaping and secret-reference tests. This is not a claim that every client release, hosted provider or model was tested end to end. Claude Desktop/neutral bridge output requires Node.js and `mcp-remote`; native HTTP outputs do not need that bridge.

### Authentication

For static bearer/API-key configurations, generation automatically references `auth.token_env`. To use a different variable on the client, pass `--token-env GATEWAY_TOKEN`. The generator never reads the variable or embeds the credential value. Export the actual credential in the environment where the client runs. For JWT/OIDC, `--token-env` may refer to a previously acquired access token; it must never contain a JWT signing key. Otherwise configure the client's OAuth login against your authorization server.

Cursor and VS Code receive `${env:GATEWAY_TOKEN}`; Gemini and Grok receive `${GATEWAY_TOKEN}`. Codex uses `bearer_token_env_var` or `env_http_headers` for API keys. The header configured by `auth.header` is respected in every authentication mode; custom headers receive the raw token. A static credential declared literally in YAML requires an explicit `--token-env`; it is never copied into output.

The legacy Desktop/neutral bridge and Claude Code command renderers reject environment-backed authentication instead of silently omitting it. Configure authentication manually for those clients or choose a native renderer. Do not put the upstream service's credential in the gateway client configuration: these are separate trust boundaries.

### Import existing JSON configs

`mcpzt client import` preserves the original `servers` or `mcpServers` root, unrelated top-level settings, and supported per-server controls such as sandbox settings, working directory and tool filters. Stdio environment variables stay in the client config and are passed into the wrapper; the MCPZT YAML references their names. Native HTTP URLs are redirected to the gateway. Existing HTTP headers move only to the upstream configuration, never to the gateway connection.

Import stops on unknown server fields, ambiguous roots, unsupported transport types, malformed arguments, and client interpolation in fields moved into YAML. For example, `${workspaceFolder}` in an upstream executable or `${input:token}` in an upstream HTTP header cannot safely be evaluated by the gateway. Configure that upstream manually rather than losing those semantics. Client-side interpolation in retained `env` or `cwd` remains in the client's context. TOML import is not implemented; use generation for Grok and Codex.

Review sandbox filesystem access after wrapping: the sandbox now needs to let the wrapper read its configuration and use its audit/approval storage. Imported HTTP header secrets remain in the generated upstream YAML if the source held literal secrets; keep that file private and convert those values to MCPZT secret references before sharing it. Review the generated development auth/policies before deployment.

## Grok: local host and hosted API are different integrations

**Grok Build** consumes the TOML generated with `--kind grok`. It also supports `grok mcp add --transport http NAME URL` and local stdio servers. MCPZT supports the host connection independently of which model Grok Build selects. See the [Grok Build MCP documentation](https://docs.x.ai/build/features/mcp-servers).

**xAI's API** has remote MCP tools in its native SDK and OpenAI-compatible Responses API. Point `server_url` at your publicly reachable, authenticated HTTPS MCPZT route, not at the upstream. Its documented fields include `server_label`, `authorization`, `headers` and tool allowlists. The OpenAI-compatible `require_approval` parameter is explicitly unsupported by xAI. A conceptual request fragment, assembled by your application, is:

```python
# `gateway_token` is acquired by your application; never commit a real token.
tool = {
    "type": "mcp",
    "server_label": "governed_tools",
    "server_url": "https://gateway.example/mcp/my-server",
    "authorization": gateway_token,
    "allowed_tools": ["search_records"],
}
```

Select the model in the xAI application using the provider's current supported model IDs; MCPZT neither chooses nor validates that model. See [xAI remote MCP documentation](https://docs.x.ai/developers/tools/remote-mcp). No xAI API request is made by the configuration generator.

## Other hosted provider APIs

OpenAI Responses API remote MCP tools use `server_url`, `server_label` and `authorization`. Its provider approval request/response mechanism is distinct from MCPZT approvals. See [OpenAI MCP and connectors](https://developers.openai.com/api/docs/guides/tools-connectors-mcp).

Claude's API MCP connector has its own server/toolset configuration and authentication token. A Claude Desktop or Claude Code snippet is not an API request. See [Claude API MCP connector](https://platform.claude.com/docs/en/agents-and-tools/mcp-connector).

Gemini CLI is an MCP host with its own JSON configuration; support for that host does not establish support for every Gemini API surface. See [Gemini CLI MCP configuration](https://geminicli.com/docs/tools/mcp-server/).

### Approval and protocol limits

MCPZT's high-risk workflow returns an approval ID, requires a human decision, and requires an exact approved retry with `_mcpzt_approval_id`. Provider-native approvals do not automatically satisfy this requirement. A hosted MCP integration needs an application/client adapter capable of that retry; discovery alone does not prove this workflow works. Do not advertise unattended high-risk use until the adapter is tested.

The HTTP runtime supports the documented JSON POST profile. GET streaming and upstream SSE are not supported. Stdio servers requiring server-initiated requests or interleaved notifications need additional transport support. Review the current audit and transport documentation before treating an arbitrary MCP server as compatible.

## Official format references

- [VS Code MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
- [Cursor MCP configuration](https://cursor.com/docs/mcp)
- [Codex MCP configuration](https://developers.openai.com/codex/mcp/)
- [Grok Build MCP configuration](https://docs.x.ai/build/features/mcp-servers)
- [Gemini CLI MCP configuration](https://geminicli.com/docs/tools/mcp-server/)
- [MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
