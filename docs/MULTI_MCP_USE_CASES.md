# Multi-MCP Use Cases

This guide explains the public multi-server scenario shipped with MCP Zero Trust Layer. It is written for teams that want to understand what happens when one MCPZT process protects several MCP servers at the same time.

The short version is simple: each upstream MCP server keeps doing its own job, while MCPZT becomes the common enforcement point. The client talks to MCPZT. MCPZT identifies the logical server, evaluates policy, validates arguments, handles approvals, redacts output when needed, writes audit events, and only then decides whether the real upstream should see the request.

The example is intentionally practical. It uses four logical MCP servers because that is closer to real adoption than a single toy server. A product engineering team may use GitHub for repository operations, Postgres for analytics or application data, a filesystem MCP for project files, and a CRM MCP for customer records. Those servers should not share the same risk model.

## Topology

```text
MCP client
  |
  v
MCP Zero Trust Layer
  |
  |-- POST /mcp/github     -> GitHub MCP upstream
  |-- POST /mcp/postgres   -> Postgres MCP upstream
  |-- POST /mcp/filesystem -> Filesystem MCP upstream
  `-- POST /mcp/crm        -> CRM MCP upstream
```

The route determines the logical server. A request sent to `/mcp/github` is evaluated against policies for the `github` server and then, if allowed, forwarded to the GitHub upstream. A request sent to `/mcp/postgres` is evaluated separately and forwarded to the Postgres upstream. This route-level separation is what prevents policies for one MCP from accidentally authorizing another MCP.

The integration test uses local fake HTTP MCP upstreams. That keeps the test deterministic and credential-free, but it still exercises the real MCPZT HTTP app, the real policy pipeline, the real validators, the real approval store, the real output enforcer, and the real HTTP upstream client.

## Example Config

The versionable starter config lives at [examples/multi-mcp/mcpzt.yaml](../examples/multi-mcp/mcpzt.yaml). It defines four logical servers.

`github` represents repository operations. It has a low-risk read tool, a critical merge tool, and a critical delete tool. The read tool is allowed. The delete tool is denied and hidden. The merge tool remains discoverable because it is legitimate, but it requires approval before execution.

`postgres` represents a database MCP. It exposes a query tool and an administrative drop-table tool. MCPZT allows read-only SQL through the query tool after validation, and hides the administrative tool from discovery.

`filesystem` represents local or project file access. It allows a safe project resource and a file-read tool constrained by an allowed root. Attempts to read outside the configured root are blocked before upstream.

`crm` represents confidential customer data. The customer lookup is allowed, but sensitive fields in the upstream response are redacted before the client receives them.

This shape matters because it proves that MCPZT is not just a single-server proxy. It can enforce different rules for different tools, resources and data classes in one project.

## Behavior Walkthrough

The first behavior is capability filtering. When a client asks GitHub for `tools/list`, the upstream may return `github.search_issues`, `github.merge_pull_request` and `github.delete_repository`. MCPZT returns only the tools that policy permits the client to know about. Search is visible because it is allowed. Merge is visible because it can proceed with approval. Delete is hidden because it is denied.

Postgres behaves differently. The query tool is visible, but the administrative drop-table tool is hidden. Filesystem resource discovery also gets filtered: the safe project README is visible, while `file:///etc/passwd` is hidden.

The second behavior is safe routing. A GitHub search reaches only the GitHub upstream. A Postgres `SELECT` reaches only the Postgres upstream. The filesystem and CRM upstreams are not touched by those calls. That seems obvious, but it is essential in a multi-MCP gateway: routing mistakes are authorization bugs.

The third behavior is argument validation before side effects. A Postgres `DELETE` is rejected by the SQL read-only validator before the Postgres upstream receives anything. A filesystem read for `/etc/passwd` is rejected by the filesystem path validator before the filesystem upstream receives anything. In both cases, the upstream request count stays at zero.

The fourth behavior is human approval for sensitive actions. The GitHub merge call into `main` does not reach upstream on the first attempt. MCPZT creates an approval request and returns an `approval_id`. After a human approves that ID, the client retries with `_mcpzt_approval_id`. MCPZT checks that the approved request still matches the original identity, server, capability, policy and argument hash. It then strips `_mcpzt_approval_id` before forwarding the call upstream.

The fifth behavior is output enforcement. The CRM upstream returns customer data containing `email` and `api_key`. MCPZT allows the call but redacts those fields from the result. This is a different control from input authorization: sometimes the request is legitimate, but the returned data still needs to be shaped before a model or agent sees it.

## Scenario Matrix

| Server | Scenario | Expected behavior | Test evidence |
| --- | --- | --- | --- |
| `github` | List tools | Search and merge are visible; repository delete is hidden | `test_multi_mcp_filters_capability_lists_per_server` |
| `github` | Search issues | Request is allowed and routed only to GitHub | `test_multi_mcp_allows_safe_calls_and_routes_to_the_right_upstream` |
| `github` | Merge pull request into `main` | First call creates an approval; approved retry reaches upstream; approval ID is stripped | `test_multi_mcp_requires_human_approval_for_sensitive_action` |
| `postgres` | List tools | Query is visible; drop-table is hidden | `test_multi_mcp_filters_capability_lists_per_server` |
| `postgres` | Run `SELECT` | Query is allowed and routed only to Postgres | `test_multi_mcp_allows_safe_calls_and_routes_to_the_right_upstream` |
| `postgres` | Run `DELETE` | Query is blocked before upstream by `sql_read_only` | `test_multi_mcp_blocks_dangerous_arguments_before_upstream` |
| `filesystem` | List resources | Project README is visible; `/etc/passwd` is hidden | `test_multi_mcp_filters_capability_lists_per_server` |
| `filesystem` | Read outside allowed root | Request is blocked before upstream by `filesystem_path` | `test_multi_mcp_blocks_dangerous_arguments_before_upstream` |
| `crm` | Read customer | Request is allowed; `email` and `api_key` are redacted in output | `test_multi_mcp_redacts_sensitive_upstream_output` |

## Running The Scenario

Install the project in editable mode before running the test.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

Validate the example config. This confirms that the YAML is structurally valid and that policy, server, audit and approval settings can be loaded.

```bash
mcpzt config validate --config examples/multi-mcp/mcpzt.yaml
```

Run the integration test.

```bash
python -m pytest tests/integration/test_multi_mcp_use_cases.py -q
```

The expected result is:

```text
5 passed
```

The test does not need real GitHub, database, filesystem or CRM credentials. It starts fake local upstreams so the behavior is reproducible in CI.

## Manual HTTP Shape

In a real deployment, the client sends JSON-RPC over HTTP to a route for the selected logical server.

```bash
curl -s http://127.0.0.1:8765/mcp/github \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

A tool call follows the same route.

```bash
curl -s http://127.0.0.1:8765/mcp/postgres \
  -H 'content-type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "postgres.query",
      "arguments": {"query": "select id, title from issues"}
    }
  }'
```

The route and the tool name both matter. The route selects the logical MCP server. The tool name selects the capability within that server. Policies can match either exact capability names or semantic mappings such as `action`, `risk`, `access`, `resource_type` and `data_classification`.

For a real client, generate config that points the client at MCPZT routes instead of upstream routes. The generated JSON creates one client-visible MCP server per logical route.

```bash
mcpzt client config \
  --config examples/multi-mcp/mcpzt.yaml \
  --base-url http://127.0.0.1:8765 \
  --kind claude-desktop
```

The important detail is the URL shape. A GitHub client entry points to `/mcp/github`, Postgres points to `/mcp/postgres`, filesystem points to `/mcp/filesystem`, and CRM points to `/mcp/crm`. That keeps client configuration simple while leaving policy isolation in MCPZT.

## Translating To A Real Deployment

Replace the example upstream URLs with private internal MCP endpoints.

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

Keep those upstreams private. If clients can still connect directly to `https://github-mcp.internal/mcp`, they can bypass MCPZT entirely. The secure shape is that clients can reach MCPZT, and MCPZT alone can reach the upstream MCP servers.

Use capability discovery when onboarding each real server.

```bash
mcpzt discover --server github --config mcpzt.yaml
mcpzt diff --server github --config mcpzt.yaml
mcpzt scan --config mcpzt.yaml --snapshot .mcpzt-capabilities/github.json
```

Treat newly discovered tools as a review event. A new read-only tool may need only a mapping. A new write, delete, payment, email, deploy or admin tool should usually start as denied or approval-gated.

When a multi-server policy behaves unexpectedly, use `policy explain` against the exact route and capability. In multi-MCP projects, many false assumptions come from matching the wrong logical server or relying on metadata that was only mapped for another server.

```bash
mcpzt policy explain \
  --config mcpzt.yaml \
  --server postgres \
  --method tools/call \
  --capability postgres.query \
  --arguments '{"query":"select * from customers"}'
```

The explanation output shows whether the `postgres` mapping was found, which policies matched and why other policies were skipped. That matters because `github` and `postgres` may both have a concept of "read", but they should not accidentally share broad rules unless you intentionally write a cross-server policy.

## Audit Signals To Expect

A healthy multi-MCP rollout should produce audit events that make each decision explainable. For allowed calls, audit should show the selected server, capability, policy ID and `upstream_called: true`. For denied validator failures, audit should show the validator error and `upstream_called: false`. For approval-required actions, audit should show the approval request before upstream execution and the approved retry later.

Those details are what make incident review possible. If a customer record was read, you should be able to answer which client called which logical server, which policy allowed it, whether the response was redacted, and whether the upstream was contacted.

The same scenario should also produce useful metrics if the HTTP runtime is used. A dashboard can show allow, deny and approval counts by logical server. A spike in denied Postgres queries may mean a bad prompt, a broken client integration or an attempted misuse. A spike in approval requests for GitHub merges may be normal during release day, but unusual outside a deployment window.

For local JSONL audit files, run hash-chain verification during review or before archiving logs.

```bash
mcpzt audit verify --config mcpzt.yaml
```

## What This Scenario Does Not Prove

The test proves policy isolation, routing, validation, approval binding and output redaction across multiple HTTP MCP upstreams. It does not prove that your real upstream credentials are least-privilege, that your network prevents bypass, that your identity provider issues correct claims, or that every tool in your organization has been mapped correctly.

Those controls belong in production rollout. Use [PRODUCTION.md](PRODUCTION.md) for the deployment posture around authentication, network access, logging, approvals, drift management and release operations.

It also does not prove that every new capability is safe after an upstream upgrade. That is why discovery snapshots, `mcpzt diff`, `mcpzt scan` and human review belong in the normal operating loop for multi-MCP projects.
