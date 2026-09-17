# Examples and compatibility with 0.6.0

These examples cover different layers. Ordinary upstream servers do not acquire receipt support merely by upgrading the gateway.

| Example | What it demonstrates | Prerequisites | Evidence mode |
| --- | --- | --- | --- |
| [github-readonly](github-readonly/mcpzt.yaml) | Reads, approval for merges, default deny | Your HTTP JSON MCP endpoint; illustrative `github.*` tool names | Off |
| [postgres-readonly](postgres-readonly/mcpzt.yaml) | Read-only SQL validation | Your HTTP JSON MCP endpoint with `postgres.query` | Off |
| [filesystem-safe](filesystem-safe/README.md) | Real pinned filesystem server; bounded reads and approval for writes | Node.js/npm, POSIX; run from its example directory | Off |
| [protected-http-upstream](protected-http-upstream/mcpzt.yaml) | Separate client API key and private upstream credential | `MCPZT_API_KEY`, `GITHUB_MCP_TOKEN`, actual endpoint | Off |
| [oidc-gateway](oidc-gateway/mcpzt.yaml) | Verified group authorization, redaction, SQLite approvals | Replace issuer/hosts/endpoints; upstream tokens and `MCPZT_AUDIT_HMAC_KEY`; writable state directories | Off |
| [multi-mcp](multi-mcp/mcpzt.yaml) | Routing, per-server rules, approvals, SQL/path validation and CRM redaction | Four HTTP JSON upstreams; integration tests supply local peers | Off |
| `mcpzt demo --output /tmp/new-http-demo` | Runnable local HTTP gateway plus synthetic upstream | Installed MCPZT and Python; execute generated `run_demo.sh` | Off |
| `mcpzt evidence demo --directory /tmp/new-ledger-demo` | Real stdio ledger, destination receipts, offline verification | Installed MCPZT; creates local keys and SQLite state | Required, v1 wire |
| [external-checks](evidence/external-checks/README.md) | Frozen public timeout/contradiction fixtures, offline observer verification | No provider credential; bundled public trust is for synthetic fixtures only | V1 evidence inside v2 exports |
| `mcpzt evidence check-demo --directory /tmp/new-check-demo` | Fresh adversarial fixtures with simulated provider queries | Installed MCPZT; no Stripe API call or money movement | Observer attestations, not provider signatures |
| [Stripe sandbox template](evidence/stripe-sandbox/README.md) | Configuration for a cooperating real sandbox integration | Your receipt-aware upstream, keys/trust, test account and read-only test credential | Required plus external checks |

## Validate and exercise

From the repository root after installing `.[dev]`:

```sh
mcpzt config validate --config examples/multi-mcp/mcpzt.yaml
python -m pytest tests/integration/test_repository_examples.py tests/integration/test_multi_mcp_use_cases.py -q
python -m pytest tests/evidence -q
```

The tests load the actual YAML files. Temporary paths and local endpoints replace deployment locations; policies are not duplicated in test code. The OIDC tests use locally generated JWTs/JWKS, not a live identity provider. The protected-upstream test checks actual HTTP headers. The filesystem test uses the official npm package when installed, as it is in CI; see its README to enable it locally. The Stripe sandbox test remains opt-in and does not create a refund.

`config validate` checks structure, not remote reachability, tool names or truthful effects. `config lint` reports intentional warnings for unauthenticated local demos and semantic starter rules; those are not production certification. Discovery must confirm the exact names of real upstream tools. The `github.*`, `postgres.*`, `filesystem.*` and `crm.*` names in HTTP examples are illustrative contracts, not names guaranteed by arbitrary vendors. The filesystem stdio example is different: it pins and tests a concrete upstream implementation with unprefixed names.

## Protocol and security boundaries

Examples explicitly permit only `initialize` and `ping` as lifecycle methods. A tool named `initialize` does not inherit those permissions. Unknown business tools remain denied. For filesystem stdio, advertise `capabilities: {}` during initialization: this gateway profile does not support server-initiated Roots requests.

Relative validator paths resolve against the config directory; a subprocess inherits its launch working directory. Run the filesystem example as documented, or use matching absolute paths on both sides. State/audit paths follow their documented runtime rules. Never assume config validation proves those paths coincide.

An output redaction rule must not accidentally authorize a caller who failed the inbound group/input checks. The OIDC example restricts redaction to `support` and to existing output; CRM examples redact all returned payloads, including an API key without an email field.

Evidence stays off in the six original configurations. Enabling required receipts requires a cooperating destination, separate configured trust, and shared private SQLite approval/evidence storage; it is not a one-line upgrade for arbitrary MCP servers. The generic ledger receipt's scope is not the Stripe refund-status scope. Offline v2 verification authenticates an observer statement, not the original gateway response or a provider signature.
