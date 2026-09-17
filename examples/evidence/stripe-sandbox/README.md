# Stripe sandbox configuration template

This folder supplies structurally valid configuration and an illustrative request preimage for the 0.6.0 adapter. It is **not** a runnable payment demo. The upstream URL and account/charge IDs are placeholders; no keys or credentials are provided.

Use the [external-check setup guide](../../../docs/EXTERNAL_CHECKS.md) to provision:

- A cooperating refund MCP destination that verifies the permit, deduplicates execution, produces the required signed receipt and supports read-only reconciliation. An arbitrary Stripe MCP server is not sufficient.
- Gateway/destination key trust for tenant `sandbox-tenant` and scope `stripe.refund.status.v1`, plus `gateway.key` and `trust.json`.
- A separate observer private key and `observers.json` matching `checker.json`.
- Client/upstream credentials and `MCPZT_STRIPE_TEST_KEY`, injected through the named environment variables. The checker accepts test keys only; configure the executing destination itself for test mode too.
- A real existing sandbox refund with the exact metadata bindings documented in the guide. Replace `acct_example` consistently in YAML, checker configuration, request and observer trust; use the actual charge ID and exact original request preimage.

Start from this directory so approval and evidence paths identify the same SQLite file; for deployment use identical absolute paths. Never run the template unchanged expecting a provider connection.

After the original operation has been recorded and its receipt obtained:

```sh
mcpzt evidence check OPERATION_ID --config mcpzt.yaml --server refund \
  --checker checker.json --request request-preimage.json
mcpzt evidence export OPERATION_ID --config mcpzt.yaml --server refund --output new-bundle-v2.json
mcpzt evidence verify new-bundle-v2.json --trust trust.json --observers observers.json
```

Checking is read-only. A timeout is not permission to resubmit the refund. This template's checker corroborates provider-reported status, not settlement or causal execution. To try the full flow without credentials, use `mcpzt evidence check-demo --directory /tmp/new-check-demo` and its explicitly simulated fixtures instead.
