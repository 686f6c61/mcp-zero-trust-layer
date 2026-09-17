# Frozen MCPZT 0.6.0 comparison fixtures

These synthetic fixtures contain public keys, signed commitments and a synthetic request preimage. No private keys or provider credentials are included. The provider was simulated; no payment API was contacted and no money moved. All actors had shared administration. These files are not an AgentKey format or an interoperability certification.

Start with `timeout-record.json`: the gateway recorded an unavailable outcome. `bundle-at-timeout.json` contains authorization/attempt only. `bundle-after-reconciliation.json` contains the destination's signed committed claim, recovered without a second tool call.

Each v2 case adds an observer's statement about a simulated source query:

| File | Expected latest reported result |
| --- | --- |
| `signed-lie.json` | contradicted: source status failed |
| `corroborated.json` | corroborated: matching source status succeeded |
| `later-failure.json` | contradicted: later failure, earlier report preserved |
| `wrong-amount.json` | contradicted: amount mismatch |
| `pending.json` | pending |
| `not-found.json` | unknown, not proof of no effect |

`bundle-v2.json` is the final six-observation history; `comparison.json` includes the method trace and expected outcomes. `request-preimage.json` is synthetic input and should not be confused with a production export's confidentiality guarantees.

```sh
mcpzt evidence verify examples/evidence/external-checks/bundle-v2.json \
  --trust examples/evidence/external-checks/trust.json \
  --observers examples/evidence/external-checks/observers.json \
  --request examples/evidence/external-checks/request-preimage.json
```

Verification authenticates an observer report, not Stripe's signature. Fixture freshness intervals are historical and naturally expire. No external current-state or completeness claim is made. Compare the observation, attestation, binding, authority, freshness and claim limits with any matching implementation.

Regenerate a separate set (new keys and IDs) with `mcpzt evidence check-demo --directory /tmp/new-check-fixtures`. Do not publish the generated directory wholesale: it also contains private demo keys and local databases. These frozen files are intentionally stable and checked by regression tests, including independent Node.js signature and chain-digest verification.
