# Evidence operations and upgrading to 0.6.0

This guide covers operator actions for evidence-enabled servers. It complements the [wire/signature contract](EVIDENCE.md) and [external-check adapter](EXTERNAL_CHECKS.md). These commands require authorized access to the local configuration and state; they are not public client tools.

## Upgrade from 0.5.0

| Surface | 0.6.0 behavior | Operator action |
| --- | --- | --- |
| MCP metadata and v1 signed documents | Unchanged v1 profile | Keep the existing destination implementation and its configured scope |
| Existing evidence mode | Remains opt-in | Do not enable evidence or the Stripe checker on unrelated upstreams |
| Export command | Defaults to a v2 wrapper, even with no observer reports | Update consumers, or explicitly use `--version 1` for old verifiers |
| Schema command | Still defaults to v1 | Use `schema --version 2` when validating the default export |
| Observer trust | Separate from gateway/destination trust | Supply `--observers` when verifying a bundle containing reports |
| SQLite | Adds `evidence_v2_observations` on initialization | Back up the database consistently, including its private persistent salt; preserve permissions |
| External checking | Explicit operator command | Configure a compatible scope, source, request preimage and separate observer key first |

Before changing a deployment, pause new dispatches and take a consistent backup of state and its associated configuration. Keep gateway/destination keys and the existing database in place; do not create an empty database as an upgrade step. This release does not rewrite v1 signatures. Any simultaneous policy, server or evidence-mode change can invalidate pending approval bindings; request new approvals when those bindings change.

Test the new verifier and consumers against a copy of your exports. A v1 export omits observer reports; it is a compatibility projection, not a lossless archive. Retain the v2 history and database backup separately. Rolling back an executable does not make old verifiers understand v2 evidence. Do not restore an earlier deduplication database while continuing dispatch: it can make already executed operations look new.

## Choose the right command

| Command | Reads or changes | What successful execution means |
| --- | --- | --- |
| `show` | Reads local evidence and gateway events | The command could display the record; inspect its nested verdict and rejection |
| `reconcile` | Queries the configured destination and records a returned receipt | A lookup was performed; inspect the returned receipt/verdict rather than assuming a business success |
| `check` | Queries the configured source and appends a signed observation | Exit 0 means the online check corroborated within its configured scope |
| `export` | Writes a new private bundle file | A snapshot was written; it does not establish business success or history completeness |
| `verify` | Checks a supplied bundle against public trust offline | Exit 0 means the evidence verified at the reported level, including authentic evidence of failure or contradiction |

`show` is not an automation gate for the verdict: inspect `verdict.rejection`, `verdict.claim` and the external-check fields. Supplying a v2 bundle with reports but no independently configured observer trust cannot authenticate those reports.

## Recover a timeout

1. Keep the operation ID from the `-32051` response. The effect is unknown; do not repeat the business call to find out what happened.
2. Read local gateway events with `show`. An authorization-only export does not contain those events and cannot prove that the gateway attempted dispatch.
3. Run `reconcile` against the same configured destination. It sends `mcpzt/evidence/get`, not another `tools/call`.
4. If a receipt is recovered, inspect its scope, claim and effect. A destination claim of `committed` is still destination-reported.
5. Only if the operation satisfies the configured adapter's prerequisites, run `check` with the exact request preimage. The current adapter accepts a committed refund receipt within `stripe.refund.status.v1`; it is not a generic checker for arbitrary tools.
6. Export a new v2 snapshot and verify it using separately configured trust stores. Keep earlier snapshots.

```sh
mcpzt evidence show OPERATION_ID --config /private/mcpzt.yaml --server refund
mcpzt evidence reconcile OPERATION_ID --config /private/mcpzt.yaml --server refund
mcpzt evidence check OPERATION_ID --config /private/mcpzt.yaml --server refund \
  --checker /private/checker.json --request /private/request-preimage.json
mcpzt evidence show OPERATION_ID --config /private/mcpzt.yaml --server refund \
  --observers /private/observers.json
mcpzt evidence export OPERATION_ID --config /private/mcpzt.yaml --server refund \
  --output /private/new-bundle-v2.json
mcpzt evidence verify /private/new-bundle-v2.json --trust /private/trust.json \
  --observers /private/observers.json --request /private/request-preimage.json
```

The paths and operation ID above are placeholders for an existing configured operation. `check` can legitimately exit 1 when it records a pending, unknown or contradicted result. A shell script using `set -e` must handle that outcome explicitly before continuing with export or incident handling.

## Interpret the result without flattening it

| Signal | Interpretation | Next step |
| --- | --- | --- |
| `check`: exit 0 / `corroborated` | The source query matched within the configured scope at check time | Retain the report and its scope/time; do not infer settlement or unique execution |
| `check`: exit 1 / `contradicted` | A source observation conflicts with the destination claim or expected fields | Inspect the reason and investigate; do not automatically retry or reverse the business action |
| `check`: exit 1 / `pending` | The source reports an intermediate state | A later explicit read-only check may add a newer observation |
| `check`: exit 1 / `unknown` | The source could not establish the requested state | Inspect the reason; missing records or binding data do not prove absence of an effect |
| `check`: exit 2 / `CHECK_UNAVAILABLE` | Prerequisites, trust, existing history or persistence prevented completion | Inspect state and configuration; do not assume a report was stored |
| `verify`: exit 0 | Cryptographic/authority/binding checks passed at the reported level | Inspect the claim, effect, latest reported result, freshness and trust limits |
| `verify`: exit 1 | The verifier rejected the evidence | Do not treat its claims as authenticated |
| `verify`: exit 2 | Input or trust configuration could not be loaded/validated | Correct the supplied files before drawing a conclusion |

In a verified v2 bundle, `external_check.result` is `observer_attested`, not the business outcome. The sequence of reported outcomes is in `external_check.history[*].reported_result`; read the last entry for the latest supplied report, and retain earlier entries when reviewing a change. An empty history means no external report was supplied.

`fresh: false` does not necessarily mean a signature is invalid: the report is outside its signed interval according to the verifier's local clock. Even `fresh: true` does not establish a trusted timestamp or the provider's present state. The observer's `checked_at` and the source's `source_recorded_at` have different meanings; neither supplies an independent trusted clock.

## Common operational limits

- **Conflicting receipts:** normal export is blocked. Preserve state and investigate the destination; do not edit receipts or delete the conflict to make a check pass.
- **Concurrent append:** a report may fail to persist because another report became the head of the chain. Read the current history before explicitly checking again. The failed command is not evidence that its observation was recorded.
- **256 reports:** the history is full and new checks fail before querying. There is no silent eviction or supported pruning workflow in 0.6.0. Keep the history; plan retention before reaching the limit.
- **Key rotation/revocation:** trust is operator-managed. Keep nonrevoked public keys for required historical verification, replace compromised keys according to your incident process, and deliberately restart/reload services that snapshot trust. A signed local timestamp does not prove a receipt predates compromise.
- **Raw preimages:** bundles do not contain original arguments or raw provider bodies. The Stripe adapter needs the exact authorized request separately; a reconstructed or normalized request may not match. Store any retained preimages with access appropriate to their contents.
- **Truncated history:** a valid supplied chain can omit a suffix. Independently retained checkpoints are needed to detect that omission; a bundle alone reports completeness as unknown.

## Reproduce safely without provider credentials

```sh
mcpzt evidence check-demo --directory /tmp/new-mcpzt-060-demo
mcpzt evidence verify /tmp/new-mcpzt-060-demo/bundle-v2.json \
  --trust /tmp/new-mcpzt-060-demo/trust.json \
  --observers /tmp/new-mcpzt-060-demo/observers.json \
  --request /tmp/new-mcpzt-060-demo/request-preimage.json
mcpzt evidence schema --version 2 > /tmp/mcpzt-evidence-v2.schema.json
```

Use a new demo directory. The provider is simulated and no money moves. The generated directory also contains private demo keys; share only the reviewed public fixture/export files. For ready-made public records, see the [frozen comparison set](../examples/evidence/external-checks/README.md).
