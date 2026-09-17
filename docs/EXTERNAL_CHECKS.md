# External checks — MCPZT 0.6.0

A destination signature authenticates a statement. It does not establish that the statement is true. Version 0.6.0 adds read-only corroboration and a v2 export envelope containing the original v1 evidence plus an append-only chain of separately signed observer reports. It does not change the MCP wire extension or add a universal proof of execution.

For upgrade steps, timeout recovery and result/exit-code interpretation, see [evidence operations](EVIDENCE_OPERATIONS.md).

## Three separate questions

| Evidence | Supported interpretation |
| --- | --- |
| Gateway events | What the gateway recorded observing, including an attempted dispatch and an unavailable outcome. |
| Destination receipt | What the configured destination attests, bound to an authorization, request and attempt. |
| External check | What an observer found when querying a separately configured source at a particular time. |

The original verifier's `effect` remains **destination-attested**, explicitly labeled by `effect_basis`. `gateway_observation: not_in_bundle` means that neither a receipt nor a supplied response preimage establishes that the gateway observed the original response. Local `show` exposes the gateway's separate events.

An online check reports `basis: online_provider_query`. Offline verification authenticates an **observer attestation**: it does not authenticate the original HTTP response as a provider-signed document. Exported reports always retain `provider_signature: not_provided`, `independence: not_proven`, `history_completeness: unknown`, and `current_state: not_established_offline`. A successful verifier exit code authenticates the evidence, including evidence of a contradiction; it does not mean the operation succeeded.

Two keys, hosts or processes do not establish administrative independence. The observer trust file records `administration` as `shared`, `separate` or `unknown`; that is operator configuration, not a cryptographically established fact. Provider-signed portable evidence and independently witnessed state proofs are not implemented in this release.

## Reproduce a signed lie and timeout recovery

```sh
mcpzt evidence check-demo --directory /tmp/mcpzt-check-demo
mcpzt evidence verify /tmp/mcpzt-check-demo/bundle-v2.json \
  --trust /tmp/mcpzt-check-demo/trust.json \
  --observers /tmp/mcpzt-check-demo/observers.json \
  --request /tmp/mcpzt-check-demo/request-preimage.json
```

Use a new directory. The demo records a timeout, retrieves the destination's correctly bound signed `committed` receipt without repeating the action, and compares it with simulated provider responses. `comparison.json` lists these cases:

| Case | External result |
| --- | --- |
| Signed commit; source reports failure | `contradicted` |
| Matching operation; source reports success | `corroborated` |
| Subsequent source-reported failure | New `contradicted` observation; earlier success retained |
| Different amount | `contradicted` |
| Source reports pending | `pending` |
| Source returns 404 | `unknown`, not proof of no effect |

The directory also contains timeout and reconciliation snapshots, individual case bundles, public trust stores and a final v2 bundle. Private demo keys stay local with restricted permissions. All actors in this demo have shared administration; the provider is simulated with HTTPX MockTransport, no Stripe API is contacted, and no money moves. The generated `mcpzt.yaml` belongs to the original local ledger demo and is not a Stripe deployment configuration. Use the standalone exported files for comparison with other implementations. These are MCPZT fixtures, not AgentKey format or a claim of AgentKey interoperability.

## Stripe sandbox adapter

The first adapter checks the narrow scope `stripe.refund.status.v1`: whether Stripe currently reports the referenced refund's status and matching attributes. It does **not** establish settlement at the beneficiary, absence of later reversal, causal execution by this attempt, global uniqueness or honesty of Stripe.

Only test keys (`sk_test_` or restricted `rk_test_`) are accepted. Configure a dedicated read-only/restricted test credential where available. The adapter performs only:

1. `GET https://api.stripe.com/v1/account`, in the configured `Stripe-Account` context, to check the account identity.
2. `GET https://api.stripe.com/v1/refunds/{refund_id}` for the receipt's strictly validated `re_...` reference.

The API origin is fixed, TLS verification is enabled, environment proxies are disabled, redirects are not followed, and there are no automatic retries or business writes. API version `2024-06-20` is pinned. Response bodies are bounded to 1 MiB; requests have a 10-second HTTPX timeout. No receipt-supplied URL, trust key or credential is used.

The cooperating tool must accept exactly these arguments, committed by the original authorization:

```json
{"amount_minor":5000,"currency":"eur","charge":"ch_example","account":"acct_example"}
```

Its signed receipt must use scope `stripe.refund.status.v1`, effect `committed`, and the actual Stripe refund ID as `transaction_ref`. The destination's trusted key must be authorized for that scope. The operator's configured tool name, tenant, destination and account must match. The adapter checks the exact request preimage before any network access, then matches refund ID, charge, amount and currency. Pending destination receipts must first be reconciled; they cannot enter this committed-receipt check path.

The existing refund must have the following metadata, set by the cooperating integration:

```text
mcpzt_operation_id       = authorization.operation_id
mcpzt_authorization_id   = authorization.authorization_id
mcpzt_attempt_id         = attempt.attempt_id
mcpzt_request_digest     = authorization.request_digest
```

These fields provide correlation, **not causal proof**. An actor able to change provider metadata can relabel an existing record. Correctly bound metadata and matching amounts must not be interpreted as proof that this attempt caused the effect. Missing or mismatched metadata yields `unknown/BINDING_MISMATCH`. Reusing a different operation's signed receipt fails the v1 signature/binding verification before querying.

The adapter treats provider `succeeded` as corroborated for this scope; `failed` or `canceled` as a contradiction to the destination's committed claim; and `pending` or `requires_action` as pending. Unknown statuses, malformed responses, unavailable accounts, denied access, timeouts and missing records do not become success. The source's `created` time is recorded separately from the observer's local `checked_at`; neither is an independently trusted timestamp. A later failed state is preserved without rewriting the earlier observation or inventing a provider event time.

## Operator setup

Create a separate Ed25519 observer key. This Python example writes only the private file and prints the public key for your trust configuration:

```python
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp_zero_trust_layer.evidence.crypto import encode

key = Ed25519PrivateKey.generate()
with os.fdopen(os.open("observer.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
    f.write(encode(key.private_bytes_raw()))
print(encode(key.public_key().public_bytes_raw()))
```

Supply an independently managed `observers.json` (never accept a trust store from a bundle):

```json
{
  "version": 1,
  "keys": [{
    "kid": "observer-1", "issuer": "operations-checker",
    "tenant": "tenant-1", "destination": "refund-service",
    "source": "stripe", "scope": "stripe.refund.status.v1",
    "account": "acct_example", "public_key": "REPLACE_WITH_PUBLIC_KEY",
    "status": "active", "administration": "unknown"
  }]
}
```

Then create `checker.json`:

```json
{
  "version": 1, "adapter": "stripe_refund",
  "tenant": "tenant-1", "destination": "refund-service", "tool": "refund",
  "receipt_scope": "stripe.refund.status.v1", "account": "acct_example",
  "api_key_env": "MCPZT_STRIPE_TEST_KEY", "observer_key_id": "observer-1",
  "observer_private_key_file": "observer.key",
  "observer_trust_file": "observers.json", "freshness_seconds": 300
}
```

Replace illustrative identifiers with the cooperating integration's actual configuration. Key/trust paths resolve relative to `checker.json`; API credentials are read from the named environment variable and are not included in exports. The observer private key must have private permissions and must not be a symlink. It cannot reuse any configured gateway/destination public key. Revoked observer keys fail verification; retired keys can verify history but cannot create new checks.

```sh
mcpzt evidence check OPERATION_ID --config /path/mcpzt.yaml --server refund \
  --checker /path/checker.json --request /path/request-preimage.json
mcpzt evidence show OPERATION_ID --config /path/mcpzt.yaml --server refund \
  --observers /path/observers.json
mcpzt evidence export OPERATION_ID --config /path/mcpzt.yaml --server refund \
  --output /path/new-bundle-v2.json
mcpzt evidence verify /path/new-bundle-v2.json --trust /path/trust.json \
  --observers /path/observers.json
```

`check` exits 0 only for corroboration, 1 for a recorded non-corroborating result, and 2 for invalid prerequisites or inability to persist the check. Do not interpret a storage failure as a recorded observation. Checking never changes the original client response or undoes an effect.

## Envelope, retention and compatibility

`export` now defaults to v2; `--version 1` deliberately exports only the original destination evidence, excluding checks. `verify` accepts both formats. `schema` defaults to the original v1 schema; use `schema --version 2` for the wrapper and constrained observation payloads. Older verifiers require an explicit v1 export. No v1 signatures, cryptographic domains or MCP metadata keys change.

Each observation binds the exact v1 bundle and its predecessor's digest. Local writes use a SQLite transaction: concurrent appends cannot fork a history; one writer must explicitly check again. A v2 export contains at most 256 observations; at that limit, checks fail to persist until a future retention/export design is implemented. There is no silent eviction. Conflicting destination receipts continue to block normal export.

The separate signature domain is `UTF8("mcpzt.evidence.v2:external_observation:") || JCS({protected, payload})`; chain digests use SHA-256 over that prefix plus `UTF8("chain:") || JCS(signed_observation)`. The evidence digest uses the existing v1 digest helper with kind `checked_bundle`. Source-response commitments use kind `external_source` with a random nonce; raw provider bodies are not exported or stored. Commitments and identifiers are still potentially sensitive, not anonymized data.

Offline `fresh` compares the signed observation's time interval with the verifier's local clock. It neither authenticates a timestamp nor proves current provider state. Truncating a suffix of valid observations cannot be detected without an independently retained checkpoint: `history_completeness` remains unknown. Keep original exports and backups; never treat a signed report as proof that all checks have been supplied.

## Validation

`tests/evidence/test_checks.py` covers dishonest signed destinations, request/receipt substitution, mismatched amounts/currencies/accounts/charges, metadata binding, provider state changes, 404/429/5xx, redirects, timeouts, malformed and oversized bodies, key authority/revocation, immutable history, concurrent append rejection, CLI exports and real local HTTP GET traffic. Existing v1 tests remain in place.

An opt-in test checks an **existing**, correctly bound Stripe sandbox refund without creating anything:

```sh
MCPZT_STRIPE_SANDBOX_DIRECTORY=/private/sandbox-fixtures \
  python -m pytest tests/integration/test_stripe_sandbox.py -q
```

That directory must contain `bundle.json` (v1), `request.json` (canonical preimage), `trust.json`, `checker.json`, and configured observer key/trust files. Set the API-key environment variable securely beforehand. Without this directory the test is explicitly skipped; local mocks and HTTP fixtures do not count as a successful live sandbox run.

Provider references: [retrieve a refund](https://docs.stripe.com/api/refunds/retrieve), [refund object and statuses](https://docs.stripe.com/api/refunds/object), [connected account request context](https://docs.stripe.com/api/connected-accounts).
