# Destination receipts — experimental v1 profile (MCPZT 0.6.0)

MCPZT 0.6.0 preserves this v1 wire/signature profile and adds [read-only external checks and v2 exports](EXTERNAL_CHECKS.md). Export now defaults to a v2 wrapper; use `--version 1` for an older verifier. Offline observer attestations never become provider-signed proof of execution.

MCPZT can bind an authorization to a dispatched tool call and verify a receipt signed by a cooperating destination. The feature is opt-in per upstream. It does not make an arbitrary MCP server produce receipts, and signing a gateway log is not independent confirmation of a business effect.

For migration, command selection and incident handling, see [evidence operations](EVIDENCE_OPERATIONS.md). The v1 wire profile was introduced in 0.5.0 and remains unchanged.

## Try the complete local flow

```sh
mcpzt evidence demo --directory /tmp/mcpzt-receipts-demo
mcpzt evidence verify /tmp/mcpzt-receipts-demo/bundle.json \
  --trust /tmp/mcpzt-receipts-demo/trust.json
```

Use a new directory. The demo refuses to overwrite keys or state. It generates separate Ed25519 gateway/destination keys and launches a real stdio destination, initializes MCP, allows a 5,000-minor-unit refund and denies a 50,000-minor-unit refund. The demo gateway allowlists the 5,000 example; the destination independently caps refunds at 10,000. One row in the destination's SQLite ledger is checked independently of the receipt. **No payment provider is contacted and no money moves.**

The printed operation ID can be used with the generated config:

```sh
mcpzt evidence show OPERATION_ID --config /tmp/mcpzt-receipts-demo/mcpzt.yaml --server refund
mcpzt evidence reconcile OPERATION_ID --config /tmp/mcpzt-receipts-demo/mcpzt.yaml --server refund
mcpzt evidence export OPERATION_ID --output /tmp/private-bundle.json \
  --config /tmp/mcpzt-receipts-demo/mcpzt.yaml --server refund
mcpzt evidence schema
```

These are **local operator commands**, authorized by access to the configuration, signing key and database. There is no unauthenticated gateway HTTP endpoint for exporting another user's evidence. Export files are created with mode 0600, without overwriting files. Exports contain signed commitments, not raw tool arguments/results. The verifier needs only the bundle and an independently supplied public trust store, not private keys, running services or network access.

## Meaning of the result

The verifier reports integrity, authority, binding, content verification and the supported claim separately. Exit status 0 means the supplied evidence verified at its reported level; an authorization-only bundle can verify with an unknown effect. Inspect `claim` and `effect`, not only the process exit status. Exit 1 means evidence verification failed; exit 2 means the input or trust file could not be loaded.

| Claim | Meaning |
| --- | --- |
| `authorization_recorded` | A trusted gateway signed an allow authorization and bound attempt. Does not prove dispatch. |
| `destination_receipt_verified` | A configured destination signed a correctly bound receipt for a trusted scope. |
| `destination_commit_attested` | That destination attests a committed effect in the configured scope, with a transaction reference. |

`effect` is independent: `unknown`, `pending`, `committed`, `rejected`, `failed`, or `partially_committed`. Failure does not necessarily mean no side effects. HTTP 200, JSON-RPC success and `isError: false` do not imply a business commit.

`request_content` and `response_content` default to `not_provided`: validating a signature over a hash is not checking the raw content against that hash. Operators holding the exact preimages can pass `--request request-preimage.json --response response-preimage.json`. The live gateway checks the response preimage before output filtering. A typed SDK may add defaults or otherwise normalize a response; use the original preimage, not a reconstructed normalized object.

The verifier always reports `completeness: unknown`, `execution_uniqueness: not_proven`, and `trusted_timestamp: false`. A bundle cannot prove that no other call occurred, that every event was exported, or that the destination clock is independently trustworthy. The reference database provides local deduplication; a portable receipt alone does not prove global exactly-once execution.

## Configuration

The generated demo configuration is executable. For an existing cooperating upstream, add:

```yaml
approvals:
  backend: sqlite
  path: /var/lib/mcpzt/evidence.sqlite3
audit:
  strict: true
  path: /var/lib/mcpzt/audit.jsonl
servers:
  - name: ledger
    transport: http
    upstream: https://ledger.internal/mcp
    evidence:
      mode: required
      issuer: gateway-1
      destination: ledger-1
      tenant: tenant-1
      scope: your-ledger-contract.v1
      key_id: gateway-key-1
      private_key_file: /run/secrets/gateway-signing.key
      trust_store: /etc/mcpzt/evidence-trust.json
      store: /var/lib/mcpzt/evidence.sqlite3
      ttl_seconds: 60
```

Supply actual keys and a trust store; the names above are illustrative. Private key files contain an unpadded base64url Ed25519 32-byte seed, with private permissions. Never put private key material in YAML or command-line arguments. Evidence-specific paths resolve relative to the config directory; the existing approvals path still follows the existing working-directory convention. Prefer absolute paths to make the required database equality unambiguous.

Modes:

- `off` (default): existing gateway behavior, without evidence state or signing keys.
- `observe`: emits permits for a configured destination and records whether its receipt verified; a missing/invalid receipt does not block the otherwise permitted response.
- `required`: requires configured signing/trust material and durable state before dispatch, then a valid receipt before releasing a successful tool response.

Both enabled modes require enforce mode, strict audit, and the **same private SQLite file** for approvals and evidence. Initialization rejects a public-readable database. Existing approval files need an explicit migration; enabling evidence invalidates earlier approval bindings, so request new approvals. Off-mode binding retains the 0.4 server projection.

The gateway cannot know in advance whether a destination will actually return a valid receipt. **Failure after dispatch cannot undo the effect.** Error `-32050` means prerequisites failed before dispatch; `-32051` means evidence/outcome is unavailable with an operation ID and an unknown effect; `-32052` means the operation was already reserved. Do not automatically repeat any operation after reservation. Successful operation IDs are available in the local evidence events/audit projection; tool results are not decorated with raw receipts or hashes.

## Frozen wire and cryptographic contract

This is an MCPZT extension, not an MCP standard or AgentKey production format. The extension key is `io.github.mcp-zero-trust-layer/evidence-v1`. Permits travel in `params._meta[KEY]`; successful receipts in `result._meta[KEY]`. JSON-RPC errors use `error.data._meta[KEY]` by this profile's explicit convention. For an error lacking `data`, a cooperating signer must commit to `data: {}` before adding metadata; do not silently change its preimage while adding a receipt.

The canonical preimages are defined in `evidence/protocol.py` and the strict models in `evidence/models.py`. `mcpzt evidence schema` exports the bundle JSON Schema, including payload constraints selected by signed document type. The verifier also checks cross-document relationships that JSON Schema cannot express.

Signatures use Ed25519 through `cryptography`. Canonicalization uses the `rfc8785` implementation of JCS. Bytes to sign are:

```text
UTF8("mcpzt.evidence.v1:signature:") || JCS({"protected": HEADER, "payload": PAYLOAD})
```

The protected header has exactly `version: 1`, `alg: "Ed25519"`, `kind` (`authorization`, `attempt`, `receipt`) and `kid`. The signature is unpadded base64url. Unknown header/payload members and unsupported versions/algorithms are rejected. A `kid` is an identifier, not authority.

All domain-separated digest bytes are:

```text
SHA256(UTF8("mcpzt.evidence.v1:" + KIND + ":") || JCS({"nonce": NONCE, "value": VALUE}))
```

Digests use lowercase hex. Domain kinds are `authorization`, `attempt`, `request`, `response`, and `client_response`. Authorization/attempt document digests use an empty nonce; request and response commitments use separate random 32-byte hex nonces. The `attempt_digest` in a receipt commits to the complete permit, including both signed documents.

Request content includes the exact method and complete params. Only this extension's evidence and idempotency metadata are removed; an empty `_meta` after their removal is omitted. Other metadata remains committed. Missing params normalize to `{}`. Approval control fields are removed by the gateway before signing. JSON-RPC transport IDs and authentication headers are excluded. Tool arguments are never rewritten to carry evidence.

Response content is exactly `{"result": ORIGINAL_RESULT}` or `{"error": ORIGINAL_ERROR}`, with only the receipt metadata removed and its now-empty `_meta` omitted. Raw and filtered response commitments are different events. The filtered response is recorded as prepared, not delivered or read by the client.

The existing HTTP upstream handles non-2xx status as a transport error, not as a receipted JSON-RPC response. Cooperating HTTP destinations return receipted JSON-RPC errors in a JSON response accepted by that transport profile; an HTTP failure instead leaves recovery to the read-only lookup path.

Evidence values are bounded to 1 MiB canonical JSON and depth 32; IDs/text fields to 256 characters. JCS rejects nonfinite numbers, invalid Unicode and integers outside its safe numeric range. No silent conversion to strings is performed. Ingress JSON rejects duplicate keys and explicit NaN/infinity before they can be discarded or accepted by the parser. Other existing transport byte/deadline limits still apply. The evidence profile can therefore reject JSON accepted by an upstream's more permissive parser.

## Destination integration

Use the signing, verification, schema and protocol helpers as the integration primitives; `RefundDestination` is an executable reference, not a generic payment adapter.

Before executing, a destination must verify the gateway permit with its own trust store and current admission time, check audience/tenant, tool and the exact request digest, and atomically deduplicate the operation. Authorizations last 1–300 seconds. A new attempt cannot silently replace the one already bound to an operation in the reference destination.

Commit the business change, result and receipt material in the **same transaction** wherever the backend permits. Sign persisted material after commit and store the immutable receipt. A signing failure leaves recoverable material and must not trigger another business operation. In the reference implementation this transaction is the actual SQLite ledger transaction; it does not span an external API.

The receipt commits to gateway/destination/tenant, operation, authorization, attempt, request, response, effect, scope, transaction reference, sequence and recorded time. `committed` and `partially_committed` require a transaction reference. The verifier trusts a commit only for a scope explicitly assigned to that destination's key. If the MCP server is merely wrapping an external API, describe the scope as an observation unless the actual effect authority supplies the confirmation.

Retrieval uses the explicitly configured upstream and extension method `mcpzt/evidence/get` with the original signed permit. It returns only a receipt. The reference destination accepts a historically valid permit for lookup, even after admission expiry; it does not execute it again. Possession of that permit permits reading its commitment-only receipt. Protect the transport and permits accordingly. Production adapters should additionally authenticate the gateway channel and enforce their tenant access rules. Never use receipt-supplied URLs for keys or lookup.

The gateway allows this profile for `tools/call` requests and existing lifecycle/list operations. Resource reads, prompt gets, arbitrary extension methods and tool-call notifications are rejected on enabled servers. Reconciliation is an operator path, not a bypass exposed as a client tool. SSE, server-initiated messages and general asynchronous MCP tasks are not added by this release.

## Durability, idempotency and recovery

SQLite evidence tables are versioned `evidence_v1_*`; the existing approvals table is retained. Approval consumption, operation reservation and the initial evidence event use one `BEGIN IMMEDIATE` transaction before dispatch. `synchronous=FULL` is selected; actual power-loss guarantees still depend on the filesystem/hardware honoring durability.

The evidence event table is authoritative. JSONL is an outbox projection with stable event IDs and at-least-once delivery: deduplicate by `event_id`. A crash after emission and before marking delivery can produce duplicates. The legacy decision log is separate, not a distributed transaction with an external tool. A post-dispatch log failure leaves a recoverable operation and an unknown client outcome.

Clients that want repeat detection supply an explicit `params._meta["io.github.mcp-zero-trust-layer/idempotency-key"]` string of 1–128 characters. Its scope includes configured tenant, authoritative principal, destination and tool. The gateway mints operation/attempt IDs itself. Reusing a key with different semantic arguments is a conflict; reusing it for the same operation never sends again. Without a key, equivalent calls can represent distinct business intentions. JSON-RPC ID is not an idempotency key.

Principal/fingerprint commitments use a persistent private database salt with HMAC. This salt must be preserved across signing-key rotation; changing the signing key does not reset repeat detection. There is no automatic purge or automatic retry API. Back up the database and salt together. Restoring an earlier database or deleting deduplication state can invalidate operational guarantees; stop dispatch and reconcile against the destination before resuming. The destination must retain deduplication records through the full lifetime of accepted permits and any recovery window.

`reconcile` only queries. A missing receipt is unknown, not proof of no effect. A verified `pending` receipt may advance to a higher sequence; equal sequence with different content, regression or changed terminal receipts creates a durable conflict that blocks normal export/show. Resolve conflicts operationally, without rewriting earlier observations. The sample ledger produces terminal receipts; pending progression is verifier/store support, not an implementation of asynchronous MCP tasks.

## Trust, privacy and operational boundaries

The trust file has `version: 1` and a `keys` array. Each entry binds `kid`, `issuer`, `audience`, `tenant`, `role`, base64url public key, trusted `scopes` and `status` (`active`, `retired`, `revoked`). Gateway and destination must use separate signing keys. Identical administration of both is still a common trust boundary, even with two keys.

Keep trust configuration independently from evidence bundles. No embedded key is automatically trusted and no network key discovery occurs. Retired keys may verify historical records but cannot authorize new execution. Revoked keys fail verification; a signed timestamp alone cannot establish that a record predates compromise. Running instances snapshot their key/trust configuration: restart/reload the deployment deliberately after rotation or revocation. Preserve old nonrevoked public keys when historical verification is required.

A signature authenticates a statement under these assumptions. It cannot establish truthful behavior by a compromised destination, independence against collusion, absence of bypass calls, or completeness of a truncated history. A gateway-only signature never earns a destination commit claim.

Arguments/results are not persisted in the evidence store or exported bundles. Commitments can still reveal low-entropy data by guessing, especially because exported nonces are available to the verifier; they are **not anonymization**. Protect bundles, audit files and database backups as potentially sensitive. Output enforcement always runs after receipt verification, including for JSON-RPC errors. Raw receipts are stripped from client responses. A hash of a raw response is not a mechanism for exposing that response to a client.

## Validation and comparison

Tests cover real HTTP/stdio peers, an MCP SDK client, schema validation, independent JavaScript/Python canonical bytes, tampering, trusted scopes, approval rollback, concurrent replay, process death before/after commit, output filtering and read-only recovery. Line coverage is retained at the existing 100% gate; it is not a cryptographic proof or full protocol certification.

An independent local implementation recomputed the seven frozen AgentKey v0.1 fixtures and matched their cryptographic/authority verdicts, rejection codes and claim ceilings. That comparison did not run a production AgentKey integration or validate an external business effect. MCPZT's own runtime verifier is for the MCPZT receipt profile, not an importer for AgentKey bundles.

References: [JCS, RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), [EdDSA, RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), [MCP metadata conventions](https://modelcontextprotocol.io/specification/2025-11-25/basic), [AgentKey fixture specification](https://agentkey.us/cross-auth-fixture/v0.1/SPEC.md).
