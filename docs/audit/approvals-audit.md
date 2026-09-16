# Approval and audit evidence audit — 2026-09-16

Scope: approval persistence, approval UI, enforcement-to-audit ordering, and chain integrity. This is a source audit with local reproductions; no live upstream, credentials, production data, or project behavior was changed. Reproductions use temporary files and an in-memory fake upstream.

Run from the repository root:

```sh
.venv/bin/python docs/audit/reproduce_approvals.py
```

The script prints actual observations rather than enforcing a permanent test expectation; a future fix should change these observations. Thread barriers deliberately select valid concurrent interleavings. They do not alter stored approvals, hashes, or validation results.

## Confirmed findings

| ID | Severity | Finding | Source |
| --- | --- | --- | --- |
| A1 | High | Strict audit failure occurs after the tool has run | `core/pipeline.py:229`, `audit/logger.py:111` |
| A2 | High | SQLite status update can resurrect a consumed approval | `approvals/store.py:239`, `approvals/store.py:300` |
| A3 | Medium | Approval UI decisions produce no audit event or configured webhook | `approvals/ui.py:60` |
| A4 | Medium | Approval UI exposes records without authentication | `approvals/ui.py:69` |
| A5 | Medium | Audit lock is released before buffered writes flush | `audit/logger.py:128` |
| A6 | Medium | stdout audit hash chain fails its own verifier | `audit/logger.py:98` |
| A7 | Medium | An upstream exception leaves no dispatch/failure audit record | `core/pipeline.py:229` |

Paths in the table are relative to `src/mcp_zero_trust_layer/`.

### A1 — strict audit does not prevent unlogged side effects

The call path executes `upstream.send()` and only then calls `_log_decision()`. With `audit.strict=true` and the configured audit path pointing to a directory, the request raises `IsADirectoryError`, but the recording upstream has already received one call. Equivalent write failures include unavailable storage and permissions errors.

Observed: `STRICT IsADirectoryError upstream_calls 1`.

This directly conflicts with `docs/PRODUCTION.md:331`, which describes strict audit as failing closed instead of allowing unlogged execution. A client receiving an error may retry an already performed side effect. The same ordering appears in list/other forwarding paths.

This is an audit reliability/fail-closed ordering defect, not a claim that a gateway can provide transactional exactly-once execution across arbitrary upstreams.

Recommendation: write and durably commit a dispatch-intent event before forwarding under strict mode, then write a separate outcome event. Define the limitation explicitly: an outcome-log failure cannot undo an upstream side effect. A preflight writability check alone does not close the race.

### A2 — SQLite stale writer allows approval reuse

`_sqlite_consume_if_valid()` correctly uses `BEGIN IMMEDIATE`, but `_sqlite_set_status()` reads and validates before beginning a write transaction. The eventual update is unconditional by approval ID. Also `_assert_valid_transition()` explicitly permits same-status updates (`if new == current: return`).

Deterministic sequence:

1. Create and approve an approval.
2. Start a second authorized `set_status(id, 'approved')`; pause after its read/transition check.
3. Consume the approval successfully in another connection.
4. Resume the stale status writer; it overwrites `consumed` with the previously constructed `approved` payload.
5. Consume the same ID again successfully.

Observed: `SQL_REPLAY True True`.

This is not an unauthenticated requester inventing an approval. It requires a concurrent approval-status writer, such as a duplicate reviewer action in a separate process/CLI or another service worker. The public API accepts same-status approvals even though the HTML disables the button for already approved records. Single-use is therefore not invariant across supported writer operations. Concurrent first-time reviewers can also cause stale terminal-state overwrites.

Recommendation: use `BEGIN IMMEDIATE` before the status read, or compare-and-swap with the expected state and verify the affected row count; make same-status writes truly idempotent. Add regression coverage that interleaves review and consumption, not only two consumers.

### A3 — UI approval decisions are not audited

The UI calls `ApprovalStore.set_status()` and returns. Neither that path nor the store instantiates/calls `AuditLogger` or `ApprovalNotifier`. The CLI separately logs/notifies, which does not cover UI requests.

Observed: UI POST allow returns 200 and changes status, but the configured audit file does not exist. This contradicts `README.md:44` and `docs/PRODUCTION.md:375` (UI decisions audited through normal log path), and the documented decision webhooks.

Consumption compounds evidence loss: `_with_status(..., 'consumed', decision_comment=None)` overwrites `decided_at` and deletes the review comment. The approval store is then insufficient to reconstruct the original review time/comment, and UI users have no immutable decision event to recover it from.

Recommendation: centralize decision processing with consistent audit/webhook semantics across CLI and UI; preserve reviewer decision fields and add a separate `consumed_at` field/event.

### A4 — configured authentication protects decisions, not approval reads

Both GET `/` and GET `/api/approvals` directly return the store contents without `_reviewer()`. With `auth.mode=static_token`, a request carrying no authorization still receives HTTP 200 and the records.

Observed: `UNAUTH_LIST 200 items 1`.

Records expose identity, capability, arguments remaining after key-pattern redaction, approval IDs, and reviewer comments. Redaction is not access control: business/personal data need not look like a token. Scope depends on exposure; default localhost binding reduces external exposure but the production guide permits exposing a UI protected by `auth`, which does not protect these routes.

Recommendation: authenticate both routes and decide explicit reviewer access policy. Current authentication alone also allows any authenticated identity other than the requester to approve; there is no reviewer-role authorization. Treat that latter point as a design boundary unless stronger role control is promised.

### A5 — premature unlock can fork the audit chain

`handle.write()` is buffered. `_locked_append()` releases `flock` before `handle.close()` flushes the data. Another writer can acquire the lock, read the old tail, and append a record with the same sequence/predecessor. The first writer then flushes its stale record.

Initial 1,200-event uncontrolled threaded stress runs happened to pass; an independent coordinator run reproduced the defect without scheduling hooks (`CONCURRENT_CHAIN` rejected line 613 with `previous_event_hash mismatch`). A deterministic scheduler barrier after the real first `LOCK_UN`, before close, reproducibly writes two events with `sequence=1` and `previous_event_hash=null`. Verification rejects line 2. The barrier changes scheduling only, not the write or hash functions.

Observed: `SCHEDULED_CHAIN (False, 'line 2: previous_event_hash mismatch')`.

Recommendation: flush inside the locked region before unlocking; use `fsync` where the durability promise requires it. Provide real locking or reject unsupported configurations when `fcntl` is unavailable. Current Windows fallback silently does no locking, affecting both JSON approvals and audit writes; this platform observation is source-based, not tested on Windows.

### A6 — stdout hash chaining is invalid

For every stdout record `_write()` sets `previous=None, sequence=0`. The verifier expects the first sequence to be 1; subsequent events do not chain either. `hash_chain` defaults to true and stdout is an accepted destination.

Observed: a captured two-event stdout log gives `STDOUT_CHAIN (False, 'line 1: sequence mismatch')`.

Recommendation: either implement a serialized stream chain with a documented process/restart boundary or reject/disable this combination explicitly. Do not emit fields that appear to promise a chain while generating unrelated events.

### A7 — dispatch exceptions disappear from audit

If `upstream.send()` raises `JSONRPCError`, `handle()` converts it to an error response before any decision audit is written. A failure after actual dispatch can therefore be indistinguishable in the audit log from no request at all.

Observed: fake upstream raises a transport failure after dispatch; client receives JSON-RPC error and no configured audit file exists. `upstream_status` is accepted by the logger but current pipeline callers do not set it.

Recommendation: pre-dispatch event plus correlated outcome/error event, including an explicit unknown completion state for timeouts/disconnects. Do not represent a transport response as independent proof of downstream side-effect completion.

## Approval-to-execution binding: precise current boundary

The store checks subject, client ID, agent ID, logical server, method, capability, capability type, policy ID, and SHA-256 of sorted serialized arguments. Both JSON and SQLite consumption reject sequential replay. These are useful enforcement properties; no independent signed execution receipt exists.

Further limitations supported by source:

- A policy ID is bound, not a digest of policy contents/version. Logical server name is bound, not an endpoint/configuration digest. Reusing IDs across policy/server changes can retain approvals within TTL.
- For tools/prompts, argument hashing covers the `arguments` dictionary rather than the complete forwarded request envelope; sibling `params` fields such as `_meta` are forwarded but are not bound. Do not describe this as a digest of the exact complete executed call. Whether those fields affect execution depends on the upstream.
- Audit decision events contain redacted arguments, no original argument hash, no approval ID, no request/response digest, and no direction field. Creation events have their own approval object, but a fresh correlation ID is allocated to each retry. This prevents deterministic evidence joining when multiple identical-looking requests or redacted values exist.
- The decision logged on an approved retry remains `require_approval`; only `upstream_called=true` indirectly distinguishes forwarding. There is no consumed approval event.
- HMAC provides verification for holders of the shared secret, not public-key signatures or independent tool attestations. Hash/HMAC chains alone do not detect deletion of a valid suffix or complete deletion; the verifier accepts an empty file as zero events. External anchors, retention, and checkpoints are needed for completeness claims. The documentation already qualifies unkeyed whole-file rewriting, so that is a limitation, not a newly discovered cryptographic defect.
- Raw request/response signatures are an optional future protocol/design decision. Correct the enforcement, concurrency, and audit gaps before marketing stronger evidence guarantees.

## Suggested acceptance criteria

1. An unavailable strict audit destination causes zero upstream calls.
2. No permitted concurrent status operation revives consumed/denied/expired approvals.
3. Every review channel produces a durable attributable decision event preserving review time/comment; consumption is separate.
4. Approval data cannot be read without configured authentication.
5. Concurrent chains verify under a forced unlock/flush interleaving; stdout behavior is coherent and documented.
6. Dispatch, success, error, and unknown completion produce linked events with explicit semantics.
7. An approved execution can be deterministically joined to its approval and argument digest without exposing secret arguments.
