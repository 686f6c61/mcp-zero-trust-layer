# MCPZT 0.6.0 validation

Local validation performed on 2026-09-17. This is a validation record for the working tree, not a statement that a GitHub release, PyPI artifact or GHCR image has been published.

## Automated results

- Ruff and mypy pass (75 source files checked by mypy).
- Full suite: **895 passed, 1 skipped**. The skipped case requires a real Stripe sandbox fixture and credentials.
- **100% line coverage: 5,419 statements**. Coverage is not proof of security or of an external business effect.
- 54 new corroboration tests cover the behaviors below. A further 25 example compatibility cases exercise the actual YAML, generated demos, authenticated OIDC group gates, client/upstream credential separation, the pinned official filesystem peer and the ledger through the gateway SDK. The pre-existing v1 and transport suites remain passing.
- Wheel and sdist build; `twine check` passes. Source distributions include the external-check guide and public comparison fixtures and exclude private keys/internal plans/audits.
- A fresh virtual environment outside the checkout installs the wheel and verifies package/source version 0.6.0. Both the original v1 ledger demo and the new v2 adversarial demo run from that installation; offline v2 verification with explicit observer trust succeeds.
- The local Docker image builds and runs the adversarial demo and offline verification as its non-root application user. This is a local image check, not GHCR publication.
- CI retains Python 3.11–3.14 gates and now runs the v2 demo/verifier from its isolated wheel installation. Remote CI for these uncommitted changes has not run.

## Contract cases

| Boundary | Executable checks |
| --- | --- |
| Signature versus truth | Valid destination `committed` claim remains authentic while a provider-reported failure yields a separate contradiction. |
| Recovery | Timeout snapshot has no receipt; read-only lookup adds the receipt; method trace contains exactly one business call. |
| Business correlation | Different refund ID, charge, currency or amount cannot corroborate. Wrong account cannot corroborate. |
| Authorization correlation | Exact request preimage plus operation, authorization, attempt and request-digest metadata; mismatches fail or remain unknown. |
| Provider uncertainty | Pending/requires-action, unknown status, missing record, access denial, rate limiting, server failure, redirect, malformed/oversized body and timeout. |
| Observer authority | Separate key, configured issuer/tenant/destination/source/scope/account; revoked or unknown keys rejected; retired keys historical only. |
| Claim ceiling | Offline verification reports observer attestation, missing provider signature, unproven independence and no established current external state. |
| History | Success and subsequent failure both retained; original receipt unchanged; concurrent appends cannot fork; conflicting receipts or full history prevent append. |
| Portability | Frozen public fixtures, JSON Schema validation, independent Node.js Ed25519 verification and chain-digest computation. |
| Actual HTTP | A local HTTP server receives exactly GET account and GET refund; no business-write method. |
| CLI | Check exit codes, private exports, v1/v2 compatibility, explicit observer trust, show and schema commands. |

## Reproduce

```sh
python -m pip install -c constraints.txt -e '.[dev]'
ruff check .
mypy
# Install and set MCPZT_FILESYSTEM_ENTRYPOINT as described in examples/filesystem-safe/README.md.
python -m pytest --cov=mcp_zero_trust_layer --cov-report=term-missing --cov-fail-under=100
mcpzt evidence check-demo --directory /tmp/new-mcpzt-check-demo
```

Node.js is required for independent fixture checks, as in CI. The recorded run also configured the official filesystem peer; without MCPZT_FILESYSTEM_ENTRYPOINT that additional integration test is explicitly skipped. CI installs the pinned package and enables it. See [the external-check guide](EXTERNAL_CHECKS.md) for commands to verify and compare the generated bundles.

## Still requires an external environment

The Stripe sandbox test is opt-in and read-only. It needs an existing refund tied to a real signed permit/receipt, matching metadata, a configured account and a test credential. Local simulated responses and the local HTTP server do not establish that this provider integration has passed a live sandbox run. No paid-provider call, real refund, settlement verification or AgentKey production integration was performed.
