# 0.4.0 verification and test review

Baseline: 0.3.0 (`4c1061daab2fa2a7442d42e7412cf3c6c85ae89f`), 501 tests and 100% line coverage. The audit found that coverage did not exercise key contracts.

## What changed in test quality

- Replaced old expectations accepting unsigned JWT identity fallbacks, anonymous session reuse, invalid requests/unsolicited responses and non-object nested allowlist ancestors. These were incorrect behavior expectations, not reasons to preserve the bugs.
- Added deterministic concurrent approval-review/consume and audit-write tests, so failures do not depend only on a lucky stress schedule.
- Added strict audit failures using real unavailable paths, not only mocked logger errors, with assertions that upstream was never invoked.
- Added actual HTTP wire peers for two-client isolation, forged internal keys, stale sessions, responses after deletion, malformed envelopes, empty HTTP errors, initialization cleanup and SSE rejection.
- Added real subprocess byte/deadline/ID tests and a real MCP SDK FastMCP integration, checking forbidden calls do not create a side-effect marker.
- Added parser/validator negative cases, client JSON/TOML parsing, and generated authentication checks against AuthResolver.
- Kept the existing 100% line coverage gate. Tests are organized around guarantees; no exclusions were added to hide new uncovered behavior.

## Regression sensitivity

Twelve initial enforcement/evidence tests in `tests/integration/test_release_contracts.py` were executed against the original 0.3.0 source via an isolated source path. All twelve failed there and passed against the corrected source. This specifically checks the OPA rejection shapes, unsupported approval methods, strict audit ordering, error evidence, trusted identity and approval/config binding. Additional tests were added afterwards; this is not a claim of full mutation-testing coverage.

Final local Python 3.14 suite: **710 passed, 100% line coverage (4,227 statements)**. The prior Python 3.11–3.13 local matrix passed all 700 tests present at that checkpoint; the final expanded suite is required on all four versions by the exact-commit GitHub gate.

## Validation performed

- Full suites with 100% line coverage locally on Python 3.11, 3.12, 3.13 and 3.14; final exact-commit matrix also required by GitHub CI/release workflows.
- Ruff, mypy, build and Twine metadata checks.
- Wheel installed into an isolated Python 3.12 environment and imported outside the checkout; CLI version, initialization, validation, policy packs and Grok TOML verified.
- Source distribution checked for intended public docs; no local audit artifacts or environments included.
- Docker build and container CLI version verified.
- Constrained cryptography updated to 50.0.0; refreshed local dependency audit reported no known vulnerabilities. This does not establish absence of unknown vulnerabilities.
- Workflow syntax checked with actionlint; publication requires the same matrix/type/lint/coverage gate as normal CI and verifies artifact checksums.

## Boundaries

Live cloud-provider calls were not performed. The supported HTTP JSON / POSIX serial stdio profile and unsupported server-initiated messages are explicit in `SUPPORTED_PROFILE.md`. Windows stdio, arbitrary SQL dialect semantics and distributed exactly-once execution are not claimed. Line coverage is not branch coverage, a formal proof or a complete threat assessment.
