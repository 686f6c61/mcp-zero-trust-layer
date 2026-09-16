# 0.4.0 release plan

Starting revision: 4c1061daab2fa2a7442d42e7412cf3c6c85ae89f (0.3.0).

1. Regression-first corrections: policy decisions, trusted identity, approval races, audit lifecycle, HTTP session isolation, bounded stdio and discovery pagination.
2. Review existing tests for assertions that preserve incorrect behavior; replace those expectations with documented contracts. Add negative cases, concurrent interleavings and actual transport integration tests. Keep the existing coverage gate; coverage is not evidence of protocol conformance by itself.
3. Client configuration: correct VS Code, preserve import controls, add Grok/Gemini/Codex, document auth and provider approval distinctions.
4. Full lint/type/test/coverage gates, clean wheel install and CLI smoke, package content checks; CI Python 3.11–3.14. Verify released artifact, not only source.
5. Version/changelog and honest compatibility boundaries, push, successful CI, publish GitHub release triggering trusted PyPI/GHCR publication, verify published version and installation.

Release gate: no known unresolved high-impact finding in the audited supported profile. Explicit unsupported protocol features must fail clearly and be documented. Cloud integrations are not described as live tested without actual evidence.
