# Landing 0.6.0 — validation

Validated on 2026-09-17 in the isolated `landing` worktree and GitHub Actions.

- **13 static/build/deployment tests pass**: ES/EN content parity; links, anchors and local assets; release commands; evidence projection from original records; unchanged public fixtures; production/preview separation; policy outcomes and configured production origin; content-hashed assets; deployment branch/revision guards, public-byte comparisons, retryable read failures and non-repeated uncertain mutations.
- **16 Chromium tests pass against the Nginx container**: both languages at 320, 375, 768 and 1280 px; all eight evidence states; interactive authorization/attempt/receipt/observation map and exact fixture fields; policy outcomes; menu and Escape behavior; explicit language routes; copy success and unavailable clipboard; no-JavaScript navigation; missing-fixture fallback.
- Automated axe checks for WCAG 2 A/AA and 2.1 AA report no violations in the tested initial views. This is not a complete accessibility certification.
- Desktop and mobile screenshots were inspected, including the English contradiction state. No page errors, failed local resources or global horizontal overflow were detected in the tested viewports.
- HTTP checks pass for language redirects and preference cookie, explicit routes, security headers, HTML revalidation and genuine 404 responses.
- Preview and production Docker images build. The production artifact contains the configured canonical origin, scoped Umami settings and 0.6.0 commands. The preview disables analytics.
- The installed 0.6.0 wheel verifies the copied external-evidence fixture: integrity and binding valid, configured destination trusted, observer signature verified. Historical observations do not establish the current external state.
- Policy fixtures were generated with the real 0.6.0 pipeline and a simulated upstream: allowed = one dispatch; denied = zero; approval pending = zero. No provider was contacted.
- All source links target `main` and map to existing public files/directories in the product repository.

The public 0.6.0 tag, PyPI package, GHCR image and documentation are published. `check_release.py` checks public availability before each deployment. [Landing run 35273490490](https://github.com/686f6c61/mcp-zero-trust-layer/actions/runs/35273490490) passed website checks and deployed commit `730d1bb8f0eeb2360683f62a0dc17f301642af16`; both public language pages matched the production build byte for byte. Its first deployment attempt hit a connection timeout before queuing any deployment; rerunning that job succeeded. Subsequent pushes must pass the same workflow and exact-commit/public-byte verification.

Reproduction commands and deployment configuration are in [README.md](README.md).

Documentation review added a guide index and 0.6.0 evidence operations guide on `main`. The landing links to those guides through its configured `source_ref: main`.
