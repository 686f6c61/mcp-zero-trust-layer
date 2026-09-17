# MCPZT landing

Static ES/EN site for the 0.6.0 release, built with the Python standard library. This directory owns the website. The historical Python package files on the `landing` branch are not the product source: build and publish MCPZT from `main`.

## Preview

```sh
python3 landing/build.py
python3 -m http.server 8938 --bind 127.0.0.1 --directory dist
```

Open `/es/` or `/en/`. Preview builds omit analytics and block indexing. The Docker deployment additionally checks headers, redirects, language preference cookies and genuine 404 responses.

```sh
docker build --build-arg ENABLE_ANALYTICS=false -t mcpzt-landing:0.6.0 .
docker run --rm -p 127.0.0.1:8938:80 mcpzt-landing:0.6.0
```

## Production build

The default Docker build uses `https://mcp-zero-trust.686f6c61.dev` from `release.json` and enables the existing Umami analytics. Override `SITE_URL` only if the production HTTPS origin changes, without a trailing path. Enable analytics only for production. Docker/Coolify must pass these as **build arguments**, not only runtime environment variables.

```sh
docker build --build-arg SITE_URL=https://mcp-zero-trust.686f6c61.dev \
  --build-arg ENABLE_ANALYTICS=true -t mcpzt-landing:0.6.0 .
```

Canonical URLs, language alternates, social image URLs, sitemap and robots are generated from that origin. Analytics respects Do Not Track, excludes search parameters and is restricted to that hostname. The language cookie stores only `es` or `en`; it affects `/`, never an explicit language URL. Click events have fixed names and contain no user-supplied tool arguments.

Publish the package and tag before making this page public: installation commands and release notes target `0.6.0`; examples and documentation target the product branch `main`. Use `python3 landing/check_release.py` as the final public-release gate. It requires the GitHub tag, PyPI version and every documentation/example link to be reachable. Passing local website tests does not establish that these public artifacts exist.

## Sources and updates

- `release.json`: release version for commands and release links; `source_ref` selects the branch for documentation and examples.
- `content.json`: complete Spanish and English copy; language pages work without JavaScript.
- `template.html`, `assets/site.css`, `assets/site.js`: structure, existing visual identity and progressive interactions.
- `fixtures/`: frozen synthetic public fixtures copied from the product's 0.6.0 `examples/evidence/external-checks`. No private keys. On release updates, copy the reviewed public fixture set and run product signature verification as well as site checks.
- `build.py`: extracts displayed claims, results and method traces from fixtures. The UI does not perform cryptographic verification or contact payment providers.
- Fonts: self-hosted Archivo and Archivo Black from Google Fonts, with the accompanying OFL licenses. No third-party font request at runtime.

The social card uses release-neutral typography. Assets and fixture directories use content hashes for immutable caching. HTML is revalidated. Clear `dist` before release builds so removed assets cannot remain published; Docker always builds in a clean stage.

## Checks

```sh
python3 landing/build.py --site-url https://preview.example
python3 -m unittest discover -s landing/tests -p 'test_*.py'
npm ci --prefix landing
npx --prefix landing playwright install chromium
# Against the Docker preview (or a static server for UI-only checks):
LANDING_URL=http://127.0.0.1:8938 npm test --prefix landing
```

Browser checks cover both languages, 320/375/768/1280 widths, all evidence states, contract-map bindings and missing-document states, keyboard/menu behavior, language URLs, copy success/failure, missing fixtures, JavaScript-disabled content and accessibility. CI stores screenshots on failure. Production publication also requires the actual deployment's origin, headers and exact commit to be checked.

To regenerate policy fixtures, run `generate_policy_fixtures.py --config /path/to/product/examples/github-readonly/mcpzt.yaml` using the product 0.6.0 environment. The script invokes the actual pipeline with a fake upstream and checks that denied and approval-pending calls never dispatch.

## CI-gated deployment

The `Landing` workflow tests the static build and Nginx container before its deployment job. That job requires the public product release and all documentation links, then pins Coolify to the exact tested commit and verifies both public HTML pages against the production build. Coolify push-triggered auto-deployment is disabled so it cannot bypass CI.

The `landing-production` GitHub environment accepts only the `landing` branch. It supplies `COOLIFY_URL` and `COOLIFY_APP_UUID` as variables and `COOLIFY_TOKEN` as an encrypted secret; none belongs in source files. The token is exposed only to the deployment step, not pull-request checks. Deployment runs are serialized. A failed release-availability check leaves the existing site running.
