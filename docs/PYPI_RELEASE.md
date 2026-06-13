# PyPI Release Guide

The first-class distribution path for MCP Zero Trust Layer is PyPI. The user-friendly install path should be `uvx mcp-zero-trust-layer`, `pipx run mcp-zero-trust-layer`, or a normal `pip install` inside an environment.

This is public release documentation. It explains how to package, verify and publish the project without exposing internal construction notes, local secrets or build artifacts.

## Package Identity

The canonical PyPI distribution name is:

```text
mcp-zero-trust-layer
```

The installed console commands are:

```text
mcpzt
mcp-zero-trust-layer
```

The short command is for daily use. The long command matches the distribution name and improves discoverability in automation and documentation.

The import package is different from the distribution name:

```text
mcp_zero_trust_layer
```

That distinction matters during release checks. PyPI users install the distribution package, while Python imports the import package.

## Release Philosophy

Releases should be boring. A release is ready when the package builds from a clean source tree, the README renders on PyPI, the wheel installs in a fresh environment, the CLI works from that wheel, the public docs included in the source distribution are intentional, and no local state or private construction material is present.

Use PyPI Trusted Publishing from GitHub Actions. Do not store long-lived PyPI API tokens in the repository, in GitHub secrets, in local `.env` files, or in release scripts. Trusted Publishing lets GitHub Actions request a short-lived publish token from PyPI through OIDC, scoped to the configured project and workflow.

## Files That Should Ship

The package should ship the user-facing project files, source code, bundled policy packs, public examples and public docs.

The source distribution should include:

```text
README.md
CHANGELOG.md
LICENSE
SECURITY.md
CONTRIBUTING.md
Dockerfile
constraints.txt
pyproject.toml
MANIFEST.in
src/
examples/
deploy/
docs/MULTI_MCP_USE_CASES.md
docs/PRODUCTION.md
docs/PYPI_RELEASE.md
```

The source distribution should not include internal construction docs, local audit files, approval stores, secrets, virtual environments, caches or generated build directories. In this repository, `MANIFEST.in` intentionally includes public docs one by one instead of using `recursive-include docs *.md`.

## Local Preflight

Start from a clean development environment.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
```

Run the full verification set.

```bash
python -m pytest
ruff check .
python -m build
twine check dist/*
```

The build creates both a source distribution and a wheel under `dist/`. `twine check` validates package metadata and README rendering enough to catch common PyPI failures before upload.

Run a focused CLI smoke test from the editable install.

```bash
mcpzt --help
mcpzt version
mcpzt pack list
mcpzt init --config /tmp/mcpzt.yaml --force
mcpzt config validate --config /tmp/mcpzt.yaml
mcpzt config schema --output /tmp/mcpzt.schema.json
mcpzt doctor --config /tmp/mcpzt.yaml
mcpzt client config --config /tmp/mcpzt.yaml --base-url http://127.0.0.1:8765
mcpzt policy test \
  --config examples/github-readonly/mcpzt.yaml \
  --server github \
  --method tools/call \
  --capability github.search_issues
mcpzt policy explain \
  --config examples/github-readonly/mcpzt.yaml \
  --server github \
  --method tools/call \
  --capability github.search_issues
```

If those commands fail locally, do not publish. Fix the package before creating a release.

## Wheel Smoke Test

Editable installs can hide packaging mistakes because they run from the working tree. A clean wheel smoke test proves that the artifact itself works.

```bash
rm -rf /tmp/mcpzt-wheel-smoke
python -m venv /tmp/mcpzt-wheel-smoke
/tmp/mcpzt-wheel-smoke/bin/python -m pip install dist/mcp_zero_trust_layer-*.whl
/tmp/mcpzt-wheel-smoke/bin/mcpzt version
/tmp/mcpzt-wheel-smoke/bin/mcpzt pack list
/tmp/mcpzt-wheel-smoke/bin/mcpzt init --config /tmp/mcpzt-smoke.yaml --force
/tmp/mcpzt-wheel-smoke/bin/mcpzt config validate --config /tmp/mcpzt-smoke.yaml
/tmp/mcpzt-wheel-smoke/bin/mcpzt client config --config /tmp/mcpzt-smoke.yaml
```

This catches missing package data, broken entry points and metadata issues that may not show up during editable development.

## Artifact Inspection

Inspect the source distribution before publishing. The goal is to prove that public docs are included and private docs are absent.

```bash
tar -tzf dist/mcp_zero_trust_layer-0.1.0.tar.gz | sort
```

Check the docs that will ship.

```bash
tar -tzf dist/mcp_zero_trust_layer-0.1.0.tar.gz | rg '(^|/)docs/'
```

Expected public docs:

```text
mcp_zero_trust_layer-0.1.0/docs/MULTI_MCP_USE_CASES.md
mcp_zero_trust_layer-0.1.0/docs/PRODUCTION.md
mcp_zero_trust_layer-0.1.0/docs/PYPI_RELEASE.md
```

Check the deployment recipes that will ship in the source distribution.

```bash
tar -tzf dist/mcp_zero_trust_layer-0.1.0.tar.gz | rg '(^|/)deploy/'
```

Check for local state and obviously private material. This command should produce no output. Keep any organization-specific private deny-list in your local release runbook rather than publishing the private filenames in public documentation.

```bash
tar -tzf dist/mcp_zero_trust_layer-0.1.0.tar.gz \
  | rg '(^|/)(internal|notes|scratch|secrets)/|\\.env|mcpzt-audit|mcpzt-approvals'
```

Also inspect the wheel when package data changes.

```bash
unzip -l dist/mcp_zero_trust_layer-0.1.0-py3-none-any.whl
```

The wheel should contain Python package code, `py.typed`, bundled policy packs and metadata. It does not need to contain public docs or deployment recipes because the README and metadata are carried in the distribution metadata, and the source distribution carries the public docs and operational examples.

## Versioning

Use SemVer with a clear `0.x` caveat.

During `0.x`, minor releases may still change the configuration schema, CLI behavior or policy shape. Patch releases should be limited to bug fixes, documentation, packaging fixes or safe hardening. A future `1.0` should mean the core CLI, config contract and proxy/wrapper behavior are stable enough for production users to automate around them.

Before release, confirm that `pyproject.toml` and `src/mcp_zero_trust_layer/__init__.py` agree on the version.

```bash
python - <<'PY'
import tomllib
from pathlib import Path
import mcp_zero_trust_layer

project = tomllib.loads(Path("pyproject.toml").read_text())["project"]
assert project["version"] == mcp_zero_trust_layer.__version__
print(project["version"])
PY
```

Any config-breaking change should be called out in `CHANGELOG.md` with migration notes.

## GitHub Actions Publishing

The repository uses `.github/workflows/publish.yml` for release publishing. It builds distributions, validates them, uploads the build artifact inside GitHub Actions, and publishes through `pypa/gh-action-pypi-publish`.

The publish job must have:

```yaml
permissions:
  id-token: write
```

The PyPI project must trust the GitHub Actions publisher. Configure the publisher in PyPI with the repository owner, repository name, workflow filename and environment name. For this repository, the workflow environment is:

```text
pypi
```

Protect the GitHub environment named `pypi` so publication can require a human review. The most important part of the security model is not merely using OIDC; it is ensuring that only trusted workflows and trusted maintainers can trigger the OIDC identity that PyPI accepts.

For a first release, PyPI supports creating a project through a pending Trusted Publisher. That avoids the old pattern of manually uploading the first release with a long-lived API token.

## TestPyPI

Use TestPyPI before the first public release or after packaging changes. The cleanest path is a separate TestPyPI project with its own trusted publisher and a separate GitHub environment such as `testpypi`.

The smoke test after TestPyPI upload should install from TestPyPI while allowing dependencies to resolve from PyPI.

```bash
python -m pipx run \
  --index-url https://test.pypi.org/simple/ \
  --pip-args "--extra-index-url https://pypi.org/simple/" \
  mcp-zero-trust-layer --help
```

Manual TestPyPI uploads with `twine upload` are acceptable only as a fallback for local experimentation. Do not commit credentials, do not paste tokens into scripts, and do not use the real PyPI project token for TestPyPI.

## Release Flow

Prepare the release on a branch. Update version fields, update `CHANGELOG.md`, update public docs if behavior changed, and run the local preflight. Build the artifacts locally and inspect them. Confirm the wheel smoke test passes.

After merging to `main`, create a GitHub release. The current publish workflow is triggered when a GitHub release is published. GitHub Actions should run tests, build artifacts, validate metadata, and publish through Trusted Publishing.

After publication, smoke test the package exactly as a user would.

```bash
uvx mcp-zero-trust-layer --help
uvx mcp-zero-trust-layer version
uvx mcp-zero-trust-layer init --config /tmp/mcpzt.yaml --force
uvx mcp-zero-trust-layer config validate --config /tmp/mcpzt.yaml
```

Then test `pipx`.

```bash
pipx run mcp-zero-trust-layer --help
```

If the package installs and the CLI works, announce the release with the version, headline changes, security notes and any migration guidance.

## Failure Handling

PyPI releases are immutable in practice. You can delete a bad release, but you should not rely on replacing it with a different artifact for the same version. If a published artifact is wrong, cut a new patch version.

If the failure is metadata-only and the package is not usable, publish a fixed patch as soon as possible. If the failure exposes sensitive material, treat it as a security incident: remove the release if appropriate, rotate affected secrets, publish a corrected version, and document the impact.

If GitHub Actions fails before upload, fix the workflow or package and retry. If Trusted Publishing fails, check the PyPI publisher configuration, workflow filename, repository owner/name, environment name and `id-token: write` permission.

## Public References

- Python Packaging User Guide, writing `pyproject.toml`: https://packaging.python.org/en/latest/guides/writing-pyproject-toml/
- Python Packaging User Guide, build and publish section: https://packaging.python.org/en/latest/guides/section-build-and-publish/
- PyPI Trusted Publishers overview: https://docs.pypi.org/trusted-publishers/
- PyPI Trusted Publishing with GitHub Actions: https://docs.pypi.org/trusted-publishers/using-a-publisher/
- PyPI Trusted Publisher security model: https://docs.pypi.org/trusted-publishers/security-model/
