# Contributing

Thanks for helping make MCP Zero Trust Layer safer and easier to use.

## Local Setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

Run the core checks before opening a pull request:

```bash
python -m pytest
ruff check .
python -m build
twine check dist/*
```

## Design Rules

- Keep policy decisions independent from HTTP and stdio transports.
- Do not put security decisions in CLI presentation code.
- Prefer explicit deny behavior over implicit allow behavior.
- Every deny, approval, validation failure and output block needs a human-readable reason.
- Never write logs to stdout in stdio mode.
- Redact secrets before audit writes, test outputs or error messages.
- Add tests when changing policy, validators, auth, output enforcement, audit or transports.

## Configuration Compatibility

The project is currently `0.x`, so config shape may evolve. Breaking config changes must include:

- changelog entry;
- migration note;
- updated examples;
- focused tests.

## Pull Request Checklist

- Tests pass.
- Lint passes.
- README/docs updated for user-visible behavior.
- New config fields have schema defaults and validation.
- Security-sensitive changes include negative tests.
- Packaging metadata still builds and passes `twine check`.
