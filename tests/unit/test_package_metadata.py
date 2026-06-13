from __future__ import annotations

import tomllib
from pathlib import Path

from mcp_zero_trust_layer import __version__


def test_package_version_matches_pyproject() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert __version__ == pyproject["project"]["version"]

