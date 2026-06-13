from __future__ import annotations

from mcp_zero_trust_layer.validators.basic import (
    validate_filesystem_path,
    validate_sql_read_only,
    validate_url,
)


def test_sql_read_only_allows_select() -> None:
    result = validate_sql_read_only({"query": "select * from issues"}, {})
    assert result.passed is True


def test_sql_read_only_blocks_destructive_sql() -> None:
    result = validate_sql_read_only({"query": "drop table users"}, {})
    assert result.passed is False


def test_url_blocks_localhost_by_default() -> None:
    result = validate_url({"url": "http://localhost:3000"}, {})
    assert result.passed is False


def test_url_blocks_hostname_resolving_to_private_ip(monkeypatch) -> None:
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, "", ("10.0.0.1", 0))],
    )

    result = validate_url({"url": "https://internal.example"}, {})

    assert result.passed is False
    assert "private IP" in result.errors[0]


def test_filesystem_path_blocks_outside_allowed_roots(tmp_path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    result = validate_filesystem_path(
        {"path": str(tmp_path / "other" / "file.txt")},
        {"allowed_roots": [str(allowed)]},
    )
    assert result.passed is False


def test_filesystem_path_resolves_relative_roots_from_config_base_dir(tmp_path) -> None:
    base = tmp_path / "project"
    allowed = base / "workspace"
    allowed.mkdir(parents=True)

    result = validate_filesystem_path(
        {"path": "workspace/report.md"},
        {"allowed_roots": ["workspace"], "base_dir": str(base)},
    )

    assert result.passed is True
