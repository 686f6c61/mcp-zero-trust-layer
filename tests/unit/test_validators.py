from __future__ import annotations

from mcp_zero_trust_layer.config.models import ValidatorConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.validators.basic import (
    validate_filesystem_path,
    validate_regex,
    validate_sql_read_only,
    validate_url,
)
from mcp_zero_trust_layer.validators.engine import ValidatorEngine


def _ctx(arguments: dict) -> RequestContext:
    return RequestContext(
        server="s",
        method="tools/call",
        capability_type="tool",
        capability="t",
        arguments=arguments,
        identity=Identity(subject="u"),
    )


def test_sql_read_only_allows_select() -> None:
    result = validate_sql_read_only({"query": "select * from issues"}, {})
    assert result.passed is True


def test_sql_read_only_blocks_destructive_sql() -> None:
    result = validate_sql_read_only({"query": "drop table users"}, {})
    assert result.passed is False


def test_sql_read_only_blocks_stacked_statements() -> None:
    for query in (
        "SELECT 1; ATTACH DATABASE '/tmp/x.db' AS y",
        "SELECT 1; COPY (SELECT 1) TO PROGRAM 'curl evil'",
        "SELECT 1; PRAGMA writable_schema=1",
        "select 1; vacuum",
    ):
        assert validate_sql_read_only({"query": query}, {}).passed is False, query


def test_sql_read_only_blocks_dangerous_functions() -> None:
    assert validate_sql_read_only({"query": "SELECT load_extension('evil.so')"}, {}).passed is False


def test_sql_read_only_blocks_mysql_executable_comment() -> None:
    query = "SELECT * FROM t /*!32302 DROP TABLE users */"
    assert validate_sql_read_only({"query": query}, {}).passed is False


def test_sql_read_only_allows_semicolon_inside_string_literal() -> None:
    result = validate_sql_read_only({"query": "SELECT * FROM t WHERE label = 'a;b'"}, {})
    assert result.passed is True


def test_sql_read_only_allows_trailing_semicolon_and_cte() -> None:
    assert validate_sql_read_only({"query": "SELECT 1;"}, {}).passed is True
    assert validate_sql_read_only(
        {"query": "WITH a AS (SELECT 1) SELECT * FROM a"}, {}
    ).passed is True


def test_forbidden_field_present_with_null_value_is_detected() -> None:
    from mcp_zero_trust_layer.validators.basic import validate_required_forbidden_fields

    result = validate_required_forbidden_fields({"danger": None}, {"forbidden": ["danger"]})
    assert result.passed is False


def test_regex_validator_fails_closed_on_invalid_pattern() -> None:
    result = validate_regex({"q": "abc"}, {"field": "q", "deny": "("})
    assert result.passed is False


def test_engine_fails_closed_when_validator_raises() -> None:
    engine = ValidatorEngine()
    result = engine.validate(
        [ValidatorConfig(name="filesystem_path", options={})],
        _ctx({"path": "/tmp/\x00null"}),
    )
    assert result.passed is False
    assert "failed to evaluate" in result.errors[0]


def test_url_validator_fails_closed_on_invalid_idna_host() -> None:
    result = validate_url({"url": "http://" + "a" * 100 + "ß.example/"}, {})
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


def test_filesystem_path_blocks_sensitive_defaults() -> None:
    for path in ("/root/.ssh/id_rsa", "/proc/self/environ", "/sys/kernel"):
        assert validate_filesystem_path({"path": path}, {}).passed is False, path


def test_url_blocks_encoded_loopback_ips() -> None:
    for host in ("0x7f000001", "2130706433", "0177.0.0.1"):
        result = validate_url({"url": f"http://{host}/"}, {"resolve_dns": False})
        assert result.passed is False, host


def test_url_blocks_cgnat_range() -> None:
    result = validate_url({"url": "http://100.64.0.1/"}, {"resolve_dns": False})
    assert result.passed is False


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
