from __future__ import annotations

import socket

from mcp_zero_trust_layer.config.models import InputPolicy, ValidatorConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.validators.basic import (
    _is_private_ip,
    validate_email,
    validate_filesystem_path,
    validate_max_field_bytes,
    validate_regex,
    validate_required_forbidden_fields,
    validate_sql_read_only,
    validate_url,
)
from mcp_zero_trust_layer.validators.engine import ValidatorEngine
from mcp_zero_trust_layer.validators.input_policy import validate_input_policy


def _ctx(arguments: dict, **kwargs) -> RequestContext:
    base = {
        "server": "s",
        "method": "tools/call",
        "capability_type": "tool",
        "capability": "t",
        "arguments": arguments,
        "identity": Identity(subject="u"),
    }
    base.update(kwargs)
    return RequestContext(**base)


# --- validate_sql_read_only edge cases -------------------------------------


def test_sql_read_only_missing_query_fails() -> None:
    assert validate_sql_read_only({}, {}).passed is False


def test_sql_read_only_non_select_fails() -> None:
    # passes forbidden keyword/function checks but is not SELECT/WITH/EXPLAIN
    result = validate_sql_read_only({"query": "SHOW TABLES"}, {})
    assert result.passed is False
    assert "SELECT" in result.errors[0]


# --- validate_filesystem_path ----------------------------------------------


def test_filesystem_path_missing_argument_fails() -> None:
    assert validate_filesystem_path({}, {}).passed is False


def test_filesystem_path_allows_normal_path() -> None:
    assert validate_filesystem_path({"path": "/tmp/data/report.txt"}, {}).passed is True


def test_filesystem_path_read_only_blocks_write_operation() -> None:
    result = validate_filesystem_path(
        {"path": "/tmp/data/x.txt", "operation": "write"},
        {"read_only": True},
    )
    assert result.passed is False
    assert "non-read" in result.errors[0]


def test_filesystem_path_read_only_allows_read_operation() -> None:
    result = validate_filesystem_path(
        {"path": "/tmp/data/x.txt", "operation": "list"},
        {"read_only": True},
    )
    assert result.passed is True


# --- validate_url ----------------------------------------------------------


def test_url_missing_argument_fails() -> None:
    assert validate_url({}, {}).passed is False


def test_url_disallowed_scheme_fails() -> None:
    result = validate_url({"url": "ftp://example.com/x"}, {})
    assert result.passed is False
    assert "scheme" in result.errors[0]


def test_url_missing_hostname_fails() -> None:
    result = validate_url({"url": "http:///just/a/path"}, {})
    assert result.passed is False
    assert "hostname" in result.errors[0]


def test_url_public_ip_passes_without_dns() -> None:
    result = validate_url({"url": "http://8.8.8.8/"}, {"resolve_dns": False})
    assert result.passed is True


def test_url_blocked_domain() -> None:
    result = validate_url(
        {"url": "http://evil.example/"},
        {"blocked_domains": ["evil.example"], "resolve_dns": False},
    )
    assert result.passed is False
    assert "blocked domain" in result.errors[0]


def test_url_allowed_domains_reject_outside() -> None:
    result = validate_url(
        {"url": "http://other.example/"},
        {"allowed_domains": ["trusted.example"], "resolve_dns": False},
    )
    assert result.passed is False
    assert "allowed_domains" in result.errors[0]


def test_url_allowed_domains_accept_subdomain() -> None:
    result = validate_url(
        {"url": "http://api.trusted.example/"},
        {"allowed_domains": ["trusted.example"], "resolve_dns": False},
    )
    assert result.passed is True


def test_url_blocks_cloud_metadata_hostname() -> None:
    result = validate_url(
        {"url": "http://metadata.google.internal/"},
        {"resolve_dns": False},
    )
    assert result.passed is False
    assert "cloud metadata" in result.errors[0]


def test_url_dns_resolves_to_public_ip_passes(monkeypatch) -> None:
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a, **k: [(None, None, None, "", ("93.184.216.34", 0))],
    )
    result = validate_url({"url": "https://example.com/"}, {})
    assert result.passed is True


def test_url_unresolved_hostname_allowed_when_configured(monkeypatch) -> None:
    def raise_gaierror(*a, **k):
        raise socket.gaierror("no such host")

    monkeypatch.setattr("socket.getaddrinfo", raise_gaierror)
    result = validate_url(
        {"url": "https://nonexistent.invalid/"},
        {"allow_unresolved": True},
    )
    assert result.passed is True


def test_url_unresolved_hostname_blocked_by_default(monkeypatch) -> None:
    def raise_gaierror(*a, **k):
        raise socket.gaierror("no such host")

    monkeypatch.setattr("socket.getaddrinfo", raise_gaierror)
    result = validate_url({"url": "https://nonexistent.invalid/"}, {})
    assert result.passed is False
    assert "could not resolve" in result.errors[0]


def test_is_private_ip_rejects_malformed_dotted_octets() -> None:
    # 4-part host with a non-numeric octet exercises the ValueError branch
    assert _is_private_ip("1.2.3.x") is False
    assert _is_private_ip("not-an-ip") is False


# --- validate_email --------------------------------------------------------


def test_email_accepts_string_recipient() -> None:
    assert validate_email({"to": "user@example.com"}, {}).passed is True


def test_email_rejects_non_list_non_string_recipients() -> None:
    result = validate_email({"to": 123}, {})
    assert result.passed is False
    assert "could not read recipients" in result.errors[0]


def test_email_rejects_invalid_recipient() -> None:
    assert validate_email({"to": ["not-an-email"]}, {}).passed is False


def test_email_blocks_blocked_domain() -> None:
    result = validate_email(
        {"to": ["user@blocked.com"]}, {"blocked_domains": ["blocked.com"]}
    )
    assert result.passed is False
    assert "blocked recipient domain" in result.errors[0]


def test_email_blocks_outside_allowed_domains() -> None:
    result = validate_email(
        {"to": ["user@other.com"]}, {"allowed_domains": ["corp.com"]}
    )
    assert result.passed is False
    assert "allowed_domains" in result.errors[0]


def test_email_allows_allowed_domain_list() -> None:
    result = validate_email(
        {"to": ["user@corp.com", "boss@corp.com"]},
        {"allowed_domains": ["corp.com"]},
    )
    assert result.passed is True


def test_email_blocks_attachments_when_configured() -> None:
    result = validate_email(
        {"to": ["user@corp.com"], "attachments": ["file.pdf"]},
        {"block_attachments": True},
    )
    assert result.passed is False
    assert "attachments" in result.errors[0]


def test_email_custom_recipients_arg() -> None:
    result = validate_email(
        {"recipients": ["user@corp.com"]}, {"recipients_arg": "recipients"}
    )
    assert result.passed is True


# --- validate_regex --------------------------------------------------------


def test_regex_requires_field_option() -> None:
    result = validate_regex({"q": "x"}, {})
    assert result.passed is False
    assert "requires field" in result.errors[0]


def test_regex_allow_pattern_no_match_fails() -> None:
    result = validate_regex({"q": "abc"}, {"field": "q", "allow": "^xyz$"})
    assert result.passed is False
    assert "allow pattern" in result.errors[0]


def test_regex_deny_pattern_match_fails() -> None:
    result = validate_regex({"q": "danger"}, {"field": "q", "deny": "danger"})
    assert result.passed is False
    assert "deny pattern" in result.errors[0]


def test_regex_passes_when_allow_matches_and_deny_absent() -> None:
    result = validate_regex({"q": "hello"}, {"field": "q", "allow": "hell"})
    assert result.passed is True


def test_regex_missing_field_treated_as_empty_string() -> None:
    # field absent -> value "" -> allow pattern must match empty
    result = validate_regex({}, {"field": "absent", "allow": "^$"})
    assert result.passed is True


# --- validate_required_forbidden_fields ------------------------------------


def test_required_field_missing_fails() -> None:
    result = validate_required_forbidden_fields({}, {"required": ["a"]})
    assert result.passed is False
    assert "required field missing" in result.errors[0]


def test_required_and_forbidden_pass() -> None:
    result = validate_required_forbidden_fields(
        {"a": 1}, {"required": ["a"], "forbidden": ["b"]}
    )
    assert result.passed is True


# --- validate_max_field_bytes ----------------------------------------------


def test_max_field_bytes_requires_field_and_int() -> None:
    assert validate_max_field_bytes({}, {}).passed is False
    assert validate_max_field_bytes({}, {"field": "q", "max_bytes": "x"}).passed is False


def test_max_field_bytes_missing_field_passes() -> None:
    result = validate_max_field_bytes({}, {"field": "q", "max_bytes": 10})
    assert result.passed is True


def test_max_field_bytes_over_limit_fails() -> None:
    result = validate_max_field_bytes(
        {"q": "abcdefghij"}, {"field": "q", "max_bytes": 4}
    )
    assert result.passed is False
    assert "exceeds max_bytes" in result.errors[0]


def test_max_field_bytes_within_limit_passes() -> None:
    result = validate_max_field_bytes({"q": "ab"}, {"field": "q", "max_bytes": 4})
    assert result.passed is True


# --- ValidatorEngine dispatch ----------------------------------------------


def test_engine_injects_base_dir_from_context(tmp_path) -> None:
    allowed = tmp_path / "ws"
    allowed.mkdir()
    engine = ValidatorEngine()
    ctx = _ctx({"path": "report.md"}, config_base_dir=str(tmp_path))
    result = engine.validate(
        [ValidatorConfig(name="filesystem_path", options={"allowed_roots": ["."]})],
        ctx,
    )
    assert result.passed is True


def test_engine_dispatches_url_validator() -> None:
    engine = ValidatorEngine()
    result = engine.validate(
        [ValidatorConfig(name="url", options={"resolve_dns": False})],
        _ctx({"url": "http://8.8.8.8/"}),
    )
    assert result.passed is True


def test_engine_dispatches_email_validator() -> None:
    engine = ValidatorEngine()
    result = engine.validate(
        [ValidatorConfig(name="email", options={})],
        _ctx({"to": ["a@b.com"]}),
    )
    assert result.passed is True


def test_engine_dispatches_regex_validator() -> None:
    engine = ValidatorEngine()
    result = engine.validate(
        [ValidatorConfig(name="regex", options={"field": "q", "allow": "x"})],
        _ctx({"q": "x"}),
    )
    assert result.passed is True


def test_engine_dispatches_required_forbidden_fields() -> None:
    engine = ValidatorEngine()
    result = engine.validate(
        [ValidatorConfig(name="required_forbidden_fields", options={"required": ["a"]})],
        _ctx({"a": 1}),
    )
    assert result.passed is True


def test_engine_dispatches_max_field_bytes() -> None:
    engine = ValidatorEngine()
    result = engine.validate(
        [ValidatorConfig(name="max_field_bytes", options={"field": "q", "max_bytes": 100})],
        _ctx({"q": "small"}),
    )
    assert result.passed is True


def test_engine_unknown_validator_fails() -> None:
    engine = ValidatorEngine()
    result = engine.validate([ValidatorConfig(name="mystery", options={})], _ctx({}))
    assert result.passed is False
    assert "unknown validator" in result.errors[0]


# --- input_policy remaining branches ---------------------------------------


def test_input_policy_allowed_ancestor_with_non_dict_value() -> None:
    # "a" is an allowed ancestor of "a.b" but its value is not a dict
    policy = InputPolicy(allowed_fields=["a.b"])
    result = validate_input_policy({"a": 5}, policy)
    assert result.passed is False
    assert "must be an object" in result.errors[0]


def test_input_policy_max_field_bytes_non_string_value() -> None:
    # non-string value goes through json.dumps in _encoded_size
    policy = InputPolicy(max_field_bytes={"blob": 2})
    result = validate_input_policy({"blob": {"x": 1}}, policy)
    assert result.passed is False
    assert "exceeds" in result.errors[0]
