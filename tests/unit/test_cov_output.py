from __future__ import annotations

from mcp_zero_trust_layer.config.models import PolicyConfig
from mcp_zero_trust_layer.output import OutputEnforcer
from mcp_zero_trust_layer.output.enforcer import _redact_patterns


def _policy(output: dict | None) -> PolicyConfig:
    return PolicyConfig.model_validate({"id": "p", "effect": "allow", "output": output})


def test_enforce_no_output_policy_passes_through() -> None:
    policy = _policy(None)
    allowed, output, reason = OutputEnforcer().enforce({"a": 1}, policy)
    assert allowed is True
    assert output == {"a": 1}
    assert reason is None


def test_enforce_max_bytes_blocks() -> None:
    policy = _policy({"max_bytes": 5})
    allowed, output, reason = OutputEnforcer().enforce({"a": "long value"}, policy)
    assert allowed is False
    assert output is None
    assert "max_bytes" in reason


def test_enforce_include_fields_projects_dict() -> None:
    policy = _policy({"include_fields": ["keep"]})
    allowed, output, reason = OutputEnforcer().enforce(
        {"keep": 1, "drop": 2}, policy
    )
    assert allowed is True
    assert output == {"keep": 1}
    assert reason is None


def test_enforce_combined_include_and_redact() -> None:
    policy = _policy({"include_fields": ["keep", "secret"], "redact_fields": ["secret"]})
    allowed, output, _ = OutputEnforcer().enforce(
        {"keep": 1, "secret": "s", "drop": 2}, policy
    )
    assert allowed is True
    assert output == {"keep": 1, "secret": "[REDACTED]"}


def test_enforce_redact_fields_recurses_into_lists() -> None:
    policy = _policy({"redact_fields": ["secret"]})
    allowed, output, _ = OutputEnforcer().enforce(
        {"items": [{"secret": 1, "ok": 2}, {"secret": 3}]}, policy
    )
    assert allowed is True
    assert output == {"items": [{"secret": "[REDACTED]", "ok": 2}, {"secret": "[REDACTED]"}]}


def test_redact_patterns_leaves_non_string_scalars_untouched() -> None:
    import re

    patterns = [re.compile(r"\d+")]
    # int scalar hits the final passthrough return in _redact_patterns
    assert _redact_patterns(42, patterns) == 42
    assert _redact_patterns(True, patterns) is True
    assert _redact_patterns(None, patterns) is None


def test_redact_patterns_recurses_lists_and_dicts() -> None:
    import re

    patterns = [re.compile(r"secret")]
    value = {"a": ["secret", 1], "b": {"c": "secret text"}}
    assert _redact_patterns(value, patterns) == {
        "a": ["[REDACTED]", 1],
        "b": {"c": "[REDACTED] text"},
    }
