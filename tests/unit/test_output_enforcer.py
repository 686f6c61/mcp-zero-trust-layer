from __future__ import annotations

from mcp_zero_trust_layer.config.models import PolicyConfig
from mcp_zero_trust_layer.output import OutputEnforcer


def test_output_redacts_configured_fields() -> None:
    policy = PolicyConfig.model_validate(
        {
            "id": "redact-pii",
            "effect": "redact",
            "output": {"redact_fields": ["email"]},
        }
    )

    allowed, output, reason = OutputEnforcer().enforce({"email": "a@example.com", "name": "Ana"}, policy)

    assert allowed is True
    assert reason is None
    assert output == {"email": "[REDACTED]", "name": "Ana"}


def test_output_redacts_values_by_pattern_inside_text() -> None:
    policy = PolicyConfig.model_validate(
        {
            "id": "redact-ssn",
            "effect": "redact",
            "output": {"redact_patterns": [r"\d{3}-\d{2}-\d{4}"]},
        }
    )

    allowed, output, reason = OutputEnforcer().enforce(
        {"content": [{"type": "text", "text": "SSN is 123-45-6789 ok"}]}, policy
    )

    assert allowed is True
    assert reason is None
    assert output == {"content": [{"type": "text", "text": "SSN is [REDACTED] ok"}]}


def test_output_blocks_matching_patterns() -> None:
    policy = PolicyConfig.model_validate(
        {
            "id": "block-private-key",
            "effect": "deny",
            "output": {"deny_if_matches": ["-----BEGIN PRIVATE KEY-----"]},
        }
    )

    allowed, output, reason = OutputEnforcer().enforce(
        {"text": "-----BEGIN PRIVATE KEY-----"}, policy
    )

    assert allowed is False
    assert output is None
    assert reason is not None

