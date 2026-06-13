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

