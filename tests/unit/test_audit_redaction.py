from __future__ import annotations

from pathlib import Path

from mcp_zero_trust_layer.audit import AuditLogger, redact_sensitive, verify_audit_hash_chain
from mcp_zero_trust_layer.config.models import AuditConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.policy import PolicyDecision


def test_redacts_secret_keys_recursively() -> None:
    value = {
        "nested": {
            "api_key": "abc",
            "safe": "ok",
        },
        "headers": {"authorization": "Bearer abc"},
    }

    assert redact_sensitive(value) == {
        "nested": {"api_key": "[REDACTED]", "safe": "ok"},
        "headers": {"authorization": "[REDACTED]"},
    }


def test_redacts_secret_values() -> None:
    assert redact_sensitive("Authorization: Bearer abc.def") == "Authorization: [REDACTED]"


def test_non_strict_audit_logs_write_failures_to_stderr(
    tmp_path: Path,
    capsys,
) -> None:
    logger = AuditLogger(AuditConfig(destination="file", path=str(tmp_path), strict=False))

    logger.log_decision(
        RequestContext(server="github", method="tools/list"),
        PolicyDecision(decision="allow", reason="test"),
    )

    assert "mcpzt audit write failed" in capsys.readouterr().err


def test_audit_hash_chain_verifies_and_detects_tampering(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(AuditConfig(destination="file", path=str(audit_path), hash_chain=True))

    logger.log_decision(
        RequestContext(server="github", method="tools/list"),
        PolicyDecision(decision="allow", reason="first"),
    )
    logger.log_decision(
        RequestContext(server="github", method="tools/call", capability="github.search"),
        PolicyDecision(decision="deny", reason="second"),
    )

    ok, message = verify_audit_hash_chain(audit_path)
    assert ok is True
    assert "verified 2 event" in message

    tampered = audit_path.read_text(encoding="utf-8").replace("second", "changed")
    audit_path.write_text(tampered, encoding="utf-8")

    ok, message = verify_audit_hash_chain(audit_path)
    assert ok is False
    assert "event_hash mismatch" in message
