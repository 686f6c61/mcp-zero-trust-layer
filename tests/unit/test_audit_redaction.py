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


def test_redacts_broader_secret_material() -> None:
    assert redact_sensitive({"credential": "x"})["credential"] == "[REDACTED]"
    assert redact_sensitive({"access_key": "x"})["access_key"] == "[REDACTED]"
    assert redact_sensitive({"private_key": "x"})["private_key"] == "[REDACTED]"
    assert "[REDACTED]" in redact_sensitive("key AKIAIOSFODNN7EXAMPLE here")


def test_hmac_chain_detects_forged_recompute(tmp_path: Path) -> None:
    import json

    from mcp_zero_trust_layer.audit.logger import event_hash

    audit_path = tmp_path / "audit.jsonl"
    key = "super-audit-secret"
    logger = AuditLogger(
        AuditConfig(destination="file", path=str(audit_path), hash_chain=True, hmac_key=key)
    )
    logger.log_decision(
        RequestContext(server="github", method="tools/list"),
        PolicyDecision(decision="allow", reason="first"),
    )

    ok, _ = verify_audit_hash_chain(audit_path, key=key)
    assert ok is True

    event = json.loads(audit_path.read_text(encoding="utf-8").strip())
    event["reason"] = "tampered"
    event["event_hash"] = event_hash(event)  # attacker recomputes without the key
    audit_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")

    ok, message = verify_audit_hash_chain(audit_path, key=key)
    assert ok is False
    assert "event_hash mismatch" in message


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
