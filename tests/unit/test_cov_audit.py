from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_zero_trust_layer.audit import AuditLogger, search_audit_events, verify_audit_hash_chain
from mcp_zero_trust_layer.audit.search import iter_audit_events
from mcp_zero_trust_layer.config.models import AuditConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.policy import PolicyDecision

# ---------------------------------------------------------------------------
# logger.py
# ---------------------------------------------------------------------------


def test_hmac_key_env_missing_fails_closed(monkeypatch) -> None:
    monkeypatch.delenv("MCPZT_MISSING_HMAC_KEY", raising=False)
    with pytest.raises(ValueError):
        AuditLogger(AuditConfig(destination="file", hmac_key_env="MCPZT_MISSING_HMAC_KEY"))


def test_strict_audit_reraises_write_failures(tmp_path: Path) -> None:
    # path points at a directory, so opening it for append raises OSError.
    logger = AuditLogger(AuditConfig(destination="file", path=str(tmp_path), strict=True))
    with pytest.raises(OSError):
        logger.log_decision(
            RequestContext(server="github", method="tools/list"),
            PolicyDecision(decision="allow", reason="test"),
        )


def test_stdout_destination_with_hash_chain(capsys) -> None:
    logger = AuditLogger(AuditConfig(destination="stdout", hash_chain=True))
    logger.log_decision(
        RequestContext(server="github", method="tools/list"),
        PolicyDecision(decision="allow", reason="test"),
    )
    printed = json.loads(capsys.readouterr().out.strip())
    assert printed["event_hash"]
    assert printed["sequence"] == 1


def test_log_approval_event(tmp_path: Path) -> None:
    logger = AuditLogger(
        AuditConfig(destination="file", path=str(tmp_path / "audit.jsonl"), hash_chain=False)
    )
    event = logger.log_approval("created", {"id": "appr_1", "token": "secret"})
    assert event["approval"]["token"] == "[REDACTED]"


def test_last_event_returns_none_for_missing_file(tmp_path: Path) -> None:
    logger = AuditLogger(AuditConfig(destination="file", path=str(tmp_path / "audit.jsonl")))
    assert logger._last_event(tmp_path / "does-not-exist.jsonl") is None


def test_last_event_returns_none_for_blank_file(tmp_path: Path) -> None:
    logger = AuditLogger(AuditConfig(destination="file", path=str(tmp_path / "audit.jsonl")))
    blank = tmp_path / "blank.jsonl"
    blank.write_text("\n", encoding="utf-8")
    assert logger._last_event(blank) is None


def test_last_event_returns_none_for_invalid_json(tmp_path: Path) -> None:
    logger = AuditLogger(AuditConfig(destination="file", path=str(tmp_path / "audit.jsonl")))
    bad = tmp_path / "bad.jsonl"
    bad.write_text("not valid json\n", encoding="utf-8")
    assert logger._last_event(bad) is None


def test_verify_hash_chain_missing_file_returns_false(tmp_path: Path) -> None:
    ok, message = verify_audit_hash_chain(tmp_path / "missing.jsonl")
    assert ok is False
    assert message


def test_verify_hash_chain_invalid_json_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("{not json}\n", encoding="utf-8")
    ok, message = verify_audit_hash_chain(path)
    assert ok is False
    assert "invalid JSON" in message


def test_verify_hash_chain_previous_hash_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(json.dumps({"previous_event_hash": "bogus"}) + "\n", encoding="utf-8")
    ok, message = verify_audit_hash_chain(path)
    assert ok is False
    assert "previous_event_hash mismatch" in message


def test_verify_hash_chain_sequence_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps({"previous_event_hash": None, "sequence": 9}) + "\n", encoding="utf-8"
    )
    ok, message = verify_audit_hash_chain(path)
    assert ok is False
    assert "sequence mismatch" in message


# ---------------------------------------------------------------------------
# search.py
# ---------------------------------------------------------------------------


def _write_events(path: Path, events: list) -> None:
    path.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")


def test_search_non_positive_limit_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_events(path, [{"event_type": "policy_decision"}])
    assert search_audit_events(path, limit=0) == []


def test_search_missing_file_returns_empty(tmp_path: Path) -> None:
    assert search_audit_events(tmp_path / "missing.jsonl") == []


def test_search_stops_at_limit(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_events(
        path,
        [
            {"event_type": "policy_decision", "server": "github"},
            {"event_type": "policy_decision", "server": "github"},
            {"event_type": "policy_decision", "server": "github"},
        ],
    )
    assert len(search_audit_events(path, server="github", limit=1)) == 1


def test_search_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps({"event_type": "approval"}) + "\n\n   \n", encoding="utf-8"
    )
    assert len(search_audit_events(path, event_type="approval")) == 1


def test_iter_events_raises_on_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("{bad}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        iter_audit_events(path)


def test_iter_events_raises_on_non_object(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("[1, 2, 3]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a JSON object"):
        iter_audit_events(path)


def test_search_time_window(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_events(
        path,
        [
            {"event_type": "policy_decision", "timestamp": "2026-06-14T09:00:00Z"},
            {"event_type": "policy_decision", "timestamp": "2026-06-14T12:00:00Z"},
            {"event_type": "policy_decision", "timestamp": "2026-06-14T15:00:00Z"},
            {"event_type": "policy_decision", "timestamp": 12345},
        ],
    )
    since = datetime(2026, 6, 14, 10, 0, tzinfo=UTC)
    until = datetime(2026, 6, 14, 13, 0, tzinfo=UTC)
    results = search_audit_events(path, since=since, until=until)
    assert [event["timestamp"] for event in results] == ["2026-06-14T12:00:00Z"]
