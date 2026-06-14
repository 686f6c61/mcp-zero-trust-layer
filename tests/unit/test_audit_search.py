from __future__ import annotations

import json
from pathlib import Path

from mcp_zero_trust_layer.audit import search_audit_events


def test_search_audit_events_filters_policy_decisions(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    events = [
        {
            "timestamp": "2026-06-14T10:00:00+00:00",
            "event_type": "policy_decision",
            "correlation_id": "corr_1",
            "server": "github",
            "decision": "allow",
            "policy_id": "allow-search",
        },
        {
            "timestamp": "2026-06-14T10:01:00+00:00",
            "event_type": "policy_decision",
            "correlation_id": "corr_2",
            "server": "postgres",
            "decision": "deny",
            "policy_id": "readonly-sql",
        },
        {
            "timestamp": "2026-06-14T10:02:00+00:00",
            "event_type": "approval",
            "approval": {"id": "appr_123", "server": "github"},
        },
    ]
    audit.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")

    denied = search_audit_events(audit, decision="deny")
    approvals = search_audit_events(audit, approval_id="appr_123")

    assert [event["policy_id"] for event in denied] == ["readonly-sql"]
    assert approvals[0]["approval"]["id"] == "appr_123"
