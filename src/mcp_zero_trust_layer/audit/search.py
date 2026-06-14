from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def search_audit_events(
    path: str | Path,
    *,
    event_type: str | None = None,
    server: str | None = None,
    decision: str | None = None,
    policy_id: str | None = None,
    correlation_id: str | None = None,
    approval_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Read a JSONL audit file and return events matching the supplied filters."""
    if limit <= 0:
        return []

    matches: list[dict[str, Any]] = []
    for event in iter_audit_events(path):
        if not _event_matches(
            event,
            event_type=event_type,
            server=server,
            decision=decision,
            policy_id=policy_id,
            correlation_id=correlation_id,
            approval_id=approval_id,
            since=since,
            until=until,
        ):
            continue
        matches.append(event)
        if len(matches) >= limit:
            break
    return matches


def iter_audit_events(path: str | Path) -> list[dict[str, Any]]:
    target = Path(path)
    if not target.exists():
        return []

    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(target.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_number}: invalid JSON: {exc}") from exc
        if not isinstance(event, dict):
            raise ValueError(f"line {line_number}: audit event must be a JSON object")
        events.append(event)
    return events


def _event_matches(
    event: dict[str, Any],
    *,
    event_type: str | None,
    server: str | None,
    decision: str | None,
    policy_id: str | None,
    correlation_id: str | None,
    approval_id: str | None,
    since: datetime | None,
    until: datetime | None,
) -> bool:
    checks = [
        _field_matches(event, "event_type", event_type),
        _field_matches(event, "server", server),
        _field_matches(event, "decision", decision),
        _field_matches(event, "policy_id", policy_id),
        _field_matches(event, "correlation_id", correlation_id),
        _approval_matches(event, approval_id),
        _time_matches(event, since=since, until=until),
    ]
    return all(checks)


def _field_matches(event: dict[str, Any], field: str, expected: str | None) -> bool:
    if expected is None:
        return True
    return event.get(field) == expected


def _approval_matches(event: dict[str, Any], approval_id: str | None) -> bool:
    if approval_id is None:
        return True
    approval = event.get("approval")
    return isinstance(approval, dict) and approval.get("id") == approval_id


def _time_matches(
    event: dict[str, Any],
    *,
    since: datetime | None,
    until: datetime | None,
) -> bool:
    if since is None and until is None:
        return True
    timestamp = event.get("timestamp")
    if not isinstance(timestamp, str):
        return False
    parsed = _parse_timestamp(timestamp)
    if since is not None and parsed < since:
        return False
    if until is not None and parsed > until:
        return False
    return True


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
