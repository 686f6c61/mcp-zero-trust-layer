from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from mcp_zero_trust_layer.config.models import AuditConfig
from mcp_zero_trust_layer.core.context import RequestContext
from mcp_zero_trust_layer.policy import PolicyDecision

SECRET_KEY_RE = re.compile(r"(password|token|api[_-]?key|secret|authorization|cookie)", re.I)
SECRET_VALUE_RES = [
    re.compile(r"Bearer\s+[A-Z0-9_.-]+", re.I),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
]


class AuditLogger:
    def __init__(self, config: AuditConfig):
        self.config = config

    def log_decision(
        self,
        context: RequestContext,
        decision: PolicyDecision,
        *,
        upstream_called: bool | None = None,
        upstream_status: str | None = None,
    ) -> dict[str, Any]:
        event = {
            "event_id": f"evt_{uuid4().hex}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": context.correlation_id or f"corr_{uuid4().hex}",
            "event_type": "policy_decision",
            "identity": redact_sensitive(context.identity.model_dump()),
            "server": context.server,
            "method": context.method,
            "capability_type": context.capability_type,
            "capability": context.capability,
            "decision": decision.decision,
            "policy_id": decision.policy_id,
            "reason": decision.reason,
            "arguments_redacted": redact_sensitive(context.arguments),
            "dry_run": decision.dry_run,
            "approval_required": decision.approval_required,
            "upstream_called": upstream_called,
            "upstream_status": upstream_status,
        }
        self._write(event)
        return event

    def log_approval(self, action: str, approval: dict[str, Any]) -> dict[str, Any]:
        event = {
            "event_id": f"evt_{uuid4().hex}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "approval",
            "action": action,
            "approval": redact_sensitive(approval),
        }
        self._write(event)
        return event

    def _write(self, event: dict[str, Any]) -> None:
        if self.config.hash_chain:
            event = self._with_hash(event)
        line = json.dumps(event, sort_keys=True)
        if self.config.destination == "stdout":
            print(line)
            return

        path = Path(self.config.path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            if self.config.strict:
                raise
            log_to_stderr(f"mcpzt audit write failed for {path}")

    def _with_hash(self, event: dict[str, Any]) -> dict[str, Any]:
        event = dict(event)
        event["previous_event_hash"] = self._previous_hash()
        event["event_hash"] = event_hash(event)
        return event

    def _previous_hash(self) -> str | None:
        if self.config.destination != "file":
            return None
        path = Path(self.config.path)
        if not path.exists():
            return None
        try:
            with path.open("rb") as handle:
                handle.seek(0, 2)
                position = handle.tell()
                if position == 0:
                    return None
                buffer = bytearray()
                position -= 1
                while position >= 0:
                    handle.seek(position)
                    char = handle.read(1)
                    if char == b"\n" and buffer:
                        break
                    if char != b"\n":
                        buffer.extend(char)
                    position -= 1
            last_line = bytes(reversed(buffer)).decode("utf-8")
            if not last_line:
                return None
            event = json.loads(last_line)
            previous = event.get("event_hash")
            return previous if isinstance(previous, str) else None
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None


def event_hash(event: dict[str, Any]) -> str:
    hashed = {key: value for key, value in event.items() if key != "event_hash"}
    payload = json.dumps(hashed, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_audit_hash_chain(path: str | Path) -> tuple[bool, str]:
    previous: str | None = None
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return False, str(exc)

    for index, line in enumerate(lines, start=1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            return False, f"line {index}: invalid JSON: {exc}"
        if event.get("previous_event_hash") != previous:
            return False, f"line {index}: previous_event_hash mismatch"
        expected = event_hash(event)
        if event.get("event_hash") != expected:
            return False, f"line {index}: event_hash mismatch"
        previous = expected
    return True, f"verified {len(lines)} event(s)"


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_sensitive(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str):
        redacted = value
        for pattern in SECRET_VALUE_RES:
            redacted = pattern.sub("[REDACTED]", redacted)
        return redacted
    return value


def log_to_stderr(message: str) -> None:
    print(message, file=sys.stderr)
