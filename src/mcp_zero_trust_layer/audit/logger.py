from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]

from mcp_zero_trust_layer.config.models import AuditConfig
from mcp_zero_trust_layer.config.secrets import SecretError, resolve_secret_value
from mcp_zero_trust_layer.core.context import RequestContext
from mcp_zero_trust_layer.policy import PolicyDecision

SECRET_KEY_RE = re.compile(
    r"(password|passwd|passphrase|pwd|token|api[_-]?key|secret|credential|"
    r"authorization|cookie|private[_-]?key|access[_-]?key|session[_-]?key)",
    re.I,
)
SECRET_VALUE_RES = [
    re.compile(r"Bearer\s+\S+", re.I),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]


class AuditLogger:
    def __init__(self, config: AuditConfig):
        self.config = config
        self._stdout_lock = threading.Lock()
        self._stdout_previous: str | None = None
        self._stdout_sequence = 0
        self._hmac_key = self._resolve_hmac_key(config)

    @staticmethod
    def _resolve_hmac_key(config: AuditConfig) -> bytes | None:
        raw = f"env:{config.hmac_key_env}" if config.hmac_key_env else config.hmac_key
        if not raw:
            return None
        try:
            return resolve_secret_value(raw, field="audit.hmac_key").encode("utf-8")
        except SecretError as exc:
            raise ValueError(str(exc)) from exc

    def log_decision(
        self,
        context: RequestContext,
        decision: PolicyDecision,
        *,
        upstream_called: bool | None = None,
        upstream_status: str | None = None,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        event = {
            "event_id": f"evt_{uuid4().hex}",
            "timestamp": datetime.now(UTC).isoformat(),
            "correlation_id": context.correlation_id or f"corr_{uuid4().hex}",
            "event_type": "policy_decision",
            "identity": redact_sensitive(context.identity.model_dump()),
            "server": context.server,
            "method": context.method,
            "direction": context.direction,
            "approval_id": approval_id,
            "request_binding": context.metadata.get("request_binding"),
            "arguments_hash": hashlib.sha256(
                json.dumps(context.arguments, sort_keys=True, separators=(",", ":"), default=str)
                .encode("utf-8")
            ).hexdigest(),
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
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": "approval",
            "action": action,
            "approval": redact_sensitive(approval),
        }
        self._write(event)
        return event

    def _write(self, event: dict[str, Any]) -> None:
        if self.config.destination == "stdout":
            with self._stdout_lock:
                if self.config.hash_chain:
                    event = self._with_hash(
                        event,
                        previous=self._stdout_previous,
                        sequence=self._stdout_sequence + 1,
                    )
                print(json.dumps(event, sort_keys=True), flush=True)
                if self.config.hash_chain:
                    self._stdout_previous = event["event_hash"]
                    self._stdout_sequence = event["sequence"]
            return

        path = Path(self.config.path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Serialise read-last-hash + append so concurrent writers cannot fork the chain.
            with self._locked_append(path) as handle:
                if self.config.hash_chain:
                    previous, sequence = self._previous_chain_state(path)
                    event = self._with_hash(event, previous=previous, sequence=sequence + 1)
                handle.write(json.dumps(event, sort_keys=True) + "\n")
        except OSError:
            if self.config.strict:
                raise
            log_to_stderr(f"mcpzt audit write failed for {path}")

    @contextlib.contextmanager
    def _locked_append(self, path: Path) -> Any:
        # 0600 so audit records are not world-readable/writable by default.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        handle = os.fdopen(fd, "a", encoding="utf-8")
        try:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield handle
                handle.flush()
                if self.config.strict:
                    os.fsync(handle.fileno())
            finally:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    def _with_hash(
        self, event: dict[str, Any], *, previous: str | None, sequence: int
    ) -> dict[str, Any]:
        event = dict(event)
        event["previous_event_hash"] = previous
        event["sequence"] = sequence
        event["event_hash"] = event_hash(event, key=self._hmac_key)
        return event

    def _previous_chain_state(self, path: Path) -> tuple[str | None, int]:
        event = self._last_event(path)
        if event is None:
            return None, 0
        previous = event.get("event_hash")
        sequence = event.get("sequence")
        return (
            previous if isinstance(previous, str) else None,
            sequence if isinstance(sequence, int) else 0,
        )

    def _last_event(self, path: Path) -> dict[str, Any] | None:
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
            parsed = json.loads(last_line)
            return parsed if isinstance(parsed, dict) else None
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None


def event_hash(event: dict[str, Any], key: bytes | None = None) -> str:
    hashed = {name: value for name, value in event.items() if name != "event_hash"}
    payload = json.dumps(hashed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if key is not None:
        return hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


def verify_audit_hash_chain(path: str | Path, key: bytes | str | None = None) -> tuple[bool, str]:
    hmac_key = key.encode("utf-8") if isinstance(key, str) else key
    previous: str | None = None
    expected_sequence = 0
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return False, str(exc)

    for index, line in enumerate(lines, start=1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            return False, f"line {index}: invalid JSON: {exc}"
        if not isinstance(event, dict):
            return False, f"line {index}: event must be a JSON object"
        if event.get("previous_event_hash") != previous:
            return False, f"line {index}: previous_event_hash mismatch"
        if "sequence" in event:
            expected_sequence += 1
            if event.get("sequence") != expected_sequence:
                return False, f"line {index}: sequence mismatch"
        expected = event_hash(event, key=hmac_key)
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
        redacted_text = value
        for pattern in SECRET_VALUE_RES:
            redacted_text = pattern.sub("[REDACTED]", redacted_text)
        return redacted_text
    return value


def log_to_stderr(message: str) -> None:
    print(message, file=sys.stderr)
