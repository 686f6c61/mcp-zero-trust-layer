from __future__ import annotations

import contextlib
import os
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]

from mcp_zero_trust_layer.approvals.models import ApprovalRequest
from mcp_zero_trust_layer.audit import redact_sensitive
from mcp_zero_trust_layer.config.models import ApprovalsConfig
from mcp_zero_trust_layer.core.context import RequestContext


class ApprovalStore:
    def __init__(self, config: ApprovalsConfig):
        self.backend = config.backend
        self.path = Path(config.path)
        self.lock_path = Path(f"{self.path}.lock")
        self.default_ttl_seconds = config.default_ttl_seconds

    def create(self, context: RequestContext, policy_id: str) -> ApprovalRequest:
        request = self._new_request(context, policy_id)
        if self.backend == "sqlite":
            self._sqlite_insert(request)
            return request
        with self._locked():
            approvals = self._load_unlocked()
            approvals[request.id] = request
            self._save_unlocked(approvals)
            return request

    def get(self, approval_id: str) -> ApprovalRequest | None:
        if self.backend == "sqlite":
            return self._sqlite_get(approval_id)
        return self._load().get(approval_id)

    def list(self) -> list[ApprovalRequest]:
        if self.backend == "sqlite":
            return self._sqlite_list()
        return sorted(self._load().values(), key=lambda item: item.created_at)

    def set_status(
        self,
        approval_id: str,
        status: Literal["pending", "approved", "denied", "expired"],
        *,
        decided_by: str | None = None,
        decision_comment: str | None = None,
    ) -> ApprovalRequest:
        if self.backend == "sqlite":
            return self._sqlite_set_status(
                approval_id,
                status,
                decided_by=decided_by,
                decision_comment=decision_comment,
            )
        with self._locked():
            approvals = self._load_unlocked()
            if approval_id not in approvals:
                raise KeyError(approval_id)
            updated = _with_status(
                approvals[approval_id],
                status,
                decided_by=decided_by,
                decision_comment=decision_comment,
            )
            approvals[approval_id] = updated
            self._save_unlocked(approvals)
            return updated

    def is_valid_for(self, approval_id: str, context: RequestContext, policy_id: str) -> bool:
        approval = self.get(approval_id)
        if approval is None or not approval.is_active():
            return False
        return all(
            [
                approval.policy_id == policy_id,
                approval.server == context.server,
                approval.capability == context.capability,
                approval.capability_type == context.capability_type,
                approval.identity_subject == context.identity.subject,
                approval.client_id == context.identity.client_id,
                approval.agent_id == context.identity.agent_id,
                approval.arguments_hash == hash_arguments(context.arguments),
            ]
        )

    def _new_request(self, context: RequestContext, policy_id: str) -> ApprovalRequest:
        return ApprovalRequest(
            server=context.server,
            capability=context.capability,
            capability_type=context.capability_type,
            policy_id=policy_id,
            identity_subject=context.identity.subject,
            client_id=context.identity.client_id,
            agent_id=context.identity.agent_id,
            arguments_hash=hash_arguments(context.arguments),
            arguments_redacted=redact_sensitive(context.arguments),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.default_ttl_seconds),
        )

    def _load(self) -> dict[str, ApprovalRequest]:
        if not self.path.exists():
            return {}
        with self._locked():
            return self._load_unlocked()

    def _load_unlocked(self) -> dict[str, ApprovalRequest]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        return {
            approval_id: ApprovalRequest.model_validate(payload)
            for approval_id, payload in raw.items()
        }

    def _save_unlocked(self, approvals: dict[str, ApprovalRequest]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            approval_id: approval.model_dump(mode="json")
            for approval_id, approval in approvals.items()
        }
        tmp_path = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp_path, self.path)

    @contextlib.contextmanager
    def _locked(self) -> Any:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as handle:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _sqlite_insert(self, approval: ApprovalRequest) -> None:
        with self._sqlite_connection() as connection:
            _ensure_sqlite_schema(connection)
            connection.execute(
                """
                INSERT INTO approvals (
                  id, status, server, capability, capability_type, policy_id,
                  identity_subject, client_id, agent_id, arguments_hash,
                  created_at, expires_at, payload
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _sqlite_row_values(approval),
            )

    def _sqlite_get(self, approval_id: str) -> ApprovalRequest | None:
        with self._sqlite_connection() as connection:
            _ensure_sqlite_schema(connection)
            row = connection.execute(
                "SELECT payload FROM approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
        if row is None:
            return None
        return _approval_from_sqlite_payload(row["payload"])

    def _sqlite_list(self) -> list[ApprovalRequest]:
        with self._sqlite_connection() as connection:
            _ensure_sqlite_schema(connection)
            rows = connection.execute(
                "SELECT payload FROM approvals ORDER BY created_at ASC, id ASC"
            ).fetchall()
        return [_approval_from_sqlite_payload(row["payload"]) for row in rows]

    def _sqlite_set_status(
        self,
        approval_id: str,
        status: Literal["pending", "approved", "denied", "expired"],
        *,
        decided_by: str | None = None,
        decision_comment: str | None = None,
    ) -> ApprovalRequest:
        with self._sqlite_connection() as connection:
            _ensure_sqlite_schema(connection)
            row = connection.execute(
                "SELECT payload FROM approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise KeyError(approval_id)
            updated = _with_status(
                _approval_from_sqlite_payload(row["payload"]),
                status,
                decided_by=decided_by,
                decision_comment=decision_comment,
            )
            connection.execute(
                """
                UPDATE approvals
                SET status = ?, payload = ?
                WHERE id = ?
                """,
                (updated.status, _sqlite_payload(updated), approval_id),
            )
            return updated

    @contextlib.contextmanager
    def _sqlite_connection(self) -> Any:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()


def hash_arguments(arguments: dict[str, Any]) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _with_status(
    approval: ApprovalRequest,
    status: Literal["pending", "approved", "denied", "expired"],
    *,
    decided_by: str | None,
    decision_comment: str | None,
) -> ApprovalRequest:
    update: dict[str, Any] = {"status": status}
    if status == "pending":
        update.update(
            {
                "decided_at": None,
                "decided_by": None,
                "decision_comment": None,
            }
        )
    else:
        update["decided_at"] = datetime.now(timezone.utc)
        update["decided_by"] = decided_by
        update["decision_comment"] = decision_comment
    return approval.model_copy(update=update)


def _ensure_sqlite_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS approvals (
          id TEXT PRIMARY KEY,
          status TEXT NOT NULL,
          server TEXT NOT NULL,
          capability TEXT,
          capability_type TEXT NOT NULL,
          policy_id TEXT NOT NULL,
          identity_subject TEXT NOT NULL,
          client_id TEXT,
          agent_id TEXT,
          arguments_hash TEXT NOT NULL,
          created_at TEXT NOT NULL,
          expires_at TEXT,
          payload TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_approvals_status_created ON approvals(status, created_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_approvals_server_created ON approvals(server, created_at)"
    )


def _sqlite_row_values(approval: ApprovalRequest) -> tuple[Any, ...]:
    return (
        approval.id,
        approval.status,
        approval.server,
        approval.capability,
        approval.capability_type,
        approval.policy_id,
        approval.identity_subject,
        approval.client_id,
        approval.agent_id,
        approval.arguments_hash,
        approval.created_at.isoformat(),
        approval.expires_at.isoformat() if approval.expires_at else None,
        _sqlite_payload(approval),
    )


def _sqlite_payload(approval: ApprovalRequest) -> str:
    return json.dumps(approval.model_dump(mode="json"), sort_keys=True)


def _approval_from_sqlite_payload(payload: str) -> ApprovalRequest:
    return ApprovalRequest.model_validate(json.loads(payload))
