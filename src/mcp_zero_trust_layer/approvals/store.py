from __future__ import annotations

import contextlib
import os
import hashlib
import json
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
        self.path = Path(config.path)
        self.lock_path = Path(f"{self.path}.lock")
        self.default_ttl_seconds = config.default_ttl_seconds

    def create(self, context: RequestContext, policy_id: str) -> ApprovalRequest:
        with self._locked():
            request = ApprovalRequest(
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
            approvals = self._load_unlocked()
            approvals[request.id] = request
            self._save_unlocked(approvals)
            return request

    def get(self, approval_id: str) -> ApprovalRequest | None:
        return self._load().get(approval_id)

    def list(self) -> list[ApprovalRequest]:
        return sorted(self._load().values(), key=lambda item: item.created_at)

    def set_status(
        self,
        approval_id: str,
        status: Literal["pending", "approved", "denied", "expired"],
        *,
        decided_by: str | None = None,
        decision_comment: str | None = None,
    ) -> ApprovalRequest:
        with self._locked():
            approvals = self._load_unlocked()
            if approval_id not in approvals:
                raise KeyError(approval_id)
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
            updated = approvals[approval_id].model_copy(update=update)
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

    def _load(self) -> dict[str, ApprovalRequest]:
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


def hash_arguments(arguments: dict[str, Any]) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
