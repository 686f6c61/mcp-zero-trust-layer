from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: f"appr_{uuid4().hex}")
    status: Literal["pending", "approved", "denied", "expired", "consumed"] = "pending"
    server: str
    method: str | None = None
    capability: str | None = None
    capability_type: str
    policy_id: str
    identity_subject: str
    client_id: str | None = None
    agent_id: str | None = None
    request_binding: str | None = None
    arguments_hash: str
    arguments_redacted: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    consumed_at: datetime | None = None
    decided_at: datetime | None = None
    decided_by: str | None = None
    decision_comment: str | None = None

    def is_active(self) -> bool:
        if self.status != "approved":
            return False
        if self.expires_at is None:
            return True
        return self.expires_at > datetime.now(UTC)
