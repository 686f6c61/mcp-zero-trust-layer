from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


Decision = Literal["allow", "deny", "hide", "require_approval", "redact", "limit", "transform", "log"]


class PolicyDecision(BaseModel):
    decision: Decision
    policy_id: str | None = None
    reason: str
    risk: str | None = None
    redactions: list[str] = Field(default_factory=list)
    validation_errors: list[str] = Field(default_factory=list)
    approval_required: bool = False
    dry_run: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

