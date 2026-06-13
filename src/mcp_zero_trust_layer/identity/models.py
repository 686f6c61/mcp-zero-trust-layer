from __future__ import annotations

from pydantic import BaseModel, Field


class Identity(BaseModel):
    """Composite principal used for policy decisions and audit."""

    subject: str = "anonymous"
    email: str | None = None
    groups: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    client_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    conversation_id: str | None = None
    project_id: str | None = None
    source_ip: str | None = None
    auth_method: str = "none"
    machine_id: str | None = None
    environment: str | None = None

