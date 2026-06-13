from __future__ import annotations

from typing import Any

import httpx

from mcp_zero_trust_layer.audit import redact_sensitive
from mcp_zero_trust_layer.config.models import ApprovalsConfig
from mcp_zero_trust_layer.config.secrets import resolve_secret_value


class ApprovalNotifier:
    def __init__(self, config: ApprovalsConfig):
        self.config = config

    def notify(self, action: str, approval: dict[str, Any]) -> None:
        if not self.config.webhook_url:
            return
        url = resolve_secret_value(self.config.webhook_url, field="approvals.webhook_url")
        payload = {
            "event_type": "approval",
            "action": action,
            "approval": redact_sensitive(approval),
        }
        try:
            response = httpx.post(url, json=payload, timeout=self.config.webhook_timeout)
            response.raise_for_status()
        except Exception:
            if self.config.webhook_strict:
                raise
