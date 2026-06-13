from __future__ import annotations

import json
import re
from typing import Any

from mcp_zero_trust_layer.config.models import PolicyConfig


class OutputEnforcer:
    """Applies configured output policy actions to upstream responses."""

    def enforce(self, output: Any, policy: PolicyConfig) -> tuple[bool, Any, str | None]:
        if policy.output is None:
            return True, output, None

        serialized = json.dumps(output, default=str)
        for pattern in policy.output.deny_if_matches:
            if re.search(pattern, serialized):
                return False, None, f"output matched deny pattern for policy {policy.id}"

        if policy.output.max_bytes is not None and len(serialized.encode("utf-8")) > policy.output.max_bytes:
            return False, None, f"output exceeded max_bytes for policy {policy.id}"

        transformed = output
        if policy.output.include_fields and isinstance(output, dict):
            transformed = {key: output.get(key) for key in policy.output.include_fields if key in output}

        if policy.output.redact_fields:
            transformed = _redact_fields(transformed, set(policy.output.redact_fields))

        return True, transformed, None


def _redact_fields(value: Any, fields: set[str]) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key in fields else _redact_fields(item, fields)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_fields(item, fields) for item in value]
    return value

