from __future__ import annotations

import json
from typing import Any

from mcp_zero_trust_layer.config.models import InputPolicy
from mcp_zero_trust_layer.validators.models import ValidatorResult


MISSING = object()


def validate_input_policy(arguments: dict[str, Any], policy: InputPolicy) -> ValidatorResult:
    errors: list[str] = []

    if policy.allowed_fields:
        allowed_top_level = {field.split(".", 1)[0] for field in policy.allowed_fields}
        for field in arguments:
            if field not in allowed_top_level:
                errors.append(f"field {field!r} is not allowed")

    for field in policy.required_fields:
        if _get_path(arguments, field) is MISSING:
            errors.append(f"field {field!r} is required")

    for field in policy.forbidden_fields:
        if _get_path(arguments, field) is not MISSING:
            errors.append(f"field {field!r} is forbidden")

    for field, allowed_values in policy.allowed_values.items():
        value = _get_path(arguments, field)
        if value is not MISSING and value not in allowed_values:
            errors.append(f"field {field!r} must be one of {allowed_values!r}")

    for field, max_bytes in policy.max_field_bytes.items():
        value = _get_path(arguments, field)
        if value is not MISSING and _encoded_size(value) > max_bytes:
            errors.append(f"field {field!r} exceeds {max_bytes} bytes")

    for field, max_items in policy.max_list_items.items():
        value = _get_path(arguments, field)
        if value is not MISSING and isinstance(value, list) and len(value) > max_items:
            errors.append(f"field {field!r} has more than {max_items} item(s)")

    return ValidatorResult(passed=not errors, errors=errors)


def _get_path(value: dict[str, Any], path: str) -> Any:
    current: Any = value
    for piece in path.split("."):
        if not isinstance(current, dict) or piece not in current:
            return MISSING
        current = current[piece]
    return current


def _encoded_size(value: Any) -> int:
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    return len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))
