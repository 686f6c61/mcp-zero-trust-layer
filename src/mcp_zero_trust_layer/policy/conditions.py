from __future__ import annotations

import re
from typing import Any

from mcp_zero_trust_layer.core import RequestContext


def evaluate_conditions(conditions: dict[str, Any], context: RequestContext) -> bool:
    return all(_evaluate_condition(path, expected, context) for path, expected in conditions.items())


def _evaluate_condition(path: str, expected: Any, context: RequestContext) -> bool:
    actual = _get_path(context, path)
    if isinstance(expected, dict):
        for operator, operand in expected.items():
            if not _compare(operator, actual, operand):
                return False
        return True
    return actual == expected


def _get_path(context: RequestContext, path: str) -> Any:
    roots = {
        "args": context.arguments,
        "arguments": context.arguments,
        "identity": context.identity.model_dump(),
        "metadata": context.metadata,
        "output": context.output,
    }
    parts = path.split(".")
    current: Any = roots.get(parts[0])
    if current is None:
        return None
    for part in parts[1:]:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
        if current is None:
            return None
    return current


def _compare(operator: str, actual: Any, operand: Any) -> bool:
    if operator == "equals":
        return actual == operand
    if operator == "not_equals":
        return actual != operand
    if operator == "in":
        return actual in operand
    if operator == "not_in":
        return actual not in operand
    if operator == "contains":
        return operand in actual if actual is not None else False
    if operator == "matches":
        return bool(re.search(str(operand), str(actual or "")))
    if operator == "exists":
        return (actual is not None) is bool(operand)
    if operator == "gt":
        return actual > operand
    if operator == "gte":
        return actual >= operand
    if operator == "lt":
        return actual < operand
    if operator == "lte":
        return actual <= operand
    return False

