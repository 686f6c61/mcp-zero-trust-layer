from __future__ import annotations

import hashlib
import json
from typing import Any

import rfc8785

MAX_BYTES = 1_048_576
MAX_DEPTH = 32
DOMAIN = b"mcpzt.evidence.v1:"


def canonical(value: Any, depth: int = 0) -> bytes:
    """Bound work before JCS; never coerce unsupported numbers or types."""
    def check(item: Any, level: int) -> None:
        if type(item) not in (dict, list, str, int, float, bool, type(None)):
            raise ValueError("not a JSON value")
        if level > MAX_DEPTH:
            raise ValueError("evidence nesting limit")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                check(child, level + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, level + 1)
    check(value, depth)
    result = rfc8785.dumps(value)
    if len(result) > MAX_BYTES:
        raise ValueError("evidence size limit")
    return result


def loads(data: str | bytes) -> Any:
    if len(data) > MAX_BYTES:
        raise ValueError("evidence size limit")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=pairs)
        canonical(value)
        return value
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("invalid evidence JSON") from exc


def digest(kind: str, value: Any, nonce: str = "") -> str:
    return hashlib.sha256(DOMAIN + kind.encode("ascii") + b":" +
                          canonical({"nonce": nonce, "value": value})).hexdigest()
