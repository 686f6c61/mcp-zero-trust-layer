from __future__ import annotations

import copy
from typing import Any

from mcp_zero_trust_layer.evidence.canonical import canonical

META = "io.github.mcp-zero-trust-layer/evidence-v1"
IDEMPOTENCY = "io.github.mcp-zero-trust-layer/idempotency-key"
LOOKUP = "mcpzt/evidence/get"


def request_payload(message: dict[str, Any]) -> dict[str, Any]:
    """Only our transport metadata is removed. Other _meta fields are committed."""
    value = copy.deepcopy({"method": message["method"], "params": message.get("params", {})})
    meta = value["params"].get("_meta")
    if meta is not None:
        if not isinstance(meta, dict):
            raise ValueError("invalid request metadata")
        meta.pop(META, None)
        meta.pop(IDEMPOTENCY, None)
        if not meta:
            value["params"].pop("_meta")
    canonical(value)
    return value


def validate_client(message: dict[str, Any]) -> str | None:
    canonical(message)
    meta = message.get("params", {}).get("_meta", {})
    if not isinstance(meta, dict) or META in meta:
        raise ValueError("client evidence is not authoritative")
    key = meta.get(IDEMPOTENCY)
    if key is not None and (not isinstance(key, str) or not 1 <= len(key) <= 128):
        raise ValueError("invalid idempotency key")
    return key


def attach_permit(message: dict[str, Any], permit: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(message)
    meta = result.setdefault("params", {}).setdefault("_meta", {})
    meta.pop(IDEMPOTENCY, None)
    meta[META] = permit
    return result


def split_response(message: dict[str, Any]) -> tuple[dict[str, Any], Any]:
    """Errors use error.data._meta; successful MCP results use result._meta."""
    clean = copy.deepcopy(message)
    container = clean["result"] if "result" in clean else clean["error"].get("data")
    receipt = None
    if isinstance(container, dict):
        meta = container.get("_meta")
        if isinstance(meta, dict) and META in meta:
            receipt = meta.pop(META)
            if not meta:
                container.pop("_meta")
    return clean, receipt


def response_payload(message: dict[str, Any]) -> dict[str, Any]:
    clean, _ = split_response(message)
    key = "result" if "result" in clean else "error"
    return {key: clean[key]}
