from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_zero_trust_layer import __version__
from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.evidence.crypto import encode
from mcp_zero_trust_layer.evidence.destination import SCOPE
from mcp_zero_trust_layer.evidence.models import TrustKey, TrustStore
from mcp_zero_trust_layer.evidence.protocol import IDEMPOTENCY
from mcp_zero_trust_layer.evidence.store import database


def create_demo(directory: Path) -> MCPZTConfig:
    """Generate independent keys; never overwrite an existing demo or its ledger."""
    directory = directory.resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = []
    for role, issuer, audience in [("gateway", "gateway-demo", "refund-demo"),
                                    ("destination", "refund-demo", "gateway-demo")]:
        key = Ed25519PrivateKey.generate()
        with os.fdopen(os.open(directory / f"{role}.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                               0o600), "w") as handle:
            handle.write(encode(key.private_bytes_raw()))
        keys.append(TrustKey.model_validate({
            "kid": role + "-demo", "issuer": issuer, "audience": audience, "tenant": "demo",
            "role": role, "public_key": encode(key.public_key().public_bytes_raw()),
            "scopes": [SCOPE] if role == "destination" else [],
        }))
    (directory / "trust.json").write_text(TrustStore(keys=keys).model_dump_json(indent=2))
    cfg = MCPZTConfig.model_validate({
        "project": {"name": "receipt-demo", "environment": "test"},
        "servers": [{"name": "refund", "transport": "stdio", "command": [
            sys.executable, "-m", "mcp_zero_trust_layer.evidence.destination", str(directory)],
            "evidence": {"mode": "required", "issuer": "gateway-demo", "destination": "refund-demo",
                         "tenant": "demo", "scope": SCOPE, "key_id": "gateway-demo",
                         "private_key_file": str(directory / "gateway.key"),
                         "trust_store": str(directory / "trust.json"),
                         "store": str(directory / "evidence.sqlite3")}}],
        "policies": [{"id": "allow-lifecycle", "effect": "allow", "match": {
                        "capability_type": "method", "capabilities": ["initialize", "ping"]}},
                     {"id": "show-refund", "effect": "allow", "match": {
                         "method": "tools/list", "capability": "refund"}},
                     {"id": "refund-limit", "effect": "allow", "match": {"method": "tools/call",
                        "capability": "refund"}, "when": {"args.amount_minor": {"in": [5000]}}}],
        "approvals": {"backend": "sqlite", "path": str(directory / "evidence.sqlite3")},
        "audit": {"path": str(directory / "audit.jsonl")},
    })
    (directory / "mcpzt.yaml").write_text(yaml.safe_dump(cfg.model_dump(mode="json")))
    return cfg


def run_demo(directory: Path) -> dict[str, Any]:
    from mcp_zero_trust_layer.core.pipeline import MCPPipeline
    from mcp_zero_trust_layer.upstream.stdio import StdioProcessUpstream

    cfg = create_demo(directory)
    server = cfg.servers[0]
    peer = StdioProcessUpstream(server)
    try:
        pipeline = MCPPipeline(cfg, peer)
        pipeline.handle("refund", {"jsonrpc": "2.0", "id": 0, "method": "initialize",
                           "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                      "clientInfo": {"name": "mcpzt-demo", "version": __version__}}})
        pipeline.handle("refund", {"jsonrpc": "2.0", "method": "notifications/initialized"})
        outcomes = []
        for number, amount in enumerate((5000, 50000), start=1):
            result = pipeline.handle("refund", {"jsonrpc": "2.0", "id": number,
                "method": "tools/call", "params": {"name": "refund",
                "arguments": {"amount_minor": amount}, "_meta": {IDEMPOTENCY: f"demo-{number}"}}})
            outcomes.append(result)
        with database(directory / "destination.sqlite3") as db:
            rows = db.execute("SELECT operation_id,amount_minor FROM refunds").fetchall()
        if len(rows) != 1 or rows[0][1] != 5000 or "error" not in (outcomes[1] or {}):
            raise ValueError("demo invariants failed")
        evidence = pipeline.evidence["refund"]
        bundle = evidence.store.get(rows[0][0], "demo")
        from mcp_zero_trust_layer.evidence.verify import verify_bundle
        verdict = verify_bundle(bundle, evidence.trust)
        if verdict["claim"] != "destination_commit_attested":
            raise ValueError("demo receipt did not verify")
        with os.fdopen(os.open(directory / "bundle.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                               0o600), "w") as handle:
            json.dump(bundle, handle, indent=2)
        return {"allowed": 1, "denied": 1, "ledger_rows": len(rows),
                "operation_id": rows[0][0], "verdict": verdict}
    finally:
        peer.close()
