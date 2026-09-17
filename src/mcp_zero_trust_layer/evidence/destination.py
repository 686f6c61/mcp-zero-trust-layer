"""Reference destination: commits a local refund ledger, NOT a payment provider."""
from __future__ import annotations

import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from mcp_zero_trust_layer import __version__
from mcp_zero_trust_layer.evidence.canonical import MAX_BYTES, canonical, digest, loads
from mcp_zero_trust_layer.evidence.crypto import sign
from mcp_zero_trust_layer.evidence.models import Attempt, Permit, Receipt, TrustStore
from mcp_zero_trust_layer.evidence.protocol import LOOKUP, META, request_payload, response_payload
from mcp_zero_trust_layer.evidence.runtime import load_private_key
from mcp_zero_trust_layer.evidence.store import database
from mcp_zero_trust_layer.evidence.verify import verify_permit
from mcp_zero_trust_layer.protocol import error_response, success_response

SCOPE = "local-refund-ledger.v1"


class RefundDestination:
    def __init__(self, directory: Path):
        self.path = directory / "destination.sqlite3"
        self.key = load_private_key(directory / "destination.key")
        self.trust = TrustStore.model_validate(loads((directory / "trust.json").read_bytes()))
        with database(self.path) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS refund_operations (
                    operation_id TEXT PRIMARY KEY, permit_digest TEXT UNIQUE NOT NULL,
                    response TEXT NOT NULL, material TEXT NOT NULL, receipt TEXT);
                CREATE TABLE IF NOT EXISTS refunds (
                    operation_id TEXT PRIMARY KEY, amount_minor INTEGER NOT NULL);
            """)

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        if method == "notifications/initialized":
            return None
        if method == "initialize":
            return success_response(message["id"], {
                "protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcpzt-receipt-demo", "version": __version__},
            })
        if method == "tools/list":
            return success_response(message["id"], {"tools": [{
                "name": "refund", "description": "Record a local demo refund (no money moves)",
                "inputSchema": {"type": "object", "properties": {
                    "amount_minor": {"type": "integer", "minimum": 1, "maximum": 10000}},
                    "required": ["amount_minor"], "additionalProperties": False},
            }]})
        try:
            if method == LOOKUP:
                permit = Permit.model_validate(message["params"]["permit"])
                auth = verify_permit(permit, self.trust)
                self._audience(auth.audience, auth.tenant)
                receipt = self._receipt(auth.operation_id, digest("attempt", permit.model_dump()))
                return success_response(message["id"], {"receipt": receipt})
            if method != "tools/call" or "id" not in message:
                raise ValueError("unsupported method")
            permit = Permit.model_validate(message["params"]["_meta"][META])
            auth = verify_permit(permit, self.trust, now=int(time.time()))
            self._audience(auth.audience, auth.tenant)
            value = request_payload(message)
            if (auth.tool != "refund" or value["params"].get("name") != auth.tool or
                    digest("request", value, auth.request_nonce) != auth.request_digest):
                raise ValueError("request binding mismatch")
            args = value["params"].get("arguments", {})
            amount = args.get("amount_minor")
            if set(args) != {"amount_minor"} or type(amount) is not int or not 0 < amount <= 10000:
                raise ValueError("destination business rule rejected")
            permit_digest = digest("attempt", permit.model_dump())
            # Transaction spans the real local effect AND the receipt material.
            with database(self.path) as db:
                db.execute("BEGIN IMMEDIATE")
                previous = db.execute("SELECT * FROM refund_operations WHERE operation_id=?",
                                      (auth.operation_id,)).fetchone()
                if previous:
                    if previous["permit_digest"] != permit_digest:
                        raise ValueError("operation already bound to another attempt")
                    response = json.loads(previous["response"])
                else:
                    response = {"result": {"content": [{"type": "text", "text": "Refund recorded"}],
                                           "structuredContent": {"amount_minor": amount}}}
                    attempt = Attempt.model_validate(permit.attempt.payload)
                    nonce = secrets.token_hex(32)
                    material = Receipt(
                        issuer=auth.audience, audience=auth.issuer, tenant=auth.tenant,
                        operation_id=auth.operation_id, authorization_id=auth.authorization_id,
                        attempt_id=attempt.attempt_id, receipt_id="receipt_" + uuid4().hex,
                        attempt_digest=permit_digest, request_digest=auth.request_digest,
                        response_digest=digest("response", response_payload(response), nonce),
                        response_nonce=nonce, effect="committed", scope=SCOPE,
                        transaction_ref=auth.operation_id, sequence=1, recorded_at=int(time.time()),
                    )
                    db.execute("INSERT INTO refunds VALUES(?,?)", (auth.operation_id, amount))
                    db.execute("INSERT INTO refund_operations VALUES(?,?,?,?,NULL)",
                               (auth.operation_id, permit_digest, canonical(response).decode(),
                                canonical(material.model_dump()).decode()))
            # A signing crash here leaves committed material, recoverable without re-execution.
            receipt = self._receipt(auth.operation_id, permit_digest)
            response["result"].setdefault("_meta", {})[META] = receipt
            return {"jsonrpc": "2.0", "id": message["id"], **response}
        except (ValueError, KeyError, TypeError):
            return error_response(message.get("id"), -32060,
                                  "Destination rejected request or receipt is unavailable")

    @staticmethod
    def _audience(audience: str, tenant: str) -> None:
        if (audience, tenant) != ("refund-demo", "demo"):
            raise ValueError("wrong destination or tenant")

    def _receipt(self, operation: str, permit_digest: str) -> dict[str, Any]:
        with database(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT material,receipt FROM refund_operations "
                             "WHERE operation_id=? AND permit_digest=?",
                             (operation, permit_digest)).fetchone()
            if row is None:
                raise ValueError("receipt unavailable")
            if row["receipt"]:
                return json.loads(row["receipt"])
            signed = sign(json.loads(row["material"]), "receipt", "destination-demo", self.key)
            result = signed.model_dump()
            db.execute("UPDATE refund_operations SET receipt=? WHERE operation_id=?",
                       (canonical(result).decode(), operation))
            return result


def main() -> None:
    destination = RefundDestination(Path(sys.argv[1]))
    for line in iter(lambda: sys.stdin.readline(MAX_BYTES + 1), ""):
        try:
            response = destination.handle(loads(line))
        except ValueError:
            response = error_response(None, -32700, "Invalid JSON")
        if response is not None:
            print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
