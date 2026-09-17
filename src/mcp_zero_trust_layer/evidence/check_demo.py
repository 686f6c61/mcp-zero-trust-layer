"""Local adversarial fixture generator; no provider is contacted and no money moves."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.evidence.canonical import digest
from mcp_zero_trust_layer.evidence.check_models import ObserverKey, ObserverTrust, StripeCheckConfig
from mcp_zero_trust_layer.evidence.checks import (
    StripeRefundReader,
    check_refund,
    observation_digest,
)
from mcp_zero_trust_layer.evidence.crypto import encode, sign
from mcp_zero_trust_layer.evidence.demo import create_demo
from mcp_zero_trust_layer.evidence.models import Receipt
from mcp_zero_trust_layer.evidence.protocol import LOOKUP, META, request_payload
from mcp_zero_trust_layer.evidence.verify import verify_bundle


def private_json(path: Path, value: Any) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as handle:
        json.dump(value, handle, indent=2)


def run_check_demo(directory: Path) -> dict[str, Any]:
    cfg = create_demo(directory)
    from mcp_zero_trust_layer.evidence.models import TrustStore
    cfg.servers[0].evidence.scope = "stripe.refund.status.v1"
    trust_path = directory / "trust.json"
    trust = TrustStore.model_validate_json(trust_path.read_text())
    trust.keys[1].scopes = ["stripe.refund.status.v1"]
    trust_path.write_text(trust.model_dump_json(indent=2))
    service_holder: dict[str, Any] = {}
    received = []
    request_value = {}

    class Destination:
        receipt: dict[str, Any] | None = None

        def send(self, server: Any, message: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            received.append(message["method"])
            if message["method"] == LOOKUP:
                return {"jsonrpc": "2.0", "id": message["id"], "result": {"receipt": self.receipt}}
            permit = message["params"]["_meta"][META]
            auth = permit["authorization"]["payload"]
            request_value.update(request_payload(message))
            payload = Receipt(issuer=auth["audience"], audience=auth["issuer"], tenant=auth["tenant"],
                operation_id=auth["operation_id"], authorization_id=auth["authorization_id"],
                attempt_id=permit["attempt"]["payload"]["attempt_id"], receipt_id="demo-receipt",
                attempt_digest=digest("attempt", permit), request_digest=auth["request_digest"],
                response_digest="0" * 64, response_nonce="1" * 64, effect="committed",
                scope=cfg.servers[0].evidence.scope, transaction_ref="re_demo", sequence=1,
                recorded_at=int(time.time()))
            self.receipt = sign(payload.model_dump(), "receipt", "destination-demo",
                                service_holder["destination_key"]).model_dump()
            raise TimeoutError("Demo destination claimed commit but its response was lost")

    from mcp_zero_trust_layer.evidence.checks import load_observer_private_key
    service_holder["destination_key"] = load_observer_private_key(directory / "destination.key")
    peer = Destination()
    pipeline = MCPPipeline(cfg, peer)
    response = pipeline.handle("refund", {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "refund", "arguments": {"amount_minor": 5000, "currency": "eur",
                                                     "account": "acct_demo", "charge": "ch_demo"}}})
    operation = response["error"]["data"]["operation_id"]  # type: ignore[index]
    service = pipeline.evidence["refund"]
    private_json(directory / "timeout-record.json", service.store.events(operation, "demo"))
    private_json(directory / "bundle-at-timeout.json", service.store.get(operation, "demo"))
    service.reconcile(operation, lambda message: peer.send(cfg.servers[0], message))
    bundle = service.store.get(operation, "demo")
    private_json(directory / "bundle-after-reconciliation.json", bundle)
    private_json(directory / "request-preimage.json", request_value)
    key = Ed25519PrivateKey.generate()
    observers = ObserverTrust(keys=[ObserverKey(kid="observer-demo", issuer="observer-demo",
        tenant="demo", destination="refund-demo", account="acct_demo", administration="shared",
        public_key=encode(key.public_key().public_bytes_raw()))])
    private_json(directory / "observers.json", observers.model_dump())
    config = StripeCheckConfig(tenant="demo", destination="refund-demo", tool="refund",
        receipt_scope="stripe.refund.status.v1", account="acct_demo", api_key_env="UNUSED_DEMO_KEY",
        observer_key_id="observer-demo", observer_private_key_file="unused", observer_trust_file="observers.json")
    auth = bundle["permit"]["authorization"]["payload"]
    provider = {"id": "re_demo", "object": "refund", "amount": 5000, "currency": "eur",
        "charge": "ch_demo", "status": "failed", "created": auth["issued_at"], "metadata": {
            "mcpzt_operation_id": operation, "mcpzt_authorization_id": auth["authorization_id"],
            "mcpzt_attempt_id": bundle["permit"]["attempt"]["payload"]["attempt_id"],
            "mcpzt_request_digest": auth["request_digest"]}}
    requests = []
    source_status = 200

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append({"method": request.method, "path": request.url.path})
        return httpx.Response(200, json={"id": "acct_demo"}) if request.url.path == "/v1/account" else httpx.Response(source_status, json=provider)

    reader = StripeRefundReader("rk_test_fixture", "acct_demo", transport=httpx.MockTransport(handle))
    cases = []
    previous = None
    try:
        for name, status, amount, http_status in [
            ("signed-lie", "failed", 5000, 200),
            ("corroborated", "succeeded", 5000, 200),
            ("later-failure", "failed", 5000, 200),
            ("wrong-amount", "succeeded", 6000, 200),
            ("pending", "pending", 5000, 200),
            ("not-found", "succeeded", 5000, 404),
        ]:
            provider.update(status=status, amount=amount)
            source_status = http_status
            document = check_refund(bundle, request_value, service.trust, config, observers, key,
                                    reader, previous=previous)
            service.store.append_observation(operation, "demo", document.model_dump())
            previous = observation_digest(document)
            cases.append({"case": name, "result": document.payload.result, "reason": document.payload.reason})
            private_json(directory / f"{name}.json", service.store.checked_bundle(operation, "demo"))
    finally:
        reader.close()
    final = service.store.checked_bundle(operation, "demo")
    private_json(directory / "bundle-v2.json", final)
    verdict = verify_bundle(final, service.trust, observers=observers)
    summary = {"simulation": True, "provider_contacted": False, "administration": "shared",
        "operation_id": operation, "destination_methods": received, "provider_requests": requests,
        "cases": cases, "verdict": verdict}
    private_json(directory / "comparison.json", summary)
    return summary
