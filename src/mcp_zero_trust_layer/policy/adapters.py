from __future__ import annotations

from typing import Any

import httpx

from mcp_zero_trust_layer.config.models import PolicyEngineConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.policy.models import PolicyDecision

SUPPORTED_DECISIONS = {
    "allow",
    "deny",
    "hide",
    "require_approval",
    "redact",
    "limit",
    "transform",
    "log",
}


def evaluate_external_policy(
    config: PolicyEngineConfig,
    context: RequestContext,
    metadata: Any,
    *,
    dry_run: bool = False,
) -> PolicyDecision:
    if config.adapter != "opa":
        raise ValueError(f"unsupported policy adapter: {config.adapter}")
    if not config.endpoint:
        raise ValueError("OPA policy adapter requires an endpoint")

    payload = {
        "input": {
            "context": context.model_dump(mode="json"),
            "metadata": metadata.model_dump(mode="json") if hasattr(metadata, "model_dump") else metadata,
        }
    }
    try:
        response = httpx.post(config.endpoint, json=payload, timeout=config.timeout)
        response.raise_for_status()
        result = response.json().get("result")
        return _decision_from_opa_result(result, dry_run=dry_run)
    except Exception as exc:
        if config.fail_closed:
            return PolicyDecision(
                decision="deny",
                reason=f"external policy adapter failed closed: {exc}",
                risk=metadata.risk if metadata else None,
                dry_run=dry_run,
                metadata={"policy_adapter": config.adapter},
            )
        return PolicyDecision(
            decision="allow",
            reason=f"external policy adapter failed open: {exc}",
            risk=metadata.risk if metadata else None,
            dry_run=dry_run,
            metadata={"policy_adapter": config.adapter},
        )


def _decision_from_opa_result(result: Any, *, dry_run: bool = False) -> PolicyDecision:
    if result is True:
        return PolicyDecision(decision="allow", reason="OPA result allowed", dry_run=dry_run)
    if result is False or result is None:
        return PolicyDecision(decision="deny", reason="OPA result denied", dry_run=dry_run)
    if not isinstance(result, dict):
        return PolicyDecision(
            decision="deny", reason="OPA result has invalid shape", dry_run=dry_run
        )

    decision = result.get("decision")
    if decision is None:
        decision = "allow" if result.get("allow") is True else "deny"
    if decision not in SUPPORTED_DECISIONS:
        return PolicyDecision(
            decision="deny",
            reason=f"OPA result returned unsupported decision: {decision!r}",
            dry_run=dry_run,
            metadata={"policy_adapter": "opa"},
        )
    reason = result.get("reason") or f"OPA result decision: {decision}"
    policy_id = result.get("policy_id") or result.get("policy")
    validation_errors = result.get("validation_errors") or []
    if not isinstance(validation_errors, list):
        validation_errors = [str(validation_errors)]

    return PolicyDecision(
        decision=decision,
        policy_id=policy_id,
        reason=reason,
        risk=result.get("risk"),
        approval_required=decision == "require_approval",
        dry_run=dry_run,
        validation_errors=[str(item) for item in validation_errors],
        metadata={"policy_adapter": "opa"},
    )
