from __future__ import annotations

import pytest

from mcp_zero_trust_layer.config.models import PolicyEngineConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.policy import adapters
from mcp_zero_trust_layer.policy.adapters import (
    _decision_from_opa_result,
    evaluate_external_policy,
)


class _Metadata:
    risk = "high"

    def model_dump(self, mode: str = "json") -> dict[str, str]:
        return {"risk": "high"}


def _ctx() -> RequestContext:
    return RequestContext(
        server="s",
        method="tools/call",
        capability_type="tool",
        capability="t",
        identity=Identity(subject="ana"),
    )


def test_unsupported_adapter_raises() -> None:
    config = PolicyEngineConfig(adapter="builtin")
    with pytest.raises(ValueError, match="unsupported policy adapter"):
        evaluate_external_policy(config, _ctx(), _Metadata())


def test_opa_adapter_requires_endpoint() -> None:
    config = PolicyEngineConfig(adapter="opa", endpoint=None)
    with pytest.raises(ValueError, match="requires an endpoint"):
        evaluate_external_policy(config, _ctx(), _Metadata())


def test_opa_adapter_fail_closed_denies(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(adapters.httpx, "post", boom)
    config = PolicyEngineConfig(adapter="opa", endpoint="http://opa/x", fail_closed=True)
    decision = evaluate_external_policy(config, _ctx(), _Metadata())
    assert decision.decision == "deny"
    assert "failed closed" in decision.reason
    assert decision.risk == "high"


def test_opa_adapter_fail_open_allows(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(adapters.httpx, "post", boom)
    config = PolicyEngineConfig(adapter="opa", endpoint="http://opa/x", fail_closed=False)
    decision = evaluate_external_policy(config, _ctx(), _Metadata())
    assert decision.decision == "allow"
    assert "failed open" in decision.reason


def test_opa_adapter_fail_open_without_metadata(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(adapters.httpx, "post", boom)
    config = PolicyEngineConfig(adapter="opa", endpoint="http://opa/x", fail_closed=False)
    decision = evaluate_external_policy(config, _ctx(), None)
    assert decision.decision == "allow"
    assert decision.risk is None


def test_opa_adapter_success_with_dict_metadata(monkeypatch) -> None:
    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"result": True}

    monkeypatch.setattr(adapters.httpx, "post", lambda *a, **k: Response())
    config = PolicyEngineConfig(adapter="opa", endpoint="http://opa/x")
    # metadata as plain dict (no model_dump) exercises the else branch of the payload
    decision = evaluate_external_policy(config, _ctx(), {"risk": "low"})
    assert decision.decision == "allow"


def test_decision_from_opa_result_true() -> None:
    assert _decision_from_opa_result(True).decision == "allow"


def test_decision_from_opa_result_false_and_none() -> None:
    assert _decision_from_opa_result(False).decision == "deny"
    assert _decision_from_opa_result(None).decision == "deny"


def test_decision_from_opa_result_invalid_shape() -> None:
    decision = _decision_from_opa_result("not-a-dict")
    assert decision.decision == "deny"
    assert "invalid shape" in decision.reason


def test_decision_from_opa_result_allow_shorthand() -> None:
    decision = _decision_from_opa_result({"allow": True})
    assert decision.decision == "allow"


def test_decision_from_opa_result_deny_shorthand() -> None:
    decision = _decision_from_opa_result({"allow": False})
    assert decision.decision == "deny"


def test_decision_from_opa_result_unsupported_decision() -> None:
    decision = _decision_from_opa_result({"decision": "explode"})
    assert decision.decision == "deny"
    assert "unsupported decision" in decision.reason


def test_decision_from_opa_result_require_approval_and_errors() -> None:
    decision = _decision_from_opa_result(
        {
            "decision": "require_approval",
            "policy_id": "p1",
            "reason": "needs review",
            "risk": "high",
            "validation_errors": ["bad field"],
        }
    )
    assert decision.decision == "require_approval"
    assert decision.approval_required is True
    assert decision.policy_id == "p1"
    assert decision.validation_errors == ["bad field"]


def test_decision_from_opa_result_scalar_validation_errors_wrapped() -> None:
    decision = _decision_from_opa_result(
        {"decision": "deny", "validation_errors": "single error"}
    )
    assert decision.validation_errors == ["single error"]


def test_decision_from_opa_result_uses_policy_alias_and_default_reason() -> None:
    decision = _decision_from_opa_result({"decision": "allow", "policy": "aliased"})
    assert decision.policy_id == "aliased"
    assert "decision: allow" in decision.reason
