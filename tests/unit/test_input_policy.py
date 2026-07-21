from __future__ import annotations

from mcp_zero_trust_layer.config.models import InputPolicy
from mcp_zero_trust_layer.validators.input_policy import validate_input_policy


def test_allowed_fields_reject_top_level_extras() -> None:
    policy = InputPolicy(allowed_fields=["query"])
    result = validate_input_policy({"query": "x", "danger": 1}, policy)
    assert result.passed is False
    assert any("danger" in error for error in result.errors)


def test_allowed_fields_reject_nested_extras() -> None:
    policy = InputPolicy(allowed_fields=["config.safe"])
    result = validate_input_policy({"config": {"safe": 1, "danger": 2}}, policy)
    assert result.passed is False
    assert any("config.danger" in error for error in result.errors)


def test_allowed_fields_accept_nested_leaf_subtree() -> None:
    policy = InputPolicy(allowed_fields=["config.safe"])
    result = validate_input_policy({"config": {"safe": {"anything": True}}}, policy)
    assert result.passed is True


def test_required_and_forbidden_fields() -> None:
    policy = InputPolicy(required_fields=["a.b"], forbidden_fields=["c"])
    assert validate_input_policy({"a": {"b": 1}}, policy).passed is True
    assert validate_input_policy({"a": {}}, policy).passed is False
    assert validate_input_policy({"a": {"b": 1}, "c": 2}, policy).passed is False


def test_allowed_values_and_limits() -> None:
    policy = InputPolicy(
        allowed_values={"mode": ["read"]},
        max_field_bytes={"blob": 4},
        max_list_items={"items": 2},
    )
    assert validate_input_policy({"mode": "read"}, policy).passed is True
    assert validate_input_policy({"mode": "write"}, policy).passed is False
    assert validate_input_policy({"blob": "toolong"}, policy).passed is False
    assert validate_input_policy({"items": [1, 2, 3]}, policy).passed is False
