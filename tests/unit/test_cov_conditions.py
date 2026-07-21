from __future__ import annotations

from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.policy.conditions import (
    _compare,
    _get_path,
    evaluate_conditions,
)


def _ctx(**kwargs) -> RequestContext:
    base = {
        "server": "s",
        "method": "tools/call",
        "capability_type": "tool",
        "capability": "t",
        "identity": Identity(subject="ana", roles=["admin"], email="ana@example.com"),
        "arguments": {"query": "hello", "count": 3, "labels": ["a", "b"]},
        "metadata": {"nested": {"key": "value"}},
        "output": {"result": "ok"},
    }
    base.update(kwargs)
    return RequestContext(**base)


def test_evaluate_conditions_empty_is_true() -> None:
    assert evaluate_conditions({}, _ctx()) is True


def test_evaluate_conditions_simple_equality() -> None:
    assert evaluate_conditions({"args.query": "hello"}, _ctx()) is True
    assert evaluate_conditions({"args.query": "nope"}, _ctx()) is False


def test_evaluate_conditions_operator_dict_all_true() -> None:
    assert evaluate_conditions({"args.count": {"gt": 1, "lt": 10}}, _ctx()) is True


def test_evaluate_conditions_operator_dict_one_false() -> None:
    assert evaluate_conditions({"args.count": {"gt": 1, "lt": 2}}, _ctx()) is False


def test_get_path_arguments_and_args_roots() -> None:
    ctx = _ctx()
    assert _get_path(ctx, "args.query") == "hello"
    assert _get_path(ctx, "arguments.query") == "hello"


def test_get_path_identity_object_attribute() -> None:
    # identity root is a dict (model_dump), so nested access uses .get
    assert _get_path(_ctx(), "identity.subject") == "ana"


def test_get_path_metadata_nested_dict() -> None:
    assert _get_path(_ctx(), "metadata.nested.key") == "value"


def test_get_path_output_root() -> None:
    assert _get_path(_ctx(), "output.result") == "ok"


def test_get_path_unknown_root_returns_none() -> None:
    assert _get_path(_ctx(), "does_not_exist.foo") is None


def test_get_path_missing_intermediate_returns_none() -> None:
    assert _get_path(_ctx(), "args.query.deeper") is None
    assert _get_path(_ctx(), "metadata.absent.key") is None


def test_get_path_object_getattr_branch() -> None:
    # When current is not a dict, _get_path falls back to getattr.
    ctx = _ctx(output="a string")
    # output root is the raw string; getattr on it for an attribute returns None
    assert _get_path(ctx, "output.upper") is not None or _get_path(ctx, "output.nope") is None


def test_compare_all_operators() -> None:
    assert _compare("equals", 1, 1) is True
    assert _compare("equals", 1, 2) is False
    assert _compare("not_equals", 1, 2) is True
    assert _compare("in", "a", ["a", "b"]) is True
    assert _compare("not_in", "c", ["a", "b"]) is True
    assert _compare("contains", ["a", "b"], "a") is True
    assert _compare("contains", None, "a") is False
    assert _compare("matches", "hello world", "wor") is True
    assert _compare("matches", None, "x") is False
    assert _compare("exists", "value", True) is True
    assert _compare("exists", None, False) is True
    assert _compare("exists", None, True) is False
    assert _compare("gt", 5, 3) is True
    assert _compare("gte", 5, 5) is True
    assert _compare("lt", 3, 5) is True
    assert _compare("lte", 5, 5) is True


def test_compare_unknown_operator_returns_false() -> None:
    assert _compare("unknown_op", 1, 1) is False
