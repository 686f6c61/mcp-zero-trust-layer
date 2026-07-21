from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from mcp_zero_trust_layer.approvals import ApprovalNotifier, ApprovalStore, create_approvals_app
from mcp_zero_trust_layer.approvals.models import ApprovalRequest
from mcp_zero_trust_layer.config.models import ApprovalsConfig, MCPZTConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity

# ---------------------------------------------------------------------------
# models.py
# ---------------------------------------------------------------------------


def _request(**overrides: Any) -> ApprovalRequest:
    base: dict[str, Any] = {
        "server": "github",
        "capability_type": "tool",
        "policy_id": "p1",
        "identity_subject": "ana",
        "arguments_hash": "abc",
    }
    base.update(overrides)
    return ApprovalRequest(**base)


def test_is_active_true_without_expiry() -> None:
    assert _request(status="approved", expires_at=None).is_active() is True


def test_is_active_false_when_not_approved() -> None:
    assert _request(status="pending").is_active() is False


def test_is_active_false_when_expired() -> None:
    past = datetime.now(UTC) - timedelta(seconds=10)
    assert _request(status="approved", expires_at=past).is_active() is False


def test_is_active_true_before_expiry() -> None:
    future = datetime.now(UTC) + timedelta(seconds=60)
    assert _request(status="approved", expires_at=future).is_active() is True


# ---------------------------------------------------------------------------
# store.py (file backend paths)
# ---------------------------------------------------------------------------


def _context() -> RequestContext:
    return RequestContext(
        server="github",
        method="tools/call",
        capability_type="tool",
        capability="github.merge_pull_request",
        arguments={"repo": "acme/api", "pull_number": 1},
        identity=Identity(subject="ana", client_id="cursor"),
    )


def test_file_store_get_before_any_write_returns_none(tmp_path: Path) -> None:
    store = ApprovalStore(ApprovalsConfig(backend="file", path=str(tmp_path / "approvals.json")))
    assert store.get("appr_missing") is None


def test_file_store_list_is_sorted(tmp_path: Path) -> None:
    store = ApprovalStore(ApprovalsConfig(backend="file", path=str(tmp_path / "approvals.json")))
    first = store.create(_context(), "p1")
    second = store.create(_context(), "p1")
    listed = [item.id for item in store.list()]
    assert listed == [first.id, second.id]


def test_file_store_set_status_missing_raises_keyerror(tmp_path: Path) -> None:
    store = ApprovalStore(ApprovalsConfig(backend="file", path=str(tmp_path / "approvals.json")))
    store.create(_context(), "p1")
    with pytest.raises(KeyError):
        store.set_status("appr_missing", "approved")


def test_file_store_same_status_transition_is_noop(tmp_path: Path) -> None:
    store = ApprovalStore(ApprovalsConfig(backend="file", path=str(tmp_path / "approvals.json")))
    approval = store.create(_context(), "p1")
    updated = store.set_status(approval.id, "pending")
    assert updated.status == "pending"
    assert updated.decided_at is None
    assert updated.decided_by is None


def test_sqlite_store_get_missing_returns_none(tmp_path: Path) -> None:
    store = ApprovalStore(ApprovalsConfig(backend="sqlite", path=str(tmp_path / "a.sqlite3")))
    store.create(_context(), "p1")
    assert store.get("appr_missing") is None


def test_sqlite_store_set_status_missing_raises_keyerror(tmp_path: Path) -> None:
    store = ApprovalStore(ApprovalsConfig(backend="sqlite", path=str(tmp_path / "a.sqlite3")))
    store.create(_context(), "p1")
    with pytest.raises(KeyError):
        store.set_status("appr_missing", "approved")


# ---------------------------------------------------------------------------
# notifier.py
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, should_raise: bool = False) -> None:
        self._should_raise = should_raise

    def raise_for_status(self) -> None:
        if self._should_raise:
            raise httpx.HTTPStatusError("boom", request=None, response=None)  # type: ignore[arg-type]


def test_notifier_noop_without_webhook() -> None:
    notifier = ApprovalNotifier(ApprovalsConfig())
    # No webhook configured: returns immediately without touching httpx.
    notifier.notify("created", {"id": "appr_1"})


def test_notifier_posts_payload(monkeypatch) -> None:
    calls: list[dict[str, Any]] = []

    def fake_post(url: str, json: dict[str, Any], timeout: float) -> _FakeResponse:
        calls.append({"url": url, "json": json, "timeout": timeout})
        return _FakeResponse()

    monkeypatch.setattr(httpx, "post", fake_post)
    config = ApprovalsConfig(webhook_url="https://hook.example/notify")
    ApprovalNotifier(config).notify("created", {"id": "appr_1", "token": "secret"})

    assert calls[0]["url"] == "https://hook.example/notify"
    assert calls[0]["json"]["action"] == "created"
    assert calls[0]["json"]["approval"]["token"] == "[REDACTED]"


def test_notifier_non_strict_logs_failure(monkeypatch, capsys) -> None:
    def fake_post(url: str, json: dict[str, Any], timeout: float) -> _FakeResponse:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "post", fake_post)
    config = ApprovalsConfig(webhook_url="https://hook.example/notify", webhook_strict=False)
    ApprovalNotifier(config).notify("created", {"id": "appr_1"})

    assert "approval webhook delivery failed" in capsys.readouterr().err


def test_notifier_strict_reraises_failure(monkeypatch) -> None:
    def fake_post(url: str, json: dict[str, Any], timeout: float) -> _FakeResponse:
        return _FakeResponse(should_raise=True)

    monkeypatch.setattr(httpx, "post", fake_post)
    config = ApprovalsConfig(webhook_url="https://hook.example/notify", webhook_strict=True)
    with pytest.raises(httpx.HTTPStatusError):
        ApprovalNotifier(config).notify("created", {"id": "appr_1"})


# ---------------------------------------------------------------------------
# ui.py
# ---------------------------------------------------------------------------


def _ui_config(tmp_path: Path) -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "ui-cov", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "policies": [],
            "audit": {"destination": "file", "path": str(tmp_path / "audit.jsonl")},
            "approvals": {
                "path": str(tmp_path / "approvals.sqlite3"),
                "backend": "sqlite",
                "require_separation_of_duties": False,
            },
        }
    )


def _ui_context() -> RequestContext:
    return RequestContext(
        server="github",
        method="tools/call",
        capability_type="tool",
        capability="github.merge_pull_request",
        arguments={"pull_number": 1},
        identity=Identity(subject="ana"),
    )


def test_ui_index_empty(tmp_path: Path) -> None:
    client = TestClient(create_approvals_app(_ui_config(tmp_path)))
    response = client.get("/")
    assert response.status_code == 200
    assert "No approvals yet" in response.text


def test_ui_decide_missing_returns_404(tmp_path: Path) -> None:
    client = TestClient(create_approvals_app(_ui_config(tmp_path)))
    response = client.post("/api/approvals/appr_missing/allow", json={})
    assert response.status_code == 404


def test_ui_api_deny(tmp_path: Path) -> None:
    config = _ui_config(tmp_path)
    approval = ApprovalStore(config.approvals).create(_ui_context(), "p1")
    client = TestClient(create_approvals_app(config))
    response = client.post(f"/api/approvals/{approval.id}/deny", json={"comment": "no"})
    assert response.status_code == 200
    assert response.json()["status"] == "denied"


def test_ui_web_allow_redirects(tmp_path: Path) -> None:
    config = _ui_config(tmp_path)
    approval = ApprovalStore(config.approvals).create(_ui_context(), "p1")
    client = TestClient(create_approvals_app(config))
    response = client.post(
        f"/approvals/{approval.id}/allow",
        data={"comment": "ship"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert ApprovalStore(config.approvals).get(approval.id).status == "approved"


def test_ui_web_deny_redirects_with_empty_body(tmp_path: Path) -> None:
    config = _ui_config(tmp_path)
    approval = ApprovalStore(config.approvals).create(_ui_context(), "p1")
    client = TestClient(create_approvals_app(config))
    response = client.post(f"/approvals/{approval.id}/deny", follow_redirects=False)
    assert response.status_code == 303
    assert ApprovalStore(config.approvals).get(approval.id).status == "denied"


def test_ui_index_shows_decision_note(tmp_path: Path) -> None:
    config = _ui_config(tmp_path)
    store = ApprovalStore(config.approvals)
    approval = store.create(_ui_context(), "p1")
    store.set_status(approval.id, "approved", decided_by="reviewer")
    client = TestClient(create_approvals_app(config))
    response = client.get("/")
    assert "Decided by reviewer" in response.text


def test_ui_invalid_transition_returns_409(tmp_path: Path) -> None:
    config = _ui_config(tmp_path)
    store = ApprovalStore(config.approvals)
    approval = store.create(_ui_context(), "p1")
    store.set_status(approval.id, "denied", decided_by="reviewer")
    client = TestClient(create_approvals_app(config))
    # denied -> approved is not a permitted transition.
    response = client.post(f"/api/approvals/{approval.id}/allow", json={})
    assert response.status_code == 409


def test_ui_set_status_keyerror_returns_404(tmp_path: Path, monkeypatch) -> None:
    config = _ui_config(tmp_path)
    approval = ApprovalStore(config.approvals).create(_ui_context(), "p1")

    def raise_key_error(*args: Any, **kwargs: Any) -> None:
        raise KeyError("gone")

    monkeypatch.setattr(ApprovalStore, "set_status", raise_key_error)
    client = TestClient(create_approvals_app(config))
    response = client.post(f"/api/approvals/{approval.id}/allow", json={})
    assert response.status_code == 404
