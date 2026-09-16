from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import mcp_zero_trust_layer.approvals.store as store_module
import mcp_zero_trust_layer.audit.logger as logger_module
from mcp_zero_trust_layer.approvals import ApprovalNotifier, ApprovalStore, create_approvals_app
from mcp_zero_trust_layer.audit import AuditLogger, verify_audit_hash_chain
from mcp_zero_trust_layer.config.models import ApprovalsConfig, AuditConfig, MCPZTConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.policy import PolicyDecision


def _context() -> RequestContext:
    return RequestContext(
        server="github",
        method="tools/call",
        capability_type="tool",
        capability="github.merge_pull_request",
        arguments={"repo": "acme/api", "pull_number": 1},
        identity=Identity(subject="ana", client_id="cursor"),
    )


def _token_config(tmp_path: Path) -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "ui-test", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "static_token", "token": "s3cret", "trust_identity_headers": True},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "policies": [],
            "audit": {"destination": "file", "path": str(tmp_path / "audit.jsonl")},
            "approvals": {"path": str(tmp_path / "approvals.sqlite3"), "backend": "sqlite"},
        }
    )


@pytest.mark.parametrize("backend", ["file", "sqlite"])
def test_consumption_preserves_review_and_same_status_is_idempotent(tmp_path, backend):
    store = ApprovalStore(ApprovalsConfig(backend=backend, path=str(tmp_path / "store")))
    approval = store.create(_context(), "p")
    reviewed = store.set_status(
        approval.id, "approved", decided_by="reviewer", decision_comment="review evidence"
    )
    assert store.set_status(approval.id, "approved", decided_by="someone-else") == reviewed
    assert store.consume_if_valid(approval.id, _context(), "p")
    consumed = store.get(approval.id)
    assert consumed.decided_at == reviewed.decided_at
    assert consumed.decided_by == reviewed.decided_by
    assert consumed.decision_comment == reviewed.decision_comment
    assert consumed.consumed_at >= reviewed.decided_at
    assert not store.consume_if_valid(approval.id, _context(), "p")


def test_sqlite_review_serializes_with_consumption(tmp_path, monkeypatch):
    store = ApprovalStore(ApprovalsConfig(backend="sqlite", path=str(tmp_path / "store")))
    approval = store.create(_context(), "p")
    store.set_status(approval.id, "approved", decided_by="reviewer")
    reviewer_read = threading.Event()
    consumer_started = threading.Event()
    consumer_done = threading.Event()
    original = store_module._with_status

    def pause_reviewer(approval, status, **kwargs):
        if threading.current_thread().name == "reviewer":
            reviewer_read.set()
            assert consumer_started.wait(5)
            # A consumer must not pass the reviewer's transaction lock.
            assert not consumer_done.wait(0.1)
        return original(approval, status, **kwargs)

    monkeypatch.setattr(store_module, "_with_status", pause_reviewer)
    errors = []

    def review():
        try:
            store.set_status(approval.id, "approved", decided_by="reviewer")
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=review, name="reviewer")
    thread.start()
    assert reviewer_read.wait(5)
    consumer_started.set()
    assert store.consume_if_valid(approval.id, _context(), "p")
    consumer_done.set()
    thread.join(5)
    assert not thread.is_alive()
    assert not errors
    assert store.get(approval.id).status == "consumed"
    assert not store.consume_if_valid(approval.id, _context(), "p")


@pytest.mark.parametrize("route", ["/", "/api/approvals"])
def test_approval_reads_require_configured_auth(tmp_path, route):
    config = _token_config(tmp_path)
    approval = ApprovalStore(config.approvals).create(_context(), "p")
    client = TestClient(create_approvals_app(config))
    assert client.get(route).status_code == 401
    response = client.get(route, headers={"authorization": "Bearer s3cret"})
    assert response.status_code == 200
    assert approval.id in response.text


@pytest.mark.parametrize("action,status", [("allow", "approved"), ("deny", "denied")])
def test_ui_records_and_notifies_authenticated_decision(tmp_path, monkeypatch, action, status):
    config = _token_config(tmp_path)
    approval = ApprovalStore(config.approvals).create(_context(), "p")
    notifications = []
    monkeypatch.setattr(
        ApprovalNotifier, "notify", lambda self, action, payload: notifications.append((action, payload))
    )
    client = TestClient(create_approvals_app(config))
    response = client.post(
        f"/api/approvals/{approval.id}/{action}",
        headers={"authorization": "Bearer s3cret", "x-mcpzt-subject": "reviewer"},
        json={"comment": "review evidence"},
    )
    assert response.status_code == 200
    intent, event = [json.loads(line) for line in Path(config.audit.path).read_text().splitlines()]
    assert intent["action"] == "decision_intent"
    assert intent["approval"]["status"] == "pending"
    assert intent["approval"]["requested_by"] == "reviewer"
    assert intent["approval"]["requested_status"] == status
    assert event["event_type"] == "approval"
    assert event["action"] == status
    assert event["approval"]["decided_by"] == "reviewer"
    assert event["approval"]["decision_comment"] == "review evidence"
    assert notifications == [(status, response.json())]
    assert verify_audit_hash_chain(config.audit.path)[0]


def test_stdout_chain_is_verifiable_across_concurrent_events(tmp_path, capsys):
    logger = AuditLogger(AuditConfig(destination="stdout", hash_chain=True))
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda index: logger.log_approval("created", {"index": index}), range(40)))
    path = tmp_path / "stdout.jsonl"
    path.write_text(capsys.readouterr().out)
    assert verify_audit_hash_chain(path) == (True, "verified 40 event(s)")


def test_audit_record_is_flushed_and_synced_before_unlock(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(AuditConfig(path=str(path), strict=True))
    real_flock = logger_module.fcntl.flock
    real_fsync = logger_module.os.fsync
    synced = []

    def fsync(fd):
        real_fsync(fd)
        synced.append(fd)

    def flock(fd, operation):
        if operation == logger_module.fcntl.LOCK_UN:
            assert synced == [fd]
            assert verify_audit_hash_chain(path) == (True, "verified 1 event(s)")
        return real_flock(fd, operation)

    monkeypatch.setattr(logger_module.os, "fsync", fsync)
    monkeypatch.setattr(logger_module.fcntl, "flock", flock)
    logger.log_approval("approved", {"id": "approval"})


def test_decision_evidence_has_binding_and_direction(tmp_path):
    from mcp_zero_trust_layer.approvals.store import hash_arguments

    logger = AuditLogger(AuditConfig(path=str(tmp_path / "audit.jsonl")))
    context = _context()
    event = logger.log_decision(
        context, PolicyDecision(decision="allow", reason="approved"), approval_id="appr_1"
    )
    assert event["approval_id"] == "appr_1"
    assert event["direction"] == context.direction
    assert event["arguments_hash"] == hash_arguments(context.arguments)


def test_verifier_rejects_non_object_json(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("[]\n")
    assert verify_audit_hash_chain(path) == (False, "line 1: event must be a JSON object")


def test_concurrent_file_writers_preserve_one_chain(tmp_path):
    path = tmp_path / "concurrent.jsonl"
    loggers = [AuditLogger(AuditConfig(path=str(path))) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(
            lambda index: loggers[index % 8].log_approval("created", {"index": index}),
            range(80),
        ))
    assert verify_audit_hash_chain(path) == (True, "verified 80 event(s)")
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert {event["approval"]["index"] for event in events} == set(range(80))


@pytest.mark.parametrize("backend", ["file", "sqlite"])
def test_full_request_binding_rejects_changed_and_legacy_approvals(tmp_path, backend):
    store = ApprovalStore(ApprovalsConfig(backend=backend, path=str(tmp_path / "store")))
    context = _context().model_copy(update={"metadata": {"request_binding": "digest-v1"}})
    approval = store.create(context, "p")
    store.set_status(approval.id, "approved")
    assert store.is_valid_for(approval.id, context, "p")
    assert not store.is_valid_for(
        approval.id, context.model_copy(update={"metadata": {"request_binding": "digest-v2"}}), "p"
    )
    assert not store.is_valid_for(approval.id, _context(), "p")
    legacy = store.create(_context(), "p")
    store.set_status(legacy.id, "approved")
    assert not store.is_valid_for(legacy.id, context, "p")
    assert store.is_valid_for(legacy.id, _context(), "p")


def test_ui_strict_audit_failure_leaves_approval_pending(tmp_path):
    config = _token_config(tmp_path)
    config.audit.path = str(tmp_path)
    store = ApprovalStore(config.approvals)
    approval = store.create(_context(), "p")
    client = TestClient(create_approvals_app(config), raise_server_exceptions=False)
    response = client.post(
        f"/api/approvals/{approval.id}/allow",
        headers={"authorization": "Bearer s3cret", "x-mcpzt-subject": "reviewer"},
        json={"comment": "review"},
    )
    assert response.status_code == 500
    assert store.get(approval.id).status == "pending"
    assert not store.consume_if_valid(approval.id, _context(), "p")


def test_cli_strict_audit_failure_leaves_approval_pending(tmp_path):
    import yaml
    from typer.testing import CliRunner

    from mcp_zero_trust_layer.cli.main import app

    config = _token_config(tmp_path)
    config.audit.path = str(tmp_path)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config.model_dump(mode="json")))
    store = ApprovalStore(config.approvals)
    approval = store.create(_context(), "p")
    result = CliRunner().invoke(app, [
        "approve", "allow", approval.id, "--config", str(path), "--by", "reviewer",
    ])
    assert result.exit_code != 0
    assert isinstance(result.exception, OSError)
    assert store.get(approval.id).status == "pending"
    assert not store.consume_if_valid(approval.id, _context(), "p")
