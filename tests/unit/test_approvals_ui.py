from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from mcp_zero_trust_layer.approvals import ApprovalStore, create_approvals_app
from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity


def _config(tmp_path: Path) -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "ui-test", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "policies": [],
            "audit": {"destination": "file", "path": str(tmp_path / "audit.jsonl")},
            "approvals": {"path": str(tmp_path / "approvals.sqlite3"), "backend": "sqlite"},
        }
    )


def _context() -> RequestContext:
    return RequestContext(
        server="github",
        method="tools/call",
        capability_type="tool",
        capability="github.merge_pull_request",
        arguments={"pull_number": 1},
        identity=Identity(subject="ana"),
    )


def test_approvals_ui_lists_and_approves_request(tmp_path: Path) -> None:
    config = _config(tmp_path)
    approval = ApprovalStore(config.approvals).create(_context(), "merge-needs-approval")
    client = TestClient(create_approvals_app(config))

    index = client.get("/")
    listed = client.get("/api/approvals")
    approved = client.post(
        f"/api/approvals/{approval.id}/allow",
        json={"decided_by": "reviewer", "comment": "ship it"},
    )

    assert index.status_code == 200
    assert approval.id in index.text
    assert listed.json()[0]["id"] == approval.id
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert ApprovalStore(config.approvals).get(approval.id).decided_by == "reviewer"  # type: ignore[union-attr]
