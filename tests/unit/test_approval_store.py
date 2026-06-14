from __future__ import annotations

from pathlib import Path

from mcp_zero_trust_layer.approvals import ApprovalStore
from mcp_zero_trust_layer.config.models import ApprovalsConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.identity import Identity


def _context() -> RequestContext:
    return RequestContext(
        server="github",
        method="tools/call",
        capability_type="tool",
        capability="github.merge_pull_request",
        arguments={"repo": "acme/api", "pull_number": 1},
        identity=Identity(subject="ana", client_id="cursor"),
    )


def test_sqlite_approval_store_create_list_get_and_validate(tmp_path: Path) -> None:
    config = ApprovalsConfig(backend="sqlite", path=str(tmp_path / "approvals.sqlite3"))
    store = ApprovalStore(config)

    approval = store.create(_context(), "critical-needs-approval")

    assert approval.id.startswith("appr_")
    assert store.get(approval.id) == approval
    assert [item.id for item in store.list()] == [approval.id]

    approved = store.set_status(approval.id, "approved", decided_by="reviewer")

    assert approved.decided_by == "reviewer"
    assert store.is_valid_for(approval.id, _context(), "critical-needs-approval") is True
    assert (tmp_path / "approvals.sqlite3").exists()


def test_sqlite_approval_store_rejects_changed_arguments(tmp_path: Path) -> None:
    config = ApprovalsConfig(backend="sqlite", path=str(tmp_path / "approvals.sqlite3"))
    store = ApprovalStore(config)
    approval = store.create(_context(), "critical-needs-approval")
    store.set_status(approval.id, "approved", decided_by="reviewer")

    changed = _context().model_copy(update={"arguments": {"repo": "acme/api", "pull_number": 2}})

    assert store.is_valid_for(approval.id, changed, "critical-needs-approval") is False
