from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_zero_trust_layer.approvals import ApprovalStore
from mcp_zero_trust_layer.config.models import MCPZTConfig, ServerConfig
from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.identity import Identity


class RecordingUpstream:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    def send(
        self,
        server: ServerConfig,
        message: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        self.messages.append(message)
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}


def _config(tmp_path: Path) -> MCPZTConfig:
    return MCPZTConfig.model_validate(
        {
            "project": {"name": "approval-test", "environment": "development"},
            "runtime": {"default_decision": "deny"},
            "auth": {"mode": "none"},
            "servers": [
                {"name": "github", "transport": "http", "upstream": "http://localhost:3001/mcp"}
            ],
            "capability_mappings": {
                "github": {
                    "tools": {
                        "github.merge_pull_request": {
                            "action": "code.merge",
                            "risk": "critical",
                            "access": "write",
                        }
                    }
                }
            },
            "policies": [
                {
                    "id": "critical-needs-approval",
                    "effect": "require_approval",
                    "match": {"server": "github", "risk": "critical"},
                }
            ],
            "audit": {"destination": "file", "path": str(tmp_path / "audit.jsonl")},
            "approvals": {"path": str(tmp_path / "approvals.json")},
        }
    )


def _merge_message(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "github.merge_pull_request", "arguments": arguments},
    }


def test_approval_required_then_approved_retry_reaches_upstream(tmp_path: Path) -> None:
    config = _config(tmp_path)
    upstream = RecordingUpstream()
    pipeline = MCPPipeline(config, upstream)
    identity = Identity(subject="ana", client_id="cursor")

    first = pipeline.handle(
        "github",
        _merge_message({"repo": "acme/api", "pull_number": 1}),
        identity=identity,
    )

    assert first is not None
    approval_id = first["error"]["data"]["approval_id"]
    assert upstream.messages == []

    approval = ApprovalStore(config.approvals).set_status(
        approval_id,
        "approved",
        decided_by="security-reviewer",
        decision_comment="looks good",
    )
    assert approval.decided_by == "security-reviewer"
    assert approval.decision_comment == "looks good"
    assert approval.decided_at is not None
    second = pipeline.handle(
        "github",
        _merge_message(
            {
                "repo": "acme/api",
                "pull_number": 1,
                "_mcpzt_approval_id": approval_id,
            }
        ),
        identity=identity,
    )

    assert second == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    assert upstream.messages == [
        _merge_message({"repo": "acme/api", "pull_number": 1})
    ]


def test_approval_retry_with_changed_arguments_is_rejected(tmp_path: Path) -> None:
    config = _config(tmp_path)
    upstream = RecordingUpstream()
    pipeline = MCPPipeline(config, upstream)
    identity = Identity(subject="ana", client_id="cursor")

    first = pipeline.handle(
        "github",
        _merge_message({"repo": "acme/api", "pull_number": 1}),
        identity=identity,
    )
    approval_id = first["error"]["data"]["approval_id"]  # type: ignore[index]
    ApprovalStore(config.approvals).set_status(approval_id, "approved", decided_by="reviewer")

    retry = pipeline.handle(
        "github",
        _merge_message(
            {
                "repo": "acme/api",
                "pull_number": 2,
                "_mcpzt_approval_id": approval_id,
            }
        ),
        identity=identity,
    )

    assert retry is not None
    assert retry["error"]["code"] == -32010
    assert upstream.messages == []
