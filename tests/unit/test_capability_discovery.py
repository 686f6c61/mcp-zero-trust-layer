from __future__ import annotations

from mcp_zero_trust_layer.capabilities.discovery import (
    CapabilitySnapshot,
    diff_snapshots,
)


def test_diff_detects_added_removed_and_changed_tools() -> None:
    previous = CapabilitySnapshot(
        server="github",
        discovered_at="2026-01-01T00:00:00Z",
        tools=[
            {"name": "github.search_issues", "description": "Search"},
            {"name": "github.delete_repository", "description": "Delete"},
        ],
    )
    current = CapabilitySnapshot(
        server="github",
        discovered_at="2026-01-02T00:00:00Z",
        tools=[
            {"name": "github.search_issues", "description": "Search issues"},
            {"name": "github.merge_pull_request", "description": "Merge"},
        ],
    )

    diff = diff_snapshots(previous, current)

    assert diff.added["tools"] == ["github.merge_pull_request"]
    assert diff.removed["tools"] == ["github.delete_repository"]
    assert diff.changed["tools"] == ["github.search_issues"]
    assert diff.has_changes() is True

