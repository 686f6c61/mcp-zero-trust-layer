from __future__ import annotations

from collections import Counter
from threading import Lock

from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.policy.models import PolicyDecision


class MetricsCollector:
    def __init__(self) -> None:
        self._lock = Lock()
        self._decisions: Counter[tuple[str, str, str, str]] = Counter()

    def record_decision(self, context: RequestContext, decision: PolicyDecision) -> None:
        key = (
            context.server,
            context.method,
            decision.decision,
            decision.policy_id or "default",
        )
        with self._lock:
            self._decisions[key] += 1

    def render_prometheus(self) -> str:
        lines = [
            "# HELP mcpzt_policy_decisions_total Policy decisions made by MCP Zero Trust Layer.",
            "# TYPE mcpzt_policy_decisions_total counter",
        ]
        with self._lock:
            for (server, method, decision, policy_id), count in sorted(self._decisions.items()):
                labels = {
                    "server": server,
                    "method": method,
                    "decision": decision,
                    "policy_id": policy_id,
                }
                rendered_labels = ",".join(
                    f'{name}="{_escape_label(value)}"' for name, value in labels.items()
                )
                lines.append(f"mcpzt_policy_decisions_total{{{rendered_labels}}} {count}")
        return "\n".join(lines) + "\n"


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
