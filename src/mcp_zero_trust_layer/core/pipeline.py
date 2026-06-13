from __future__ import annotations

from typing import Any
from uuid import uuid4

from mcp_zero_trust_layer.audit import AuditLogger
from mcp_zero_trust_layer.approvals import ApprovalNotifier, ApprovalStore
from mcp_zero_trust_layer.capabilities.filtering import filter_capabilities
from mcp_zero_trust_layer.config.models import MCPZTConfig, PolicyConfig, ServerConfig
from mcp_zero_trust_layer.core.context import RequestContext
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.observability import MetricsCollector
from mcp_zero_trust_layer.output import OutputEnforcer
from mcp_zero_trust_layer.policy import PolicyDecision, PolicyEngine
from mcp_zero_trust_layer.protocol import (
    JSONRPCError,
    error_response,
    is_notification,
    is_request,
    is_response,
)
from mcp_zero_trust_layer.protocol.jsonrpc import require_jsonrpc_message
from mcp_zero_trust_layer.upstream import UpstreamClient

LIST_RESULT_KEYS = {
    "tools/list": ("tool", "tools"),
    "resources/list": ("resource", "resources"),
    "prompts/list": ("prompt", "prompts"),
}

CALL_METHODS = {
    "tools/call": ("tool", "name", "arguments"),
    "resources/read": ("resource", "uri", None),
    "prompts/get": ("prompt", "name", "arguments"),
}

SAFE_NOTIFICATION_METHODS = {
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/roots/list_changed",
    "notifications/tools/list_changed",
    "notifications/resources/list_changed",
    "notifications/prompts/list_changed",
}


class MCPPipeline:
    def __init__(
        self,
        config: MCPZTConfig,
        upstream: UpstreamClient,
        *,
        metrics: MetricsCollector | None = None,
    ):
        self.config = config
        self.upstream = upstream
        self.policy_engine = PolicyEngine(config)
        self.audit = AuditLogger(config.audit)
        self.output_enforcer = OutputEnforcer()
        self.approvals = ApprovalStore(config.approvals)
        self.approval_notifier = ApprovalNotifier(config.approvals)
        self.metrics = metrics

    def handle(
        self,
        server_name: str,
        message: dict[str, Any],
        *,
        identity: Identity | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        request_id = message.get("id")
        try:
            message = require_jsonrpc_message(message)
            server = self._server(server_name)
            if is_response(message):
                return self._forward_notification(server, message, headers=headers)
            if is_notification(message):
                return self._handle_notification(
                    server,
                    message,
                    identity=identity or Identity(environment=self.config.project.environment),
                    headers=headers,
                )
            if not is_request(message):
                return self.upstream.send(server, message, headers=headers)
            return self._handle_request(
                server,
                message,
                identity=identity or Identity(environment=self.config.project.environment),
                headers=headers,
            )
        except JSONRPCError as exc:
            return error_response(request_id, exc.code, exc.message, exc.data)

    def _handle_request(
        self,
        server: ServerConfig,
        message: dict[str, Any],
        *,
        identity: Identity,
        headers: dict[str, str] | None,
    ) -> dict[str, Any]:
        method = message["method"]
        request_id = message.get("id")
        context = self._context_for_message(server.name, message, identity=identity)
        decision = self.policy_engine.evaluate(context)

        if method in LIST_RESULT_KEYS:
            if decision.decision in {"deny", "hide"} and decision.policy_id and not decision.dry_run:
                self._log_decision(context, decision, upstream_called=False)
                return self._deny_response(request_id, decision)
            upstream_response = self.upstream.send(server, message, headers=headers)
            self._log_decision(context, decision, upstream_called=True)
            if upstream_response is None:
                return error_response(request_id, -32603, "Upstream returned no response")
            if self.config.runtime.dry_run:
                return upstream_response
            return self._filter_list_response(server.name, method, upstream_response, identity)

        if method in CALL_METHODS:
            if decision.decision in {"deny", "hide"} and not decision.dry_run:
                self._log_decision(context, decision, upstream_called=False)
                if method == "tools/call" and decision.validation_errors:
                    return {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": "; ".join(decision.validation_errors),
                                }
                            ],
                            "isError": True,
                        },
                    }
                return self._deny_response(request_id, decision)
            if decision.decision == "require_approval" and not decision.dry_run:
                approval_id = _extract_approval_id(message)
                if approval_id and decision.policy_id and self.approvals.is_valid_for(
                    approval_id, context, decision.policy_id
                ):
                    message = _strip_approval_id(message)
                    upstream_response = self.upstream.send(server, message, headers=headers)
                    self._log_decision(context, decision, upstream_called=True)
                    if upstream_response is None:
                        return error_response(request_id, -32603, "Upstream returned no response")
                    return self._enforce_output(context, upstream_response, request_id)
                approval = self.approvals.create(context, decision.policy_id or "unknown")
                self._log_decision(context, decision, upstream_called=False)
                self.audit.log_approval("created", approval.model_dump(mode="json"))
                self.approval_notifier.notify("created", approval.model_dump(mode="json"))
                return error_response(
                    request_id,
                    -32010,
                    "Approval required",
                    {
                        "decision": decision.decision,
                        "policy_id": decision.policy_id,
                        "reason": decision.reason,
                        "approval_id": approval.id,
                        "expires_at": approval.expires_at.isoformat()
                        if approval.expires_at
                        else None,
                    },
                )
            upstream_response = self.upstream.send(server, message, headers=headers)
            self._log_decision(context, decision, upstream_called=True)
            if upstream_response is None:
                return error_response(request_id, -32603, "Upstream returned no response")
            return self._enforce_output(context, upstream_response, request_id)

        if decision.decision in {"deny", "hide"} and not decision.dry_run:
            self._log_decision(context, decision, upstream_called=False)
            return self._deny_response(request_id, decision)
        upstream_response = self.upstream.send(server, message, headers=headers)
        self._log_decision(context, decision, upstream_called=True)
        return upstream_response or error_response(
            request_id, -32603, "Upstream returned no response"
        )

    def _handle_notification(
        self,
        server: ServerConfig,
        message: dict[str, Any],
        *,
        identity: Identity,
        headers: dict[str, str] | None,
    ) -> dict[str, Any] | None:
        method = message.get("method", "")
        if method in SAFE_NOTIFICATION_METHODS:
            return self.upstream.send(server, message, headers=headers)

        context = self._context_for_message(server.name, message, identity=identity)
        decision = self.policy_engine.evaluate(context)
        if decision.decision in {"deny", "hide", "require_approval"} and not decision.dry_run:
            self._log_decision(context, decision, upstream_called=False)
            return None
        response = self.upstream.send(server, message, headers=headers)
        self._log_decision(context, decision, upstream_called=True)
        return response

    def _forward_notification(
        self,
        server: ServerConfig,
        message: dict[str, Any],
        *,
        headers: dict[str, str] | None,
    ) -> dict[str, Any] | None:
        return self.upstream.send(server, message, headers=headers)

    def _filter_list_response(
        self,
        server_name: str,
        method: str,
        response: dict[str, Any],
        identity: Identity,
    ) -> dict[str, Any]:
        if "result" not in response or method not in LIST_RESULT_KEYS:
            return response
        capability_type, result_key = LIST_RESULT_KEYS[method]
        result = response.get("result")
        if not isinstance(result, dict):
            return response
        raw_items = result.get(result_key)
        if not isinstance(raw_items, list):
            return response
        filtered = filter_capabilities(
            self.config,
            server_name,
            capability_type,  # type: ignore[arg-type]
            raw_items,
            identity=identity,
            environment=self.config.project.environment,
        )
        response = dict(response)
        response["result"] = dict(result)
        response["result"][result_key] = filtered
        return response

    def _enforce_output(
        self,
        inbound_context: RequestContext,
        upstream_response: dict[str, Any],
        request_id: Any,
    ) -> dict[str, Any]:
        if "result" in upstream_response:
            payload_key = "result"
        elif "error" in upstream_response:
            payload_key = "error"
        else:
            return upstream_response
        output_payload = upstream_response[payload_key]
        output_context = inbound_context.model_copy(
            update={"direction": "outbound", "output": output_payload}
        )
        decision = self.policy_engine.evaluate(output_context)
        if decision.policy_id:
            self._log_decision(output_context, decision)
        if decision.dry_run:
            return upstream_response
        if decision.decision == "deny" and decision.policy_id:
            return error_response(
                request_id,
                -32020,
                "Output blocked by policy",
                {"policy_id": decision.policy_id, "reason": decision.reason},
            )
        if decision.decision in {"redact", "limit", "transform"} and decision.policy_id:
            policy = self._policy_by_id(decision.policy_id)
            if policy:
                allowed, transformed, reason = self.output_enforcer.enforce(
                    output_payload, policy
                )
                if not allowed:
                    return error_response(
                        request_id,
                        -32020,
                        "Output blocked by policy",
                        {"policy_id": policy.id, "reason": reason},
                    )
                upstream_response = dict(upstream_response)
                upstream_response[payload_key] = transformed
        return upstream_response

    def _context_for_message(
        self,
        server_name: str,
        message: dict[str, Any],
        *,
        identity: Identity,
    ) -> RequestContext:
        method = message.get("method", "")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        capability_type = "method"
        capability = method
        arguments: dict[str, Any] = {}

        if method in CALL_METHODS:
            mapped_type, capability_key, arguments_key = CALL_METHODS[method]
            capability_type = mapped_type
            capability = params.get(capability_key)
            if arguments_key:
                raw_args = params.get(arguments_key, {})
                arguments = raw_args if isinstance(raw_args, dict) else {}
                arguments = {
                    key: value
                    for key, value in arguments.items()
                    if key != "_mcpzt_approval_id"
                }
            else:
                arguments = {
                    key: value for key, value in params.items() if key != "_mcpzt_approval_id"
                }
        elif method in LIST_RESULT_KEYS:
            capability_type = "method"
            capability = method
            arguments = params

        return RequestContext(
            server=server_name,
            method=method,
            capability_type=capability_type,  # type: ignore[arg-type]
            capability=capability,
            arguments=arguments,
            identity=identity,
            environment=self.config.project.environment,
            correlation_id=f"corr_{uuid4().hex}",
            config_base_dir=self.config.config_base_dir,
        )

    def _server(self, name: str) -> ServerConfig:
        for server in self.config.servers:
            if server.name == name:
                return server
        raise JSONRPCError(-32004, "Unknown MCP server", {"server": name})

    def _policy_by_id(self, policy_id: str) -> PolicyConfig | None:
        return next((policy for policy in self.config.policies if policy.id == policy_id), None)

    def _log_decision(
        self,
        context: RequestContext,
        decision: PolicyDecision,
        *,
        upstream_called: bool | None = None,
        upstream_status: str | None = None,
    ) -> None:
        self.audit.log_decision(
            context,
            decision,
            upstream_called=upstream_called,
            upstream_status=upstream_status,
        )
        if self.metrics:
            self.metrics.record_decision(context, decision)

    @staticmethod
    def _deny_response(request_id: Any, decision: PolicyDecision) -> dict[str, Any]:
        return error_response(
            request_id,
            -32001,
            "Request denied by policy",
            {
                "decision": decision.decision,
                "policy_id": decision.policy_id,
                "reason": decision.reason,
                "validation_errors": decision.validation_errors,
            },
        )


def _extract_approval_id(message: dict[str, Any]) -> str | None:
    params = message.get("params")
    if not isinstance(params, dict):
        return None
    direct = params.get("_mcpzt_approval_id")
    if isinstance(direct, str):
        return direct
    arguments = params.get("arguments")
    if isinstance(arguments, dict) and isinstance(arguments.get("_mcpzt_approval_id"), str):
        return arguments["_mcpzt_approval_id"]
    return None


def _strip_approval_id(message: dict[str, Any]) -> dict[str, Any]:
    copied = dict(message)
    params = copied.get("params")
    if not isinstance(params, dict):
        return copied
    params = dict(params)
    params.pop("_mcpzt_approval_id", None)
    arguments = params.get("arguments")
    if isinstance(arguments, dict):
        arguments = dict(arguments)
        arguments.pop("_mcpzt_approval_id", None)
        params["arguments"] = arguments
    copied["params"] = params
    return copied
