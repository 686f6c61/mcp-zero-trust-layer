from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from mcp_zero_trust_layer.capabilities.mapping import lookup_capability_metadata
from mcp_zero_trust_layer.config.models import MCPZTConfig, PolicyConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.policy.adapters import evaluate_external_policy
from mcp_zero_trust_layer.policy.conditions import evaluate_conditions
from mcp_zero_trust_layer.policy.models import PolicyDecision
from mcp_zero_trust_layer.validators import ValidatorEngine
from mcp_zero_trust_layer.validators.input_policy import validate_input_policy


LIST_METHODS = {"tools/list", "resources/list", "prompts/list"}


class PolicyEngine:
    """Deterministic policy evaluator."""

    def __init__(self, config: MCPZTConfig):
        self.config = config
        self.validator_engine = ValidatorEngine()

    def evaluate(self, context: RequestContext) -> PolicyDecision:
        metadata = lookup_capability_metadata(self.config, context)
        if self.config.policy_engine.adapter != "builtin":
            return evaluate_external_policy(
                self.config.policy_engine,
                context,
                metadata,
                dry_run=self.config.runtime.dry_run,
            )

        matching = [
            policy
            for policy in self.config.policies
            if self._matches(policy, context, metadata)
            and evaluate_conditions(policy.when, context)
        ]

        selected = self._select_by_precedence(matching)
        if selected:
            should_validate_request = (
                selected.effect not in {"deny", "hide"} and context.method not in LIST_METHODS
            )
            if should_validate_request and selected.input:
                validation = validate_input_policy(context.arguments, selected.input)
                if not validation.passed:
                    return self._validation_denied(
                        selected, context, metadata, matching, validation.errors
                    )

            if should_validate_request and selected.validators:
                validation = self.validator_engine.validate(selected.validators, context)
                if not validation.passed:
                    return self._validation_denied(
                        selected, context, metadata, matching, validation.errors
                    )

            return PolicyDecision(
                decision=selected.effect,
                policy_id=selected.id,
                reason=selected.reason or f"matched policy {selected.id}",
                risk=metadata.risk if metadata else None,
                approval_required=selected.effect == "require_approval",
                dry_run=self.config.runtime.dry_run,
                metadata={"matched_policies": [policy.id for policy in matching]},
            )

        return PolicyDecision(
            decision=self.config.runtime.default_decision,
            reason=f"default decision: {self.config.runtime.default_decision}",
            risk=metadata.risk if metadata else None,
            dry_run=self.config.runtime.dry_run,
        )

    def explain(self, context: RequestContext) -> dict[str, Any]:
        metadata = lookup_capability_metadata(self.config, context)
        if self.config.policy_engine.adapter != "builtin":
            decision = evaluate_external_policy(
                self.config.policy_engine,
                context,
                metadata,
                dry_run=self.config.runtime.dry_run,
            )
            return {
                "adapter": self.config.policy_engine.adapter,
                "context": context.model_dump(mode="json"),
                "metadata": metadata.model_dump(mode="json") if metadata else None,
                "decision": decision.model_dump(mode="json"),
            }

        explanations = []
        matching: list[PolicyConfig] = []
        for policy in self.config.policies:
            match_report = self._match_report(policy, context, metadata)
            condition_matched = evaluate_conditions(policy.when, context)
            matched = match_report["matched"] and condition_matched
            if matched:
                matching.append(policy)
            explanations.append(
                {
                    "policy_id": policy.id,
                    "effect": policy.effect,
                    "matched": matched,
                    "match": match_report,
                    "conditions_matched": condition_matched,
                    "condition": policy.when,
                }
            )

        decision = self.evaluate(context)
        return {
            "adapter": "builtin",
            "context": context.model_dump(mode="json"),
            "metadata": metadata.model_dump(mode="json") if metadata else None,
            "matched_policies": [policy.id for policy in matching],
            "selected_policy_id": decision.policy_id,
            "decision": decision.model_dump(mode="json"),
            "policies": explanations,
        }

    def _matches(
        self, policy: PolicyConfig, context: RequestContext, metadata: object | None
    ) -> bool:
        match = policy.match
        identity = context.identity

        if match.server and match.server != context.server:
            return False
        if match.method and not fnmatch(context.method, match.method):
            return False
        if match.capability_type and match.capability_type != context.capability_type:
            return False
        if match.capability and not self._matches_any(context.capability, [match.capability]):
            return False
        if match.capabilities and not self._matches_any(context.capability, match.capabilities):
            return False
        if match.environment and match.environment != context.environment:
            return False
        if match.user and match.user not in {identity.subject, identity.email}:
            return False
        if match.group and match.group not in identity.groups:
            return False
        if match.role and match.role not in identity.roles:
            return False
        if match.client_id and match.client_id != identity.client_id:
            return False
        if match.agent_id and match.agent_id != identity.agent_id:
            return False

        if metadata is not None:
            if match.action and match.action != metadata.action:
                return False
            if match.risk and match.risk != metadata.risk:
                return False
            if match.access and match.access != metadata.access:
                return False
            if match.resource_type and match.resource_type != metadata.resource_type:
                return False
            if match.data_classification and match.data_classification != metadata.data_classification:
                return False
            if match.tag and match.tag not in metadata.tags:
                return False
            if match.tags and not set(match.tags).issubset(set(metadata.tags)):
                return False
        elif any(
            [
                match.action,
                match.risk,
                match.access,
                match.resource_type,
                match.data_classification,
                match.tag,
                match.tags,
            ]
        ):
            return False

        return True

    def _match_report(
        self,
        policy: PolicyConfig,
        context: RequestContext,
        metadata: object | None,
    ) -> dict[str, Any]:
        failures: list[str] = []
        match = policy.match
        identity = context.identity

        if match.server and match.server != context.server:
            failures.append(f"server {context.server!r} != {match.server!r}")
        if match.method and not fnmatch(context.method, match.method):
            failures.append(f"method {context.method!r} does not match {match.method!r}")
        if match.capability_type and match.capability_type != context.capability_type:
            failures.append(
                f"capability_type {context.capability_type!r} != {match.capability_type!r}"
            )
        if match.capability and not self._matches_any(context.capability, [match.capability]):
            failures.append(f"capability {context.capability!r} does not match {match.capability!r}")
        if match.capabilities and not self._matches_any(context.capability, match.capabilities):
            failures.append(
                f"capability {context.capability!r} does not match configured capabilities"
            )
        if match.environment and match.environment != context.environment:
            failures.append(f"environment {context.environment!r} != {match.environment!r}")
        if match.user and match.user not in {identity.subject, identity.email}:
            failures.append(f"user {identity.subject!r} or email {identity.email!r} did not match")
        if match.group and match.group not in identity.groups:
            failures.append(f"group {match.group!r} not present")
        if match.role and match.role not in identity.roles:
            failures.append(f"role {match.role!r} not present")
        if match.client_id and match.client_id != identity.client_id:
            failures.append(f"client_id {identity.client_id!r} != {match.client_id!r}")
        if match.agent_id and match.agent_id != identity.agent_id:
            failures.append(f"agent_id {identity.agent_id!r} != {match.agent_id!r}")

        metadata_requirements = [
            match.action,
            match.risk,
            match.access,
            match.resource_type,
            match.data_classification,
            match.tag,
            match.tags,
        ]
        if metadata is None and any(metadata_requirements):
            failures.append("capability metadata is missing")
        elif metadata is not None:
            if match.action and match.action != metadata.action:
                failures.append(f"action {metadata.action!r} != {match.action!r}")
            if match.risk and match.risk != metadata.risk:
                failures.append(f"risk {metadata.risk!r} != {match.risk!r}")
            if match.access and match.access != metadata.access:
                failures.append(f"access {metadata.access!r} != {match.access!r}")
            if match.resource_type and match.resource_type != metadata.resource_type:
                failures.append(
                    f"resource_type {metadata.resource_type!r} != {match.resource_type!r}"
                )
            if (
                match.data_classification
                and match.data_classification != metadata.data_classification
            ):
                failures.append(
                    "data_classification "
                    f"{metadata.data_classification!r} != {match.data_classification!r}"
                )
            if match.tag and match.tag not in metadata.tags:
                failures.append(f"tag {match.tag!r} not present")
            if match.tags and not set(match.tags).issubset(set(metadata.tags)):
                failures.append(f"tags {match.tags!r} are not all present")

        return {"matched": not failures, "failures": failures}

    def _validation_denied(
        self,
        selected: PolicyConfig,
        context: RequestContext,
        metadata: object | None,
        matching: list[PolicyConfig],
        errors: list[str],
    ) -> PolicyDecision:
        return PolicyDecision(
            decision="deny",
            policy_id=selected.id,
            reason="validator failed",
            risk=metadata.risk if metadata else None,
            validation_errors=errors,
            dry_run=self.config.runtime.dry_run,
            metadata={
                "matched_policies": [policy.id for policy in matching],
                "validated_policy": selected.id,
                "server": context.server,
            },
        )

    @staticmethod
    def _matches_any(value: str | None, patterns: list[str]) -> bool:
        if value is None:
            return False
        return any(fnmatch(value, pattern) for pattern in patterns)

    @staticmethod
    def _select_by_precedence(policies: list[PolicyConfig]) -> PolicyConfig | None:
        precedence = {
            "deny": 0,
            "hide": 1,
            "require_approval": 2,
            "redact": 3,
            "limit": 4,
            "transform": 5,
            "allow": 6,
            "log": 7,
        }
        if not policies:
            return None
        return sorted(policies, key=lambda policy: precedence[policy.effect])[0]
