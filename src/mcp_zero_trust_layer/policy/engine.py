from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from mcp_zero_trust_layer.capabilities.mapping import lookup_capability_metadata
from mcp_zero_trust_layer.config.models import MCPZTConfig, PolicyConfig, PolicyMatch
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

        matching = self._matching_policies(context, metadata)
        selected = self._select_by_precedence(matching)
        if selected is None:
            return self._default_decision(metadata)

        validation_errors = self._request_validation_errors(selected, context)
        if validation_errors:
            return self._validation_denied(selected, context, metadata, matching, validation_errors)

        return self._selected_decision(selected, metadata, matching)

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

    def _matching_policies(
        self, context: RequestContext, metadata: object | None
    ) -> list[PolicyConfig]:
        return [
            policy
            for policy in self.config.policies
            if self._matches(policy, context, metadata)
            and evaluate_conditions(policy.when, context)
        ]

    def _matches(self, policy: PolicyConfig, context: RequestContext, metadata: object | None) -> bool:
        return not self._match_failures(policy, context, metadata)

    def _match_report(
        self,
        policy: PolicyConfig,
        context: RequestContext,
        metadata: object | None,
    ) -> dict[str, Any]:
        failures = self._match_failures(policy, context, metadata)
        return {"matched": not failures, "failures": failures}

    def _match_failures(
        self,
        policy: PolicyConfig,
        context: RequestContext,
        metadata: object | None,
    ) -> list[str]:
        match = policy.match
        failures = self._request_match_failures(match, context)
        failures.extend(self._metadata_match_failures(match, metadata))
        return failures

    def _request_match_failures(self, match: PolicyMatch, context: RequestContext) -> list[str]:
        identity = context.identity
        failures = _compact_failures(
            [
                _exact_failure("server", context.server, match.server),
                _method_failure(context.method, match.method),
                _exact_failure("capability_type", context.capability_type, match.capability_type),
                _pattern_failure("capability", context.capability, match.capability),
                _patterns_failure(context.capability, match.capabilities),
                _exact_failure("environment", context.environment, match.environment),
                _identity_user_failure(match, identity),
                _contains_failure("group", match.group, identity.groups),
                _contains_failure("role", match.role, identity.roles),
                _exact_failure("client_id", identity.client_id, match.client_id),
                _exact_failure("agent_id", identity.agent_id, match.agent_id),
            ]
        )
        return failures

    @staticmethod
    def _metadata_requirements(match: PolicyMatch) -> list[object]:
        return [
            match.action,
            match.risk,
            match.access,
            match.resource_type,
            match.data_classification,
            match.tag,
            match.tags,
        ]

    def _metadata_match_failures(self, match: PolicyMatch, metadata: object | None) -> list[str]:
        metadata_requirements = self._metadata_requirements(match)
        if metadata is None and any(metadata_requirements):
            return ["capability metadata is missing"]
        if metadata is None:
            return []
        failures = _compact_failures(
            [
                _exact_failure("action", metadata.action, match.action),
                _exact_failure("risk", metadata.risk, match.risk),
                _exact_failure("access", metadata.access, match.access),
                _exact_failure("resource_type", metadata.resource_type, match.resource_type),
                _exact_failure(
                    "data_classification",
                    metadata.data_classification,
                    match.data_classification,
                ),
                _contains_failure("tag", match.tag, metadata.tags),
            ]
        )
        if match.tags and not set(match.tags).issubset(set(metadata.tags)):
            failures.append(f"tags {match.tags!r} are not all present")
        return failures

    def _request_validation_errors(
        self, selected: PolicyConfig, context: RequestContext
    ) -> list[str] | None:
        if not self._should_validate_request(selected, context):
            return None
        if selected.input:
            validation = validate_input_policy(context.arguments, selected.input)
            if not validation.passed:
                return validation.errors
        if selected.validators:
            validation = self.validator_engine.validate(selected.validators, context)
            if not validation.passed:
                return validation.errors
        return None

    @staticmethod
    def _should_validate_request(selected: PolicyConfig, context: RequestContext) -> bool:
        return selected.effect not in {"deny", "hide"} and context.method not in LIST_METHODS

    def _selected_decision(
        self,
        selected: PolicyConfig,
        metadata: object | None,
        matching: list[PolicyConfig],
    ) -> PolicyDecision:
        return PolicyDecision(
            decision=selected.effect,
            policy_id=selected.id,
            reason=selected.reason or f"matched policy {selected.id}",
            risk=metadata.risk if metadata else None,
            approval_required=selected.effect == "require_approval",
            dry_run=self.config.runtime.dry_run,
            metadata={"matched_policies": [policy.id for policy in matching]},
        )

    def _default_decision(self, metadata: object | None) -> PolicyDecision:
        return PolicyDecision(
            decision=self.config.runtime.default_decision,
            reason=f"default decision: {self.config.runtime.default_decision}",
            risk=metadata.risk if metadata else None,
            dry_run=self.config.runtime.dry_run,
        )

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
        return min(policies, key=lambda policy: precedence[policy.effect])


def _compact_failures(failures: list[str | None]) -> list[str]:
    return [failure for failure in failures if failure is not None]


def _exact_failure(label: str, actual: object, expected: object | None) -> str | None:
    if expected and expected != actual:
        return f"{label} {actual!r} != {expected!r}"
    return None


def _method_failure(actual: str, expected: str | None) -> str | None:
    if expected and not fnmatch(actual, expected):
        return f"method {actual!r} does not match {expected!r}"
    return None


def _pattern_failure(label: str, actual: str | None, expected: str | None) -> str | None:
    if expected and not _matches_pattern(actual, expected):
        return f"{label} {actual!r} does not match {expected!r}"
    return None


def _patterns_failure(actual: str | None, patterns: list[str]) -> str | None:
    if patterns and not any(_matches_pattern(actual, pattern) for pattern in patterns):
        return f"capability {actual!r} does not match configured capabilities"
    return None


def _matches_pattern(actual: str | None, pattern: str) -> bool:
    return actual is not None and fnmatch(actual, pattern)


def _identity_user_failure(match: PolicyMatch, identity: object) -> str | None:
    if match.user and match.user not in {identity.subject, identity.email}:
        return f"user {identity.subject!r} or email {identity.email!r} did not match"
    return None


def _contains_failure(label: str, expected: object | None, values: list[object]) -> str | None:
    if expected and expected not in values:
        return f"{label} {expected!r} not present"
    return None
