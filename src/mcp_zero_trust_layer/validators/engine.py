from __future__ import annotations

from mcp_zero_trust_layer.config.models import ValidatorConfig
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.validators.basic import (
    validate_email,
    validate_filesystem_path,
    validate_max_field_bytes,
    validate_regex,
    validate_required_forbidden_fields,
    validate_sql_read_only,
    validate_url,
)
from mcp_zero_trust_layer.validators.models import ValidatorResult


class ValidatorEngine:
    def validate(self, validators: list[ValidatorConfig], context: RequestContext) -> ValidatorResult:
        errors: list[str] = []
        for validator in validators:
            result = self._run_validator(validator, context)
            errors.extend(result.errors)
        return ValidatorResult(passed=not errors, errors=errors)

    def _run_validator(
        self, validator: ValidatorConfig, context: RequestContext
    ) -> ValidatorResult:
        name = validator.name
        options = dict(validator.options)
        if context.config_base_dir and "base_dir" not in options:
            options["base_dir"] = context.config_base_dir
        if name == "sql_read_only":
            return validate_sql_read_only(context.arguments, options)
        if name == "filesystem_path":
            return validate_filesystem_path(context.arguments, options)
        if name == "url":
            return validate_url(context.arguments, options)
        if name == "email":
            return validate_email(context.arguments, options)
        if name == "regex":
            return validate_regex(context.arguments, options)
        if name == "required_forbidden_fields":
            return validate_required_forbidden_fields(context.arguments, options)
        if name == "max_field_bytes":
            return validate_max_field_bytes(context.arguments, options)
        return ValidatorResult.fail(f"unknown validator: {name}")
