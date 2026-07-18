from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from iamkit.convention.rules import RulesRegistry, RuleValidationResult, create_default_registry
from iamkit.convention.schema import ConventionSchema


def _resource_kind(resource: Any) -> str:
    """Snake_case class name, e.g. SecurityGroup -> 'security_group'."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", type(resource).__name__).lower()


class IAMConvention:
    """Runtime wrapper for a loaded IAM convention.

    Provides name generation, validation, and default application.
    """

    def __init__(
        self,
        schema: ConventionSchema,
        registry: RulesRegistry | None = None,
    ) -> None:
        self.schema = schema
        self.registry = registry or create_default_registry()

    def validate(self, resource: Any) -> list[RuleValidationResult]:
        results: list[RuleValidationResult] = []
        for rule_spec in self.schema.rules:
            rule_def = self.registry.get(rule_spec.rule)  # KeyError on unknown rule
            if rule_spec.applies_to is not None:
                if _resource_kind(resource) not in rule_spec.applies_to:
                    continue
            validator_kwargs: dict[str, Any] = {}
            if rule_spec.pattern:
                validator_kwargs["pattern"] = rule_spec.pattern
            if rule_spec.tags:
                validator_kwargs["tags"] = rule_spec.tags
            validator = rule_def.validator_factory(**validator_kwargs)
            result = validator(resource)
            result.mode = rule_spec.mode
            results.append(result)
        return results

    def get_validation_errors(
        self,
        resource: Any,
        include_advisory: bool = False,
    ) -> list[str]:
        results = self.validate(resource)
        errors: list[str] = []
        for r in results:
            if r.passed:
                continue
            if r.mode == "enforced" or include_advisory:
                errors.append(r.message or f"Rule '{r.rule_name}' failed")
        return errors


def load_convention(
    path: str | Path,
    registry: RulesRegistry | None = None,
) -> IAMConvention:
    path = Path(path)
    with open(path) as f:
        data = yaml.safe_load(f)
    schema = ConventionSchema(**data)
    return IAMConvention(schema=schema, registry=registry)
