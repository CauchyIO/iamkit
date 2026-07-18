from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class RuleValidationResult:
    passed: bool
    message: str | None = None
    rule_name: str = ""
    mode: str = "enforced"


@dataclass
class RuleDefinition:
    name: str
    description: str
    validator_factory: Callable[..., Callable[[Any], RuleValidationResult]]


class RulesRegistry:
    """Central registry for governance rule implementations."""

    def __init__(self) -> None:
        self._rules: dict[str, RuleDefinition] = {}

    def register(self, rule: RuleDefinition) -> None:
        self._rules[rule.name] = rule

    def get(self, name: str) -> RuleDefinition:
        if name not in self._rules:
            raise KeyError(f"Unknown rule: {name}")
        return self._rules[name]

    def list_rules(self) -> list[str]:
        return list(self._rules.keys())

    def has_rule(self, name: str) -> bool:
        return name in self._rules


def _require_usage_location_factory(**kwargs: Any) -> Callable[[Any], RuleValidationResult]:
    def validate(user: Any) -> RuleValidationResult:
        if hasattr(user, "usage_location") and not user.usage_location:
            return RuleValidationResult(
                passed=False,
                message=f"User '{user.name}' is missing usage_location",
                rule_name="require_usage_location",
            )
        return RuleValidationResult(passed=True, rule_name="require_usage_location")

    return validate


def _naming_pattern_factory(pattern: str = "", **kwargs: Any) -> Callable[[Any], RuleValidationResult]:
    if not pattern:
        raise ValueError("naming_pattern rule requires a non-empty 'pattern'")

    def validate(resource: Any) -> RuleValidationResult:
        name = getattr(resource, "name", "")
        if not re.fullmatch(pattern, name):
            return RuleValidationResult(
                passed=False,
                message=f"Name '{name}' does not match pattern '{pattern}'",
                rule_name="naming_pattern",
            )
        return RuleValidationResult(passed=True, rule_name="naming_pattern")

    return validate


def _group_must_have_owner_factory(**kwargs: Any) -> Callable[[Any], RuleValidationResult]:
    def validate(group: Any) -> RuleValidationResult:
        if not hasattr(group, "owners"):
            return RuleValidationResult(passed=True, rule_name="group_must_have_owner")
        owners = group.owners
        if not owners:
            return RuleValidationResult(
                passed=False,
                message=f"Group '{group.name}' has no owners",
                rule_name="group_must_have_owner",
            )
        return RuleValidationResult(passed=True, rule_name="group_must_have_owner")

    return validate


def _environment_suffix_factory(**kwargs: Any) -> Callable[[Any], RuleValidationResult]:
    def validate(resource: Any) -> RuleValidationResult:
        name = getattr(resource, "name", "")
        environment = getattr(resource, "environment", None)
        if environment is None and re.search(r"_(dev|acc|prd)$", name):
            return RuleValidationResult(
                passed=False,
                message=(
                    f"Group '{name}' hardcodes an environment suffix; "
                    "set the environment field instead and drop the suffix from the name"
                ),
                rule_name="environment_suffix",
            )
        return RuleValidationResult(passed=True, rule_name="environment_suffix")

    return validate


def create_default_registry() -> RulesRegistry:
    registry = RulesRegistry()
    registry.register(
        RuleDefinition(
            name="require_usage_location",
            description="Users must have a usage_location set for M365 licensing",
            validator_factory=_require_usage_location_factory,
        )
    )
    registry.register(
        RuleDefinition(
            name="naming_pattern",
            description="Resource names must match a regex pattern",
            validator_factory=_naming_pattern_factory,
        )
    )
    registry.register(
        RuleDefinition(
            name="group_must_have_owner",
            description="Groups must have at least one owner defined",
            validator_factory=_group_must_have_owner_factory,
        )
    )
    registry.register(
        RuleDefinition(
            name="environment_suffix",
            description="Environment-suffixed group names must use the environment field",
            validator_factory=_environment_suffix_factory,
        )
    )
    return registry
