from __future__ import annotations

from pydantic import field_validator

from iamkit.models.base import BaseIdentityModel
from iamkit.models.enums import GroupType


class NamingSpec(BaseIdentityModel):
    """Naming patterns per group type."""

    security_group: str = "SG-{department}-{function}"
    license_group: str = "License-{sku}"
    mailing_list: str = "ML-{name}"
    m365_group: str = "{name}"

    @field_validator("security_group", "license_group", "mailing_list", "m365_group")
    @classmethod
    def validate_pattern_has_placeholder(cls, v: str) -> str:
        if "{" not in v or "}" not in v:
            raise ValueError(f"Naming pattern must contain at least one placeholder: {v}")
        return v


class DefaultsNewUser(BaseIdentityModel):
    """Defaults applied to every new user."""

    groups: list[str] = []
    usage_location: str = "NL"


class DefaultsSpec(BaseIdentityModel):
    """Default values for new resources."""

    new_user: DefaultsNewUser = DefaultsNewUser()


class RuleMode(BaseIdentityModel):
    """A governance rule with enforcement mode."""

    rule: str
    mode: str = "enforced"
    tags: list[str] | None = None
    pattern: str | None = None
    applies_to: list[str] | None = None


class ConventionSchema(BaseIdentityModel):
    """Root schema for an IAM convention YAML file.

    Adapted from brickkit's YamlConventionSchema.
    """

    version: str = "1.0"
    convention: str
    naming: NamingSpec = NamingSpec()
    defaults: DefaultsSpec = DefaultsSpec()
    rules: list[RuleMode] = []
    tags: dict[str, str] = {}

    def get_naming_pattern(self, group_type: GroupType) -> str:
        mapping = {
            GroupType.SECURITY: self.naming.security_group,
            GroupType.LICENSE: self.naming.license_group,
            GroupType.MAILING_LIST: self.naming.mailing_list,
            GroupType.M365: self.naming.m365_group,
        }
        return mapping[group_type]
