from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import Discriminator, Field, Tag, field_validator

from iamkit.models.base import BaseIdentityModel, MemberReference
from iamkit.models.enums import Environment, GroupType


class SecurityGroup(BaseIdentityModel):
    """An Entra ID security group.

    environment is None for environment-agnostic groups (the common case).
    When set, resolved_name carries the "{name}_{env}" suffix that
    downstream consumers (e.g. Databricks via SCIM sync) look up.
    """

    type: Literal[GroupType.SECURITY] = GroupType.SECURITY
    name: str
    display_name: str | None = None
    description: str | None = None
    members: list[MemberReference] = []
    owners: list[MemberReference] = []
    assignable_to_role: bool = False
    environment: Environment | None = None

    @property
    def resolved_name(self) -> str:
        if self.environment is None:
            return self.name
        return f"{self.name}_{self.environment.value}"

    def add_user(self, name: str) -> SecurityGroup:
        from iamkit.models.enums import PrincipalType

        self.members.append(MemberReference(name=name, principal_type=PrincipalType.USER))
        return self

    def add_service_principal(self, name: str) -> SecurityGroup:
        from iamkit.models.enums import PrincipalType

        self.members.append(
            MemberReference(name=name, principal_type=PrincipalType.SERVICE_PRINCIPAL)
        )
        return self

    def add_nested_group(self, name: str) -> SecurityGroup:
        from iamkit.models.enums import PrincipalType

        self.members.append(MemberReference(name=name, principal_type=PrincipalType.GROUP))
        return self


class LicenseGroup(SecurityGroup):
    """A security group that assigns M365 licenses to its members.

    Adding a user to this group auto-assigns the license via
    Entra group-based licensing.

    Convention: named license-{sku} (e.g., license-m365-business-premium).
    """

    type: Literal[GroupType.LICENSE] = GroupType.LICENSE
    sku: str
    disabled_plans: list[str] = []

    @field_validator("name")
    @classmethod
    def validate_license_naming(cls, v: str) -> str:
        if not v.startswith("license-"):
            raise ValueError(f"License group name must start with 'license-': {v}")
        return v


class MailingList(BaseIdentityModel):
    """A distribution group (mail-enabled, not security-enabled).

    Created via Graph API (mailEnabled=true, securityEnabled=false).
    Not supported by the azuread Terraform provider.
    """

    type: Literal[GroupType.MAILING_LIST] = GroupType.MAILING_LIST
    name: str
    display_name: str | None = None
    email_address: str
    members: list[MemberReference] = []

    @field_validator("email_address")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError(f"Invalid email: {v}")
        return v


class M365Group(BaseIdentityModel):
    """A Microsoft 365 (Unified) group.

    Linked to a SharePoint site + shared mailbox automatically.
    Created via Terraform with types = ["Unified"].
    """

    type: Literal[GroupType.M365] = GroupType.M365
    name: str
    display_name: str | None = None
    description: str | None = None
    members: list[MemberReference] = []
    owners: list[MemberReference] = []
    subscribe_members: bool = False


def _group_discriminator(v: dict | object) -> str:
    if isinstance(v, dict):
        raw = v.get("type", GroupType.SECURITY)
    else:
        raw = getattr(v, "type", GroupType.SECURITY)
    if isinstance(raw, GroupType):
        return raw.value
    return str(raw)


Group = Annotated[
    Union[
        Annotated[SecurityGroup, Tag("security")],
        Annotated[LicenseGroup, Tag("license")],
        Annotated[MailingList, Tag("mailing_list")],
        Annotated[M365Group, Tag("m365")],
    ],
    Discriminator(_group_discriminator),
    Field(description="A group, discriminated by the 'type' field."),
]
