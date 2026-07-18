from __future__ import annotations

from pydantic import field_validator

from iamkit.models.base import BaseIdentityModel, IdentityMapping
from iamkit.models.enums import (
    GitHubOrgRole,
    LinearRole,
    PrincipalSource,
)


class GitHubUserConfig(BaseIdentityModel):
    """GitHub-specific configuration for a user."""

    handle: str
    org_role: GitHubOrgRole = GitHubOrgRole.MEMBER


class LinearUserConfig(BaseIdentityModel):
    """Linear-specific configuration for a user."""

    email: str
    role: LinearRole = LinearRole.MEMBER


class PlatformConfig(BaseIdentityModel):
    """Per-platform overrides for a user."""

    github: GitHubUserConfig | None = None
    linear: LinearUserConfig | None = None

    def to_identity_mapping(self, entra_upn: str) -> IdentityMapping:
        return IdentityMapping(
            entra_upn=entra_upn,
            github_handle=self.github.handle if self.github else None,
            linear_email=self.linear.email if self.linear else None,
        )


class User(BaseIdentityModel):
    """An Entra ID user account.

    The canonical identity is the Entra UPN (email). Platform-specific
    identities (GitHub handle, Linear email) live in platform_config.
    """

    name: str
    display_name: str
    email: str
    department: str | None = None
    job_title: str | None = None
    manager: str | None = None
    usage_location: str | None = None
    account_enabled: bool = True
    managed: bool = True
    platform_config: PlatformConfig = PlatformConfig()
    group_memberships: list[str] = []

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError(f"Invalid email: {v}")
        return v

    @property
    def identity_mapping(self) -> IdentityMapping:
        return self.platform_config.to_identity_mapping(self.email)


class ServicePrincipal(BaseIdentityModel):
    """An Entra ID service principal / app registration identity."""

    name: str
    display_name: str | None = None
    application_id: str | None = None
    source: PrincipalSource = PrincipalSource.ENTRA
    entitlements: list[str] = []
    group_memberships: list[str] = []


class ManagedIdentity(BaseIdentityModel):
    """An Azure managed identity, created via azurerm and referenced in azuread."""

    name: str
    resource_group: str
    location: str


class ExternalUser(BaseIdentityModel):
    """A B2B guest user invited via azuread_invitation."""

    email: str
    display_name: str
    invitation_redirect_url: str = "https://myapps.microsoft.com"
    send_invitation: bool = True
    group_memberships: list[str] = []

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError(f"Invalid email: {v}")
        return v


class SharedMailbox(BaseIdentityModel):
    """A shared mailbox — a single address that delegates can send-as/access.

    Created via Graph API (not Exchange PowerShell).
    """

    name: str
    email_address: str
    display_name: str
    delegates: list[str] = []

    @field_validator("email_address")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError(f"Invalid email: {v}")
        return v
