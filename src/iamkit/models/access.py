from __future__ import annotations

from pydantic import ValidationInfo, field_validator

from iamkit.models.base import BaseIdentityModel
from iamkit.models.enums import (
    GitHubBasePermission,
    LinearRole,
    PermissionLevel,
    PrincipalSource,
)


def _reject_duplicates(values: list[str], info: ValidationInfo) -> list[str]:
    duplicates = sorted({value for value in values if values.count(value) > 1})
    if duplicates:
        raise ValueError(f"Duplicate {info.field_name}: {', '.join(duplicates)}")
    return values


class GitHubOrgSettings(BaseIdentityModel):
    """Organization-level GitHub settings.

    `name` is the org's display name — what `github_organization_settings`
    renders. `login` is the org's URL slug, which is what the github provider's
    `owner` and every org-scoped API call need. They are the same string for
    many orgs and different for some, so `login` is optional and only has to be
    set when they diverge.
    """

    name: str
    login: str | None = None
    billing_email: str
    email: str | None = None
    blog: str | None = None
    location: str | None = None
    default_repository_permission: GitHubBasePermission = GitHubBasePermission.NONE
    members_can_create_repositories: bool = True


class GitHubAccessSpec(BaseIdentityModel):
    """GitHub access specification for a group or access policy."""

    team_name: str
    repositories: dict[str, PermissionLevel] = {}
    all_repositories: PermissionLevel | None = None
    exclude_repositories: list[str] = []
    external_members: list[str] = []  # GitHub handles for users outside the DSL


class LinearAccessSpec(BaseIdentityModel):
    """Linear access specification."""

    teams: list[str] = []
    role: LinearRole = LinearRole.MEMBER


class SharePointAccessSpec(BaseIdentityModel):
    """SharePoint site access specification."""

    sites: dict[str, PermissionLevel] = {}


class AzureRoleAssignment(BaseIdentityModel):
    """An Azure RBAC role assignment scoped to a security group."""

    group_name: str
    role: str
    scope: str


class Application(BaseIdentityModel):
    """A relying application whose entry iamkit governs.

    Declares the roles, scopes and workspaces an AccessPolicy may bind a group
    to through AppAccessSpec. Workspaces partition the application (tenant or
    company slugs); a binding names the ones it opens, drawn from this list.

    Not to be confused with AppRegistration, which records what an Entra app
    registration requests. An Application is what groups are granted into:
    registration details here (application_id, audience, redirect_uris) are
    declarative data for exporters, and nothing in iamkit provisions them.
    """

    name: str
    display_name: str
    source: PrincipalSource = PrincipalSource.ENTRA
    application_id: str | None = None
    audience: str | None = None
    redirect_uris: list[str] = []
    available_roles: list[str] = ["admin", "member", "reader"]
    available_scopes: list[str] = []
    workspaces: list[str] = []

    @field_validator("redirect_uris", "available_roles", "available_scopes", "workspaces")
    @classmethod
    def validate_unique(cls, v: list[str], info: ValidationInfo) -> list[str]:
        return _reject_duplicates(v, info)


class AppAccessSpec(BaseIdentityModel):
    """Binds the owning AccessPolicy's group to a role in an Application.

    `application` names a key of IAMConfig.applications. IAMConfig checks at
    model time that `role` is one of the application's available_roles, that
    `scopes` and `workspaces` draw only from its available_scopes and
    workspaces, and that a binding into a workspace-partitioned application
    names at least one workspace: an empty list never means "all of them".
    """

    application: str
    role: str
    workspaces: list[str] = []
    scopes: list[str] = []

    @field_validator("workspaces", "scopes")
    @classmethod
    def validate_unique(cls, v: list[str], info: ValidationInfo) -> list[str]:
        return _reject_duplicates(v, info)


class AccessPolicy(BaseIdentityModel):
    """Standalone access policy template defining what a group gets across platforms.

    Maps a group to its permissions on each platform. Groups reference
    an access policy by name; the IAMConfig container validates that
    all references resolve.
    """

    name: str
    group: str | None = None
    description: str | None = None
    entra_roles: list[str] = []
    github: GitHubAccessSpec | None = None
    linear: LinearAccessSpec | None = None
    sharepoint: SharePointAccessSpec | None = None
    applications: list[AppAccessSpec] = []
    conditional_access_groups: list[str] = []
