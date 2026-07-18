from __future__ import annotations

from iamkit.models.base import BaseIdentityModel
from iamkit.models.enums import GitHubBasePermission, LinearRole, PermissionLevel


class GitHubOrgSettings(BaseIdentityModel):
    """Organization-level GitHub settings."""

    name: str
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
    conditional_access_groups: list[str] = []
