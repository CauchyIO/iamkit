from enum import Enum


class PrincipalType(str, Enum):
    USER = "user"
    GROUP = "group"
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY = "managed_identity"
    EXTERNAL_USER = "external_user"


class Environment(str, Enum):
    """Deployment environment a group gates access to.

    Values are the lowercase suffix parts: a group named "sg-x" in DEV
    resolves to "sg-x_dev" — the same shape brickkit's
    MemberReference.resolved_name produces for SCIM-synced group lookups.
    """

    DEV = "dev"
    ACC = "acc"
    PRD = "prd"


class PrincipalSource(str, Enum):
    ENTRA = "entra"
    EXTERNAL = "external"


class Platform(str, Enum):
    ENTRA = "entra"
    GITHUB = "github"
    LINEAR = "linear"
    SHAREPOINT = "sharepoint"
    M365 = "m365"
    EXCHANGE = "exchange"


class PermissionLevel(str, Enum):
    # GitHub
    PULL = "pull"
    TRIAGE = "triage"
    PUSH = "push"
    MAINTAIN = "maintain"
    ADMIN = "admin"

    # SharePoint
    READ = "read"
    CONTRIBUTE = "contribute"
    FULL_CONTROL = "full_control"

    # Generic
    OWNER = "owner"
    MEMBER = "member"
    WRITE = "write"


class GroupType(str, Enum):
    SECURITY = "security"
    LICENSE = "license"
    MAILING_LIST = "mailing_list"
    M365 = "m365"


class GitHubBasePermission(str, Enum):
    NONE = "none"
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class GitHubOrgRole(str, Enum):
    ADMIN = "admin"
    MEMBER = "member"


class GitHubTeamRole(str, Enum):
    MAINTAINER = "maintainer"
    MEMBER = "member"


class LinearRole(str, Enum):
    ADMIN = "admin"
    MEMBER = "member"
    GUEST = "guest"


class CAState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    REPORT_ONLY = "enabledForReportingButNotEnforced"
