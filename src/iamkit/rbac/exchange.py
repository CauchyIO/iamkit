"""Exchange RBAC posture as desired state.

The alias plane's decision record rules that its Exchange-side objects — the
service principal pointer, the management scope, the stripped role, the role
group — are created by an interactive admin session, never CI. This module
makes that session reconcile a declared posture instead of pasting a runbook:
`plan` reads and diffs, `apply` converges and re-reads. The reconciler never
deletes a scope, role, group, or service principal, and the only removal it
can express is a role *entry* on the declared role.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, field_validator

from iamkit.clients.exchange import ExchangeOnlineError, _quote

__all__ = [
    "CurrentPosture",
    "ExchangeOnlineError",
    "ExchangeRbacPosture",
    "read_script",
]

# Names travel into -Name/-Identity arguments; a strict shape is the injection
# guard, same stance as the client's address regex.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _-]*$")
_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_CMDLET_RE = re.compile(r"^[A-Za-z]+-[A-Za-z]+$")
_PARAM_RE = re.compile(r"^[A-Za-z]+$")
_UPN_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


class ExchangeRbacPosture(BaseModel):
    """The declared shape of the Exchange side of the alias plane.

    `role_entries` maps each surviving cmdlet to the exact parameter list it
    is pinned to; anything on the role but absent here is drift to remove.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    mailbox_upn: str
    scope_name: str
    role_name: str
    role_parent: str = "Mail Recipients"
    role_entries: dict[str, tuple[str, ...]] = {
        "Get-Mailbox": ("Identity",),
        "Set-Mailbox": ("Identity", "EmailAddresses"),
    }
    group_name: str
    sp_display_name: str
    sp_app_id: str
    sp_object_id: str

    @field_validator("mailbox_upn")
    @classmethod
    def _upn(cls, v: str) -> str:
        if not _UPN_RE.fullmatch(v):
            raise ValueError(f"Invalid mailbox UPN: {v!r}")
        return v

    @field_validator(
        "scope_name", "role_name", "role_parent", "group_name", "sp_display_name"
    )
    @classmethod
    def _name(cls, v: str) -> str:
        if not _NAME_RE.fullmatch(v):
            raise ValueError(f"Invalid Exchange object name: {v!r}")
        return v

    @field_validator("sp_app_id", "sp_object_id")
    @classmethod
    def _guid(cls, v: str) -> str:
        if not _GUID_RE.fullmatch(v.lower()):
            raise ValueError(f"Invalid GUID: {v!r}")
        return v.lower()

    @field_validator("role_entries")
    @classmethod
    def _entries(cls, v: dict[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
        if not v:
            raise ValueError("role_entries must declare at least one cmdlet")
        for cmdlet, params in v.items():
            if not _CMDLET_RE.fullmatch(cmdlet):
                raise ValueError(f"Invalid cmdlet name: {cmdlet!r}")
            if not params:
                raise ValueError(f"Cmdlet {cmdlet} pins no parameters")
            for p in params:
                if not _PARAM_RE.fullmatch(p):
                    raise ValueError(f"Invalid parameter name: {p!r} on {cmdlet}")
        return v

    @property
    def restriction_filter(self) -> str:
        return f"UserPrincipalName -eq '{self.mailbox_upn}'"


_READ_KEYS = (
    "org_customization_enabled",
    "service_principal",
    "scope",
    "role",
    "role_entries",
    "group",
    "group_members",
    "authorization",
)


def read_script(posture: ExchangeRbacPosture, admin_upn: str, json_path: str) -> str:
    """A read-only interactive session that dumps the current posture as JSON.

    Probes use -ErrorAction SilentlyContinue so an absent object is $null
    rather than a terminating error; everything else runs under Stop. The
    document goes to `json_path` — stdout stays free for the interactive
    sign-in.
    """
    if not _UPN_RE.fullmatch(admin_upn):
        raise ValueError(f"Invalid admin UPN: {admin_upn!r}")
    q = _quote
    role_star = q(f"{posture.role_name}\\*")
    return (
        "$ErrorActionPreference = 'Stop'\n"
        "$WarningPreference = 'SilentlyContinue'\n"
        f"Connect-ExchangeOnline -UserPrincipalName {q(admin_upn)} -ShowBanner:$false\n"
        "try {\n"
        "    $org = Get-OrganizationConfig\n"
        f"    $sp = Get-ServicePrincipal -Identity {q(posture.sp_display_name)}"
        " -ErrorAction SilentlyContinue\n"
        f"    $scope = Get-ManagementScope -Identity {q(posture.scope_name)}"
        " -ErrorAction SilentlyContinue\n"
        f"    $role = Get-ManagementRole {q(posture.role_name)}"
        " -ErrorAction SilentlyContinue\n"
        "    $entries = @()\n"
        "    if ($role) {\n"
        f"        $entries = @(Get-ManagementRoleEntry {role_star} | ForEach-Object"
        " { @{ name = $_.Name; parameters = @($_.Parameters) } })\n"
        "    }\n"
        f"    $group = Get-RoleGroup {q(posture.group_name)}"
        " -ErrorAction SilentlyContinue\n"
        "    $members = @()\n"
        "    if ($group) {\n"
        f"        $members = @(Get-RoleGroupMember {q(posture.group_name)}"
        " | ForEach-Object { $_.Name })\n"
        "    }\n"
        "    $auth = @()\n"
        "    if ($sp) {\n"
        f"        $auth = @(Test-ServicePrincipalAuthorization -Identity"
        f" {q(posture.sp_display_name)} | ForEach-Object"
        " { @{ role = [string]$_.RoleName; granted = [bool]$_.GrantedPermissions } })\n"
        "    }\n"
        "    @{\n"
        "        org_customization_enabled = -not [bool]$org.IsDehydrated\n"
        "        service_principal = if ($sp) { @{ app_id = [string]$sp.AppId;"
        " object_id = [string]$sp.ObjectId;"
        " display_name = [string]$sp.DisplayName } } else { $null }\n"
        "        scope = if ($scope) { @{ name = [string]$scope.Name;"
        " filter = [string]$scope.RecipientFilter } } else { $null }\n"
        "        role = if ($role) { @{ name = [string]$role.Name } } else { $null }\n"
        "        role_entries = $entries\n"
        "        group = if ($group) { @{ name = [string]$group.Name;"
        " write_scope = [string]$group.CustomRecipientWriteScope } } else { $null }\n"
        "        group_members = $members\n"
        "        authorization = $auth\n"
        f"    }} | ConvertTo-Json -Depth 5 | Set-Content -Path {q(json_path)}"
        " -Encoding utf8\n"
        "} finally {\n"
        "    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue"
        " | Out-Null\n"
        "}\n"
    )


def _as_list(value: object) -> list:
    """Lift ConvertTo-Json's single-element collapse back to a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@dataclass(frozen=True)
class CurrentPosture:
    """What the tenant answered, shaped for the diff and nothing more."""

    org_customization_enabled: bool
    service_principal: dict | None
    scope: dict | None
    role: dict | None
    role_entries: tuple[dict, ...]
    group: dict | None
    group_members: tuple[str, ...]
    authorization: tuple[dict, ...]

    @classmethod
    def from_json_text(cls, text: str) -> CurrentPosture:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ExchangeOnlineError(
                f"RBAC read output is not JSON: {text!r}"
            ) from exc
        if not isinstance(doc, dict):
            raise ExchangeOnlineError(f"RBAC read output is not an object: {text!r}")
        missing = [k for k in _READ_KEYS if k not in doc]
        if missing:
            raise ExchangeOnlineError(
                f"RBAC read output is missing keys {missing}: {text!r}"
            )
        entries = tuple(
            {"name": e["name"], "parameters": tuple(_as_list(e["parameters"]))}
            for e in _as_list(doc["role_entries"])
        )
        return cls(
            org_customization_enabled=bool(doc["org_customization_enabled"]),
            service_principal=doc["service_principal"],
            scope=doc["scope"],
            role=doc["role"],
            role_entries=entries,
            group=doc["group"],
            group_members=tuple(_as_list(doc["group_members"])),
            authorization=tuple(_as_list(doc["authorization"])),
        )
