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
    "AddRoleEntry",
    "AddSoleMember",
    "CreateGroup",
    "CreateRole",
    "CreateScope",
    "CreateServicePrincipalPointer",
    "CurrentPosture",
    "EnableOrgCustomization",
    "ExchangeOnlineError",
    "ExchangeRbacPosture",
    "PinRoleEntryParameters",
    "RbacPlan",
    "RemoveRoleEntry",
    "SetGroupWriteScope",
    "StripUndeclaredEntries",
    "diff",
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


# --- Convergence actions -----------------------------------------------------
# One frozen dataclass per mutation the reconciler can express. The write
# script renders from these and nothing else, so this set IS the whitelist.


@dataclass(frozen=True)
class EnableOrgCustomization:
    pass


@dataclass(frozen=True)
class CreateServicePrincipalPointer:
    app_id: str
    object_id: str
    display_name: str


@dataclass(frozen=True)
class CreateScope:
    name: str
    filter: str


@dataclass(frozen=True)
class CreateRole:
    name: str
    parent: str


@dataclass(frozen=True)
class StripUndeclaredEntries:
    role: str
    keep: tuple[str, ...]


@dataclass(frozen=True)
class AddRoleEntry:
    role: str
    cmdlet: str
    parameters: tuple[str, ...]


@dataclass(frozen=True)
class RemoveRoleEntry:
    role: str
    cmdlet: str


@dataclass(frozen=True)
class PinRoleEntryParameters:
    role: str
    cmdlet: str
    parameters: tuple[str, ...]


@dataclass(frozen=True)
class CreateGroup:
    name: str
    role: str
    write_scope: str


@dataclass(frozen=True)
class SetGroupWriteScope:
    group: str
    write_scope: str


@dataclass(frozen=True)
class AddSoleMember:
    group: str
    member: str


@dataclass(frozen=True)
class RbacPlan:
    actions: tuple
    blockers: tuple[str, ...]

    @property
    def empty(self) -> bool:
        return not self.actions and not self.blockers


def _normalise_filter(value: str) -> str:
    # Exchange canonicalises stored filters (wrapping parens, casing); compare
    # the intent, not the tenant's rendering of it.
    return value.strip().strip("()").strip().casefold()


def diff(desired: ExchangeRbacPosture, current: CurrentPosture) -> RbacPlan:
    """Typed convergence actions in a fixed order.

    Two states are deliberately blockers rather than actions: a scope whose
    filter points somewhere else (rewriting a scope silently retargets every
    grant that hangs off it) and a foreign group member (removing a principal
    is not this reconciler's to do).
    """
    actions: list = []
    blockers: list[str] = []

    if not current.org_customization_enabled:
        actions.append(EnableOrgCustomization())

    if current.service_principal is None:
        actions.append(
            CreateServicePrincipalPointer(
                app_id=desired.sp_app_id,
                object_id=desired.sp_object_id,
                display_name=desired.sp_display_name,
            )
        )

    if current.scope is None:
        actions.append(
            CreateScope(name=desired.scope_name, filter=desired.restriction_filter)
        )
    elif _normalise_filter(current.scope["filter"]) != _normalise_filter(
        desired.restriction_filter
    ):
        blockers.append(
            f"scope {desired.scope_name} has filter {current.scope['filter']!r},"
            f" expected {desired.restriction_filter!r}; fix by hand — the"
            " reconciler does not rewrite scopes"
        )

    if current.role is None:
        actions.append(CreateRole(name=desired.role_name, parent=desired.role_parent))
        actions.append(
            StripUndeclaredEntries(
                role=desired.role_name, keep=tuple(desired.role_entries)
            )
        )
        for cmdlet, params in desired.role_entries.items():
            actions.append(
                PinRoleEntryParameters(
                    role=desired.role_name, cmdlet=cmdlet, parameters=params
                )
            )
    else:
        have = {e["name"]: tuple(e["parameters"]) for e in current.role_entries}
        for cmdlet in sorted(set(have) - set(desired.role_entries)):
            actions.append(RemoveRoleEntry(role=desired.role_name, cmdlet=cmdlet))
        for cmdlet in sorted(set(desired.role_entries) - set(have)):
            actions.append(
                AddRoleEntry(
                    role=desired.role_name,
                    cmdlet=cmdlet,
                    parameters=desired.role_entries[cmdlet],
                )
            )
        for cmdlet in sorted(set(desired.role_entries) & set(have)):
            if set(have[cmdlet]) != set(desired.role_entries[cmdlet]):
                actions.append(
                    PinRoleEntryParameters(
                        role=desired.role_name,
                        cmdlet=cmdlet,
                        parameters=desired.role_entries[cmdlet],
                    )
                )

    if current.group is None:
        actions.append(
            CreateGroup(
                name=desired.group_name,
                role=desired.role_name,
                write_scope=desired.scope_name,
            )
        )
        actions.append(
            AddSoleMember(group=desired.group_name, member=desired.sp_display_name)
        )
    else:
        if current.group["write_scope"] != desired.scope_name:
            actions.append(
                SetGroupWriteScope(
                    group=desired.group_name, write_scope=desired.scope_name
                )
            )
        extras = [m for m in current.group_members if m != desired.sp_display_name]
        if extras:
            blockers.append(
                f"role group {desired.group_name} has members beyond the automation"
                f" principal: {', '.join(extras)}; remove them by hand — membership"
                " removal is not this reconciler's to do"
            )
        if desired.sp_display_name not in current.group_members:
            actions.append(
                AddSoleMember(group=desired.group_name, member=desired.sp_display_name)
            )

    return RbacPlan(actions=tuple(actions), blockers=tuple(blockers))
