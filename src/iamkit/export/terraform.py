from __future__ import annotations

import json
import os
from typing import Any

from iamkit.models.config import IAMConfig
from iamkit.models.enums import PermissionLevel
from iamkit.models.groups import LicenseGroup, M365Group, SecurityGroup

# GitHub API uses "push" where our DSL says "write".
_GITHUB_PERMISSION_MAP: dict[str, str] = {
    PermissionLevel.WRITE.value: "push",
}

# ---------------------------------------------------------------------------
# Variable schemas — the single source of truth for Terraform variable blocks.
# The exporter uses these to generate both variables.tf and .auto.tfvars.json.
# ---------------------------------------------------------------------------

ENTRA_VARIABLE_SCHEMAS: list[dict[str, str]] = [
    {
        "name": "iam_users_existing",
        "description": "Board/unmanaged users — data source lookup only",
        "type": (
            "list(object({\n"
            "    name         = string\n"
            "    display_name = string\n"
            "    email        = string\n"
            "  }))"
        ),
    },
    {
        "name": "iam_users_managed",
        "description": "Terraform-managed Entra ID users",
        "type": (
            "list(object({\n"
            "    name            = string\n"
            "    display_name    = string\n"
            "    email           = string\n"
            "    account_enabled = bool\n"
            "    usage_location  = optional(string, null)\n"
            "    department      = optional(string, null)\n"
            "    job_title       = optional(string, null)\n"
            "  }))"
        ),
    },
    {
        "name": "iam_security_groups",
        "description": "Security groups with members and owners",
        "type": (
            "list(object({\n"
            "    name               = string\n"
            "    display_name       = optional(string, null)\n"
            "    description        = optional(string, null)\n"
            "    assignable_to_role = bool\n"
            "    members            = list(string)\n"
            "    owners             = list(string)\n"
            "  }))"
        ),
    },
    {
        "name": "iam_license_groups",
        "description": "License groups for group-based licensing",
        "type": (
            "list(object({\n"
            "    name           = string\n"
            "    display_name   = optional(string, null)\n"
            "    sku            = string\n"
            "    sku_id         = string\n"
            "    disabled_plans = list(string)\n"
            "    members        = list(string)\n"
            "  }))"
        ),
    },
    {
        "name": "iam_m365_groups",
        "description": "Microsoft 365 Unified groups",
        "type": (
            "list(object({\n"
            "    name         = string\n"
            "    display_name = optional(string, null)\n"
            "    description  = optional(string, null)\n"
            "    members      = list(string)\n"
            "    owners       = list(string)\n"
            "  }))"
        ),
    },
    {
        "name": "iam_role_assignments",
        "description": "Azure RBAC role assignments for security groups",
        "type": (
            "list(object({\n"
            "    group_name = string\n"
            "    role       = string\n"
            "    scope      = string\n"
            "  }))"
        ),
        "default": "[]",
    },
    {
        "name": "iam_external_users",
        "description": "B2B guest users invited via azuread_invitation",
        "type": (
            "list(object({\n"
            "    name                    = string\n"
            "    email                   = string\n"
            "    display_name            = string\n"
            "    invitation_redirect_url = string\n"
            "    send_invitation         = bool\n"
            "  }))"
        ),
        "default": "[]",
    },
    {
        "name": "iam_conditional_access_policies",
        "description": "CA policies — consumed by tenant root modules, not the entra module",
        "type": "list(any)",
        "default": "[]",
    },
    {
        "name": "iam_app_registrations",
        "description": "App registrations — consumed by tenant root modules, not the entra module",
        "type": (
            "list(object({\n"
            "    name            = string\n"
            "    application_id  = string\n"
            "    display_name    = optional(string, null)\n"
            "    api_permissions = list(string)\n"
            "    redirect_uris   = list(string)\n"
            "  }))"
        ),
        "default": "[]",
    },
]

GITHUB_VARIABLE_SCHEMAS: list[dict[str, str]] = [
    {
        "name": "github_org",
        "description": "GitHub organization name",
        "type": "string",
    },
    {
        "name": "github_members",
        "description": "Org members with their roles",
        "type": (
            "list(object({\n"
            "    username = string\n"
            "    role     = string\n"
            "  }))"
        ),
    },
    {
        "name": "github_teams",
        "description": "Teams with repo permissions",
        "type": (
            "list(object({\n"
            "    name                 = string\n"
            "    members              = list(string)\n"
            "    repositories         = map(string)\n"
            "    all_repositories     = optional(string, null)\n"
            "    exclude_repositories = list(string)\n"
            "  }))"
        ),
    },
    {
        "name": "github_org_settings",
        "description": "Organization-level GitHub settings",
        "type": (
            "object({\n"
            "    name                             = string\n"
            "    billing_email                    = string\n"
            "    email                            = string\n"
            "    blog                             = string\n"
            "    location                         = string\n"
            "    default_repository_permission    = string\n"
            "    members_can_create_repositories  = bool\n"
            "  })"
        ),
    },
]


def _render_variables_tf(schemas: list[dict[str, str]]) -> str:
    """Render a list of variable schemas to HCL variable blocks."""
    blocks: list[str] = [
        "# Auto-generated by TerraformExporter — do not edit by hand.\n"
    ]
    for var in schemas:
        lines = [f'variable "{var["name"]}" {{']
        lines.append(f'  description = "{var["description"]}"')
        # Multi-line types get a newline after '='
        if "\n" in var["type"]:
            lines.append(f'  type = {var["type"]}')
        else:
            lines.append(f"  type        = {var['type']}")
        if "default" in var:
            lines.append(f"  default     = {var['default']}")
        lines.append("}\n")
        blocks.append("\n".join(lines))
    return "\n".join(blocks)


class TerraformExporter:
    """Exports IAMConfig to .auto.tfvars.json and variables.tf for Terraform.

    Covers: users, groups, role assignments, app registrations,
    CA policies (Entra/azuread provider), GitHub org/teams (github provider).
    """

    def __init__(self, config: IAMConfig, github_org_default: str | None = None) -> None:
        self.config = config
        self.github_org_default = github_org_default

    def _github_variable_schemas(self) -> list[dict[str, str]]:
        schemas = [dict(s) for s in GITHUB_VARIABLE_SCHEMAS]
        if self.github_org_default is not None:
            for s in schemas:
                if s["name"] == "github_org":
                    s["default"] = f'"{self.github_org_default}"'
        return schemas

    def export_entra_tfvars(self) -> dict[str, Any]:
        sku_by_part_number = {
            sku.sku_part_number: sku for sku in self.config.license_skus.values()
        }
        return {
            "iam_users_existing": [
                {
                    "name": key,
                    "display_name": user.display_name,
                    "email": user.email,
                }
                for key, user in self.config.users.items()
                if not user.managed
            ],
            "iam_users_managed": [
                {
                    "name": key,
                    "display_name": user.display_name,
                    "email": user.email,
                    "account_enabled": user.account_enabled,
                    "usage_location": user.usage_location,
                    "department": user.department,
                    "job_title": user.job_title,
                }
                for key, user in self.config.users.items()
                if user.managed
            ],
            "iam_external_users": [
                {
                    "name": key,
                    "email": eu.email,
                    "display_name": eu.display_name,
                    "invitation_redirect_url": eu.invitation_redirect_url,
                    "send_invitation": eu.send_invitation,
                }
                for key, eu in self.config.external_users.items()
            ],
            "iam_security_groups": [
                {
                    "name": group.resolved_name,
                    "display_name": group.display_name,
                    "description": group.description,
                    "assignable_to_role": group.assignable_to_role,
                    "members": [m.name for m in group.members],
                    "owners": [o.name for o in group.owners],
                }
                for group in self.config.groups.values()
                if isinstance(group, SecurityGroup)
                and not isinstance(group, LicenseGroup)
            ],
            "iam_license_groups": [
                {
                    "name": group.resolved_name,
                    "display_name": group.display_name,
                    "sku": group.sku,
                    "sku_id": sku_by_part_number[group.sku].sku_id,
                    "disabled_plans": group.disabled_plans,
                    "members": [m.name for m in group.members],
                }
                for group in self.config.groups.values()
                if isinstance(group, LicenseGroup)
            ],
            "iam_m365_groups": [
                {
                    "name": group.name,
                    "display_name": group.display_name,
                    "description": group.description,
                    "members": [m.name for m in group.members],
                    "owners": [o.name for o in group.owners],
                }
                for group in self.config.groups.values()
                if isinstance(group, M365Group)
            ],
            "iam_role_assignments": [
                {
                    "group_name": ra.group_name,
                    "role": ra.role,
                    "scope": ra.scope,
                }
                for ra in self.config.azure_role_assignments
            ],
            "iam_conditional_access_policies": [
                policy.model_dump(mode="json", exclude_none=True)
                for policy in self.config.conditional_access_policies.values()
            ],
            "iam_app_registrations": [
                {
                    "name": app.name,
                    "application_id": app.application_id,
                    "display_name": app.display_name,
                    "api_permissions": app.api_permissions,
                    "redirect_uris": app.redirect_uris,
                }
                for app in self.config.app_registrations.values()
            ],
        }

    def export_github_tfvars(self) -> dict[str, Any]:
        members: list[dict[str, Any]] = []
        for user in self.config.users.values():
            gh = user.platform_config.github
            if gh is None or not user.account_enabled:
                continue
            members.append(
                {
                    "username": gh.handle,
                    "role": gh.org_role.value,
                }
            )

        teams: list[dict[str, Any]] = []
        for policy in self.config.access_policies.values():
            if policy.github is None:
                continue
            gh = policy.github

            # Derive team members: group members (with GitHub config) + external handles
            team_members: list[str] = []
            if policy.group and policy.group in self.config.groups:
                group = self.config.groups[policy.group]
                for member in group.members:
                    user = self.config.users.get(member.name)
                    if user and user.account_enabled:
                        gh_cfg = user.platform_config.github
                        if gh_cfg:
                            team_members.append(gh_cfg.handle)
            team_members.extend(gh.external_members)
            team_members = list(dict.fromkeys(team_members))

            team: dict[str, Any] = {
                "name": gh.team_name,
                "members": team_members,
                "repositories": {
                    repo: _GITHUB_PERMISSION_MAP.get(level.value, level.value)
                    for repo, level in gh.repositories.items()
                },
                "exclude_repositories": gh.exclude_repositories,
            }
            if gh.all_repositories:
                team["all_repositories"] = _GITHUB_PERMISSION_MAP.get(
                    gh.all_repositories.value, gh.all_repositories.value
                )
            teams.append(team)

        result: dict[str, Any] = {
            "github_members": members,
            "github_teams": teams,
        }
        org_name = (
            self.config.github_org_settings.name
            if self.config.github_org_settings is not None
            else self.github_org_default
        )
        if org_name is not None:
            result["github_org"] = org_name
        if self.config.github_org_settings is not None:
            org = self.config.github_org_settings
            result["github_org_settings"] = {
                "name": org.name,
                "billing_email": org.billing_email,
                "email": org.email or "",
                "blog": org.blog or "",
                "location": org.location or "",
                "default_repository_permission": org.default_repository_permission.value,
                "members_can_create_repositories": org.members_can_create_repositories,
            }
        return result

    def to_json(self, data: dict[str, Any]) -> str:
        return json.dumps(data, indent=2, default=str)

    def write_entra_tfvars(self, path: str) -> None:
        data = self.export_entra_tfvars()
        with open(path, "w") as f:
            f.write(self.to_json(data))

        variables_path = os.path.join(os.path.dirname(path), "entra-variables.tf")
        with open(variables_path, "w") as f:
            f.write(_render_variables_tf(ENTRA_VARIABLE_SCHEMAS))

    def write_github_tfvars(self, path: str) -> None:
        data = self.export_github_tfvars()
        with open(path, "w") as f:
            f.write(self.to_json(data))

        variables_path = os.path.join(os.path.dirname(path), "github-variables.tf")
        with open(variables_path, "w") as f:
            f.write(_render_variables_tf(self._github_variable_schemas()))
