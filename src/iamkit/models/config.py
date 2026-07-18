from __future__ import annotations

from pydantic import model_validator

from iamkit.models.base import BaseIdentityModel
from iamkit.models.access import AccessPolicy, AzureRoleAssignment, GitHubOrgSettings
from iamkit.models.conditional_access import ConditionalAccessPolicy
from iamkit.models.enums import PrincipalType
from iamkit.models.groups import Group
from iamkit.models.license import LicenseSKU
from iamkit.models.principals import (
    ExternalUser,
    ManagedIdentity,
    ServicePrincipal,
    SharedMailbox,
    User,
)


class AppRegistration(BaseIdentityModel):
    """An Entra ID app registration."""

    name: str
    application_id: str
    display_name: str | None = None
    api_permissions: list[str] = []
    redirect_uris: list[str] = []


class IAMConfig(BaseIdentityModel):
    """Top-level container for the entire IAM desired state.

    All cross-object validation happens here via model validators.
    """

    users: dict[str, User] = {}
    service_principals: dict[str, ServicePrincipal] = {}
    managed_identities: dict[str, ManagedIdentity] = {}
    external_users: dict[str, ExternalUser] = {}
    shared_mailboxes: dict[str, SharedMailbox] = {}
    groups: dict[str, Group] = {}
    access_policies: dict[str, AccessPolicy] = {}
    github_org_settings: GitHubOrgSettings | None = None
    conditional_access_policies: dict[str, ConditionalAccessPolicy] = {}
    app_registrations: dict[str, AppRegistration] = {}
    license_skus: dict[str, LicenseSKU] = {}
    azure_role_assignments: list[AzureRoleAssignment] = []

    @model_validator(mode="after")
    def validate_all_references(self) -> IAMConfig:
        errors: list[str] = []

        errors.extend(self._validate_namespace_collisions())
        errors.extend(self._validate_member_references())
        errors.extend(self._validate_group_memberships())
        errors.extend(self._validate_circular_nesting())
        errors.extend(self._validate_license_groups())
        errors.extend(self._validate_github_handles_unique())
        errors.extend(self._validate_manager_references())
        errors.extend(self._validate_ca_policy_references())
        errors.extend(self._validate_shared_mailbox_delegates())
        errors.extend(self._validate_access_policies())

        if errors:
            raise ValueError(
                f"IAMConfig validation failed with {len(errors)} error(s):\n"
                + "\n".join(f"  - {e}" for e in errors)
            )
        return self

    def _all_principal_names(self) -> set[str]:
        names: set[str] = set()
        names.update(self.users.keys())
        names.update(self.service_principals.keys())
        names.update(self.managed_identities.keys())
        names.update(self.external_users.keys())
        names.update(self.shared_mailboxes.keys())
        return names

    def _validate_namespace_collisions(self) -> list[str]:
        # Principals and groups are referenced by bare name everywhere
        # (members, owners, delegates, tfvars), so all six collections
        # share one namespace; a collision would silently shadow in the
        # terraform principal_object_ids merge.
        errors: list[str] = []
        namespaces: list[tuple[str, set[str]]] = [
            ("users", set(self.users)),
            ("service_principals", set(self.service_principals)),
            ("managed_identities", set(self.managed_identities)),
            ("external_users", set(self.external_users)),
            ("shared_mailboxes", set(self.shared_mailboxes)),
            ("groups", set(self.groups)),
        ]
        for i, (kind_a, names_a) in enumerate(namespaces):
            for kind_b, names_b in namespaces[i + 1 :]:
                for name in sorted(names_a & names_b):
                    errors.append(
                        f"Name '{name}' is used by both {kind_a} and {kind_b}"
                    )
        return errors

    def _validate_member_references(self) -> list[str]:
        errors: list[str] = []
        all_names = self._all_principal_names()
        group_names = set(self.groups.keys())
        valid_targets = all_names | group_names

        for group_key, group in self.groups.items():
            if not hasattr(group, "members"):
                continue
            for member in group.members:
                if member.principal_type == PrincipalType.GROUP:
                    if member.name not in group_names:
                        errors.append(
                            f"Group '{group_key}' references unknown nested group '{member.name}'"
                        )
                elif member.name not in valid_targets:
                    errors.append(
                        f"Group '{group_key}' references unknown principal '{member.name}'"
                    )
        return errors

    def _validate_group_memberships(self) -> list[str]:
        errors: list[str] = []
        group_names = set(self.groups.keys())

        for user_key, user in self.users.items():
            for group_ref in user.group_memberships:
                if group_ref not in group_names:
                    errors.append(
                        f"User '{user_key}' references unknown group '{group_ref}'"
                    )

        for sp_key, sp in self.service_principals.items():
            for group_ref in sp.group_memberships:
                if group_ref not in group_names:
                    errors.append(
                        f"ServicePrincipal '{sp_key}' references unknown group '{group_ref}'"
                    )

        for eu_key, eu in self.external_users.items():
            for group_ref in eu.group_memberships:
                if group_ref not in group_names:
                    errors.append(
                        f"ExternalUser '{eu_key}' references unknown group '{group_ref}'"
                    )
        return errors

    def _validate_circular_nesting(self) -> list[str]:
        errors: list[str] = []
        adjacency: dict[str, list[str]] = {}

        for group_key, group in self.groups.items():
            children: list[str] = []
            if hasattr(group, "members"):
                for member in group.members:
                    if member.principal_type == PrincipalType.GROUP:
                        children.append(member.name)
            adjacency[group_key] = children

        def has_cycle(node: str, visited: set[str], path: set[str]) -> bool:
            visited.add(node)
            path.add(node)
            for child in adjacency.get(node, []):
                if child in path:
                    return True
                if child not in visited and has_cycle(child, visited, path):
                    return True
            path.discard(node)
            return False

        visited: set[str] = set()
        for group_key in adjacency:
            if group_key not in visited:
                if has_cycle(group_key, visited, set()):
                    errors.append(f"Circular group nesting detected involving '{group_key}'")
        return errors

    def _validate_license_groups(self) -> list[str]:
        from iamkit.models.groups import LicenseGroup

        errors: list[str] = []
        valid_skus = {sku.sku_part_number for sku in self.license_skus.values()}

        for group_key, group in self.groups.items():
            if not isinstance(group, LicenseGroup):
                continue
            if group.sku not in valid_skus:
                errors.append(
                    f"LicenseGroup '{group_key}' references unknown SKU '{group.sku}'"
                )
            for member in group.members:
                if member.principal_type != PrincipalType.USER:
                    continue
                user = self.users.get(member.name)
                if user and not user.usage_location:
                    errors.append(
                        f"User '{member.name}' in LicenseGroup '{group_key}' "
                        f"is missing required 'usage_location'"
                    )
        return errors

    def _validate_github_handles_unique(self) -> list[str]:
        errors: list[str] = []
        handles: dict[str, str] = {}

        for user_key, user in self.users.items():
            gh = user.platform_config.github
            if gh is None:
                continue
            if gh.handle in handles:
                errors.append(
                    f"Duplicate GitHub handle '{gh.handle}' on users "
                    f"'{handles[gh.handle]}' and '{user_key}'"
                )
            else:
                handles[gh.handle] = user_key
        return errors

    def _validate_manager_references(self) -> list[str]:
        errors: list[str] = []
        user_keys = set(self.users.keys())

        for user_key, user in self.users.items():
            if user.manager is None:
                continue
            if user.manager not in user_keys:
                errors.append(
                    f"User '{user_key}' references unknown manager '{user.manager}'"
                )
            elif user.manager == user_key:
                errors.append(f"User '{user_key}' lists themselves as manager")
        return errors

    def _validate_ca_policy_references(self) -> list[str]:
        errors: list[str] = []
        all_names = self._all_principal_names()
        group_names = set(self.groups.keys())

        for policy_key, policy in self.conditional_access_policies.items():
            cond = policy.conditions.users
            for ref in cond.include_users + cond.exclude_users:
                if ref not in all_names and ref != "All":
                    errors.append(
                        f"CA policy '{policy_key}' references unknown user '{ref}'"
                    )
            for ref in cond.include_groups + cond.exclude_groups:
                if ref not in group_names:
                    errors.append(
                        f"CA policy '{policy_key}' references unknown group '{ref}'"
                    )
        return errors

    def _validate_access_policies(self) -> list[str]:
        errors: list[str] = []
        group_names = set(self.groups.keys())

        for policy_key, policy in self.access_policies.items():
            if policy.group is not None and policy.group not in group_names:
                errors.append(
                    f"AccessPolicy '{policy_key}' references unknown group '{policy.group}'"
                )
            for ref in policy.conditional_access_groups:
                if ref not in group_names:
                    errors.append(
                        f"AccessPolicy '{policy_key}' references unknown "
                        f"conditional access group '{ref}'"
                    )
        return errors

    def _validate_shared_mailbox_delegates(self) -> list[str]:
        errors: list[str] = []
        all_names = self._all_principal_names()

        for mb_key, mb in self.shared_mailboxes.items():
            for delegate in mb.delegates:
                if delegate not in all_names:
                    errors.append(
                        f"SharedMailbox '{mb_key}' references unknown delegate '{delegate}'"
                    )
        return errors
