"""The write script renders only whitelisted templates, in plan order."""

import pytest

from iamkit.clients.exchange import ExchangeOnlineError
from iamkit.rbac.exchange import (
    AddRoleEntry,
    AddSoleMember,
    CreateGroup,
    CreateRole,
    CreateScope,
    CreateServicePrincipalPointer,
    EnableOrgCustomization,
    PinRoleEntryParameters,
    RbacPlan,
    RemoveRoleEntry,
    SetGroupWriteScope,
    StripUndeclaredEntries,
    write_script,
)

FULL = RbacPlan(
    actions=(
        EnableOrgCustomization(),
        CreateServicePrincipalPointer(
            app_id="024db853-e770-44ad-8875-c335a45e7c10",
            object_id="ff9f2c3e-d6dc-44fb-a8c1-147728ef5aa7",
            display_name="tenant alias automation",
        ),
        CreateScope(
            name="alias-target",
            filter="UserPrincipalName -eq 'alias-owner@tenant.example'",
        ),
        CreateRole(name="alias-writer", parent="Mail Recipients"),
        StripUndeclaredEntries(
            role="alias-writer", keep=("Get-Mailbox", "Set-Mailbox")
        ),
        PinRoleEntryParameters(
            role="alias-writer",
            cmdlet="Set-Mailbox",
            parameters=("Identity", "EmailAddresses"),
        ),
        RemoveRoleEntry(role="alias-writer", cmdlet="Get-Recipient"),
        AddRoleEntry(
            role="alias-writer",
            cmdlet="Set-Mailbox",
            parameters=("Identity", "EmailAddresses"),
        ),
        CreateGroup(
            name="alias-automation", role="alias-writer", write_scope="alias-target"
        ),
        SetGroupWriteScope(group="alias-automation", write_scope="alias-target"),
        AddSoleMember(group="alias-automation", member="tenant alias automation"),
    ),
    blockers=(),
)


def test_every_action_renders_its_exact_cmdlet():
    s = write_script(FULL, "admin@tenant.example")
    assert "Enable-OrganizationCustomization" in s
    assert (
        "New-ServicePrincipal -AppId '024db853-e770-44ad-8875-c335a45e7c10' "
        "-ObjectId 'ff9f2c3e-d6dc-44fb-a8c1-147728ef5aa7' "
        "-DisplayName 'tenant alias automation'"
    ) in s
    assert (
        "New-ManagementScope -Name 'alias-target' -RecipientRestrictionFilter "
        "\"UserPrincipalName -eq 'alias-owner@tenant.example'\""
    ) in s
    assert "New-ManagementRole -Parent 'Mail Recipients' -Name 'alias-writer'" in s
    assert "@('Get-Mailbox', 'Set-Mailbox')" in s  # strip keep-list
    assert (
        "Remove-ManagementRoleEntry -Identity 'alias-writer\\Get-Recipient'"
        " -Confirm:$false"
    ) in s
    assert (
        "Add-ManagementRoleEntry -Identity 'alias-writer\\Set-Mailbox'"
        " -Parameters 'Identity','EmailAddresses'"
    ) in s
    assert (
        "Set-ManagementRoleEntry -Identity 'alias-writer\\Set-Mailbox'"
        " -Parameters 'Identity','EmailAddresses'"
    ) in s
    assert (
        "New-RoleGroup -Name 'alias-automation' -Roles 'alias-writer' "
        "-CustomRecipientWriteScope 'alias-target'"
    ) in s
    assert (
        "Set-RoleGroup -Identity 'alias-automation'"
        " -CustomRecipientWriteScope 'alias-target'"
    ) in s
    assert (
        "Add-RoleGroupMember -Identity 'alias-automation'"
        " -Member 'tenant alias automation'"
    ) in s


def test_only_remove_star_is_the_role_entry_removal():
    s = write_script(FULL, "admin@tenant.example")
    for line in s.splitlines():
        if "Remove-" in line and "Remove-ManagementRoleEntry" not in line:
            pytest.fail(f"unexpected Remove-*: {line}")


def test_actions_render_in_plan_order_inside_connect_wrapper():
    s = write_script(FULL, "admin@tenant.example")
    assert s.index("Connect-ExchangeOnline") < s.index("Enable-OrganizationCustomization")
    assert s.index("New-ManagementScope") < s.index("New-ManagementRole -Parent")
    assert s.index("New-RoleGroup") < s.index("Add-RoleGroupMember")
    assert s.rstrip().endswith("}")
    assert s.count("Disconnect-ExchangeOnline") == 1


def test_empty_or_blocked_plans_are_refused():
    with pytest.raises(ExchangeOnlineError):
        write_script(RbacPlan(actions=(), blockers=()), "admin@tenant.example")
    with pytest.raises(ExchangeOnlineError):
        write_script(
            RbacPlan(actions=(EnableOrgCustomization(),), blockers=("scope is wrong",)),
            "admin@tenant.example",
        )


def test_unknown_action_types_have_no_template():
    with pytest.raises(ExchangeOnlineError):
        write_script(
            RbacPlan(actions=("not-an-action",), blockers=()), "admin@tenant.example"
        )
