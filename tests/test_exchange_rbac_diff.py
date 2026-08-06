"""Each test pins one diff rule; swapping any guard must kill at least one."""

import json

from iamkit.rbac.exchange import (
    AddRoleEntry,
    AddSoleMember,
    CreateGroup,
    CreateRole,
    CreateScope,
    CreateServicePrincipalPointer,
    CurrentPosture,
    EnableOrgCustomization,
    PinRoleEntryParameters,
    RemoveRoleEntry,
    SetGroupWriteScope,
    StripUndeclaredEntries,
    diff,
)
from test_exchange_rbac_model import make_posture
from test_exchange_rbac_read import FIXTURE_HALF_PROVISIONED


def half():
    return CurrentPosture.from_json_text(FIXTURE_HALF_PROVISIONED)


def converged_doc():
    return {
        "org_customization_enabled": True,
        "service_principal": {
            "app_id": "024db853-e770-44ad-8875-c335a45e7c10",
            "object_id": "ff9f2c3e-d6dc-44fb-a8c1-147728ef5aa7",
            "display_name": "tenant alias automation",
        },
        "scope": {
            "name": "alias-target",
            "filter": "UserPrincipalName -eq 'alias-owner@tenant.example'",
        },
        "role": {"name": "alias-writer"},
        "role_entries": [
            {"name": "Get-Mailbox", "parameters": ["Identity"]},
            {"name": "Set-Mailbox", "parameters": ["Identity", "EmailAddresses"]},
        ],
        "group": {"name": "alias-automation", "write_scope": "alias-target"},
        "group_members": ["tenant alias automation"],
        "authorization": [{"role": "alias-writer", "granted": True}],
    }


def current(doc):
    return CurrentPosture.from_json_text(json.dumps(doc))


def test_half_provisioned_tenant_plans_the_exact_bootstrap():
    plan = diff(make_posture(), half())
    assert plan.blockers == ()
    assert plan.actions == (
        EnableOrgCustomization(),
        CreateScope(
            name="alias-target",
            filter="UserPrincipalName -eq 'alias-owner@tenant.example'",
        ),
        CreateRole(name="alias-writer", parent="Mail Recipients"),
        StripUndeclaredEntries(
            role="alias-writer", keep=("Get-Mailbox", "Set-Mailbox")
        ),
        PinRoleEntryParameters(
            role="alias-writer", cmdlet="Get-Mailbox", parameters=("Identity",)
        ),
        PinRoleEntryParameters(
            role="alias-writer",
            cmdlet="Set-Mailbox",
            parameters=("Identity", "EmailAddresses"),
        ),
        CreateGroup(
            name="alias-automation", role="alias-writer", write_scope="alias-target"
        ),
        AddSoleMember(group="alias-automation", member="tenant alias automation"),
    )


def test_converged_tenant_is_zero_drift():
    plan = diff(make_posture(), current(converged_doc()))
    assert plan.empty and plan.actions == () and plan.blockers == ()


def test_missing_service_principal_is_created():
    doc = converged_doc()
    doc["service_principal"] = None
    plan = diff(make_posture(), current(doc))
    assert plan.actions == (
        CreateServicePrincipalPointer(
            app_id="024db853-e770-44ad-8875-c335a45e7c10",
            object_id="ff9f2c3e-d6dc-44fb-a8c1-147728ef5aa7",
            display_name="tenant alias automation",
        ),
    )


def test_existing_role_diffs_entries_exactly():
    doc = converged_doc()
    doc["role_entries"] = [
        {"name": "Get-Mailbox", "parameters": ["Identity", "Filter"]},  # over-pinned
        {"name": "Get-Recipient", "parameters": ["Identity"]},  # undeclared
    ]  # Set-Mailbox missing
    plan = diff(make_posture(), current(doc))
    assert plan.actions == (
        RemoveRoleEntry(role="alias-writer", cmdlet="Get-Recipient"),
        AddRoleEntry(
            role="alias-writer",
            cmdlet="Set-Mailbox",
            parameters=("Identity", "EmailAddresses"),
        ),
        PinRoleEntryParameters(
            role="alias-writer", cmdlet="Get-Mailbox", parameters=("Identity",)
        ),
    )


def test_scope_filter_mismatch_is_a_blocker_not_an_action():
    doc = converged_doc()
    doc["scope"]["filter"] = "UserPrincipalName -eq 'someone-else@tenant.example'"
    plan = diff(make_posture(), current(doc))
    assert plan.actions == ()
    assert len(plan.blockers) == 1 and "alias-target" in plan.blockers[0]


def test_scope_filter_comparison_ignores_exchange_canonicalisation():
    doc = converged_doc()
    doc["scope"]["filter"] = "(UserPrincipalName -eq 'alias-owner@tenant.example')"
    assert diff(make_posture(), current(doc)).empty


def test_wrong_group_write_scope_is_corrected():
    doc = converged_doc()
    doc["group"]["write_scope"] = "Default Scope"
    plan = diff(make_posture(), current(doc))
    assert plan.actions == (
        SetGroupWriteScope(group="alias-automation", write_scope="alias-target"),
    )


def test_extra_group_member_is_a_blocker():
    doc = converged_doc()
    doc["group_members"] = ["tenant alias automation", "Somebody Else"]
    plan = diff(make_posture(), current(doc))
    assert plan.actions == ()
    assert len(plan.blockers) == 1 and "Somebody Else" in plan.blockers[0]


def test_missing_member_is_added():
    doc = converged_doc()
    doc["group_members"] = []
    plan = diff(make_posture(), current(doc))
    assert plan.actions == (
        AddSoleMember(group="alias-automation", member="tenant alias automation"),
    )
