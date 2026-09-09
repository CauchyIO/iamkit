"""The read script observes without mutating; the parser distrusts its input."""

import json

import pytest

from iamkit.clients.exchange import ExchangeOnlineError
from iamkit.rbac.exchange import CurrentPosture, read_script
from test_exchange_rbac_model import make_posture


def test_read_script_is_read_only_and_names_every_object():
    s = read_script(make_posture(), "admin@tenant.example", "/tmp/state.json")
    assert "Connect-ExchangeOnline -UserPrincipalName 'admin@tenant.example'" in s
    for probe in [
        "Get-OrganizationConfig",
        "Get-ServicePrincipal",
        "Get-ManagementScope",
        "Get-ManagementRole ",
        "Get-ManagementRoleEntry",
        "Get-RoleGroup ",
        "Get-RoleGroupMember",
        "Test-ServicePrincipalAuthorization",
    ]:
        assert probe in s
    for mutator in [
        "New-",
        "Set-Mailbox",
        "Set-ManagementRoleEntry",
        "Set-RoleGroup",
        "Remove-",
        "Add-",
        "Enable-",
    ]:
        assert mutator not in s
    assert "Set-Content -Path '/tmp/state.json'" in s
    assert s.count("Disconnect-ExchangeOnline") == 1


def test_read_script_quotes_the_posture_values():
    p = make_posture(sp_display_name="o brien automation")
    assert "'o brien automation'" in read_script(p, "admin@tenant.example", "/x.json")


def test_read_script_refuses_a_malformed_admin_upn():
    with pytest.raises(ValueError):
        read_script(make_posture(), "not-an-upn", "/x.json")


FIXTURE_HALF_PROVISIONED = json.dumps(
    {
        "org_customization_enabled": False,
        "service_principal": {
            "app_id": "024db853-e770-44ad-8875-c335a45e7c10",
            "object_id": "ff9f2c3e-d6dc-44fb-a8c1-147728ef5aa7",
            "display_name": "tenant alias automation",
        },
        "scope": None,
        "role": None,
        "role_entries": [],
        "group": None,
        "group_members": [],
        "authorization": [],
    }
)


def test_parser_reads_the_half_provisioned_shape():
    c = CurrentPosture.from_json_text(FIXTURE_HALF_PROVISIONED)
    assert c.org_customization_enabled is False
    assert c.service_principal["display_name"] == "tenant alias automation"
    assert c.scope is None and c.role is None and c.group is None
    assert c.role_entries == () and c.group_members == ()


def test_parser_normalises_powershell_single_element_collapse():
    # ConvertTo-Json collapses one-element arrays to a bare object; the parser
    # must lift those back to lists rather than crash or mis-type.
    doc = json.loads(FIXTURE_HALF_PROVISIONED)
    doc["role"] = {"name": "alias-writer"}
    doc["role_entries"] = {"name": "Get-Mailbox", "parameters": "Identity"}
    doc["group_members"] = "tenant alias automation"
    c = CurrentPosture.from_json_text(json.dumps(doc))
    assert c.role_entries == ({"name": "Get-Mailbox", "parameters": ("Identity",)},)
    assert c.group_members == ("tenant alias automation",)


@pytest.mark.parametrize(
    "bad", ["", "not json", "{}", '{"org_customization_enabled": true}']
)
def test_parser_raises_with_context_on_bad_documents(bad):
    with pytest.raises(ExchangeOnlineError):
        CurrentPosture.from_json_text(bad)


def test_read_script_takes_the_write_scope_from_the_role_assignment():
    script = read_script(make_posture(), "admin@tenant.example", "/tmp/state.json")
    assert "Get-ManagementRoleAssignment -RoleAssignee 'alias-automation' -Role 'alias-writer'" in script
    assert "$assignment.CustomRecipientWriteScope" in script
    assert "$group.CustomRecipientWriteScope" not in script
    assert "if ($_.DisplayName) { [string]$_.DisplayName } else { [string]$_.Name }" in script
