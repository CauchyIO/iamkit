"""The posture model refuses everything that could reach PowerShell unguarded."""

import pytest
from pydantic import ValidationError

from iamkit.rbac.exchange import ExchangeRbacPosture


def make_posture(**overrides):
    kwargs = dict(
        mailbox_upn="alias-owner@tenant.example",
        scope_name="alias-target",
        role_name="alias-writer",
        group_name="alias-automation",
        sp_display_name="tenant alias automation",
        sp_app_id="024db853-e770-44ad-8875-c335a45e7c10",
        sp_object_id="ff9f2c3e-d6dc-44fb-a8c1-147728ef5aa7",
    )
    kwargs.update(overrides)
    return ExchangeRbacPosture(**kwargs)


def test_defaults_pin_the_two_reconciler_cmdlets():
    p = make_posture()
    assert p.role_parent == "Mail Recipients"
    assert p.role_entries == {
        "Get-Mailbox": ("Identity",),
        "Set-Mailbox": ("Identity", "EmailAddresses"),
    }


def test_restriction_filter_names_the_mailbox():
    assert make_posture().restriction_filter == (
        "UserPrincipalName -eq 'alias-owner@tenant.example'"
    )


def test_model_is_frozen_and_forbids_extras():
    p = make_posture()
    with pytest.raises(ValidationError):
        p.mailbox_upn = "other@tenant.example"
    with pytest.raises(ValidationError):
        make_posture(unknown_field="x")


@pytest.mark.parametrize(
    "field,value",
    [
        ("mailbox_upn", "not an address"),
        ("mailbox_upn", "quote'inject@tenant.example"),
        ("scope_name", "bad;name"),
        ("scope_name", "'quoted'"),
        ("role_name", "role\nname"),
        ("group_name", ""),
        ("sp_display_name", "name$(rm)"),
        ("sp_app_id", "not-a-guid"),
        ("sp_object_id", "024db853"),
    ],
)
def test_injection_shaped_values_are_refused(field, value):
    with pytest.raises(ValidationError):
        make_posture(**{field: value})


@pytest.mark.parametrize(
    "entries",
    [
        {"Get-Mailbox; Remove-Mailbox": ("Identity",)},
        {"Get-Mailbox": ("Identity;Format",)},
        {"": ("Identity",)},
        {"Get-Mailbox": ()},
    ],
)
def test_role_entries_validate_cmdlet_and_parameter_shapes(entries):
    with pytest.raises(ValidationError):
        make_posture(role_entries=entries)


def test_empty_role_entries_are_refused():
    with pytest.raises(ValidationError):
        make_posture(role_entries={})
