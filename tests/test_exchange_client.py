"""Tests for the Exchange Online client using a fake pwsh runner."""

import json

import pytest

from iamkit.clients.exchange import (
    ExchangeOnlineClient,
    ExchangeOnlineError,
    MailboxAddresses,
)

EXISTING_MAILBOX = {
    "found": True,
    "addresses": [
        "SMTP:alice@acme.example",
        "smtp:privacy@acme.example",
        "smtp:alice@acme.onmicrosoft.com",
        "SIP:alice@acme.example",
        "X500:/o=ExchangeLabs/ou=Exchange Administrative Group/cn=alice",
    ],
}


def _client(runner):
    return ExchangeOnlineClient(
        app_id="00000000-0000-0000-0000-000000000000",
        organization="acme.onmicrosoft.com",
        certificate_path="/tmp/cert.pfx",
        runner=runner,
    )


def test_get_mailbox_addresses_splits_primary_from_secondary():
    scripts = []

    def runner(script: str) -> str:
        scripts.append(script)
        return json.dumps(EXISTING_MAILBOX)

    result = _client(runner).get_mailbox_addresses("alice@acme.example")

    assert isinstance(result, MailboxAddresses)
    assert result.primary == "alice@acme.example"
    assert result.secondary == (
        "privacy@acme.example",
        "alice@acme.onmicrosoft.com",
    )
    assert "Connect-ExchangeOnline" in scripts[0]
    assert "Get-Mailbox" in scripts[0]


def test_get_mailbox_addresses_returns_none_when_absent():
    result = _client(lambda script: json.dumps({"found": False})).get_mailbox_addresses(
        "ghost@acme.example"
    )
    assert result is None


def test_get_mailbox_addresses_rejects_unparseable_output():
    with pytest.raises(ExchangeOnlineError, match="unparseable"):
        _client(lambda script: "not json").get_mailbox_addresses("alice@acme.example")


def test_get_mailbox_addresses_rejects_mailbox_with_no_primary():
    payload = {"found": True, "addresses": ["smtp:privacy@acme.example"]}
    with pytest.raises(ExchangeOnlineError, match="no primary"):
        _client(lambda script: json.dumps(payload)).get_mailbox_addresses(
            "alice@acme.example"
        )


def test_set_proxy_addresses_builds_add_and_remove():
    scripts = []

    def runner(script: str) -> str:
        scripts.append(script)
        return ""

    _client(runner).set_proxy_addresses(
        "alice@acme.example",
        add=["support@acme.example"],
        remove=["old@acme.example"],
    )

    script = scripts[0]
    assert "Set-Mailbox" in script
    assert "Add='smtp:support@acme.example'" in script
    assert "Remove='smtp:old@acme.example'" in script


def test_set_proxy_addresses_refuses_a_no_op():
    with pytest.raises(ValueError, match="no addresses"):
        _client(lambda script: "").set_proxy_addresses(
            "alice@acme.example", add=[], remove=[]
        )


@pytest.mark.parametrize(
    "bad",
    ["alice@acme.example'; Remove-Mailbox -Identity x #", "no-at-sign", "a@b"],
)
def test_malformed_addresses_are_refused_before_reaching_pwsh(bad):
    def runner(script: str) -> str:
        raise AssertionError("runner must not be reached")

    with pytest.raises(ValueError, match="Invalid address"):
        _client(runner).get_mailbox_addresses(bad)
