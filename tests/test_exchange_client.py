"""Tests for the Exchange Online client using a fake pwsh runner."""

import json
import logging

import pytest

from iamkit.clients.exchange import (
    CERT_PASSWORD_ENV,
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


@pytest.mark.parametrize("payload", ["", "[1,2]"])
def test_get_mailbox_addresses_rejects_non_dict_payload(payload):
    with pytest.raises(ExchangeOnlineError, match="unparseable"):
        _client(lambda script: payload).get_mailbox_addresses("alice@acme.example")


def test_get_mailbox_addresses_rejects_mailbox_with_no_primary():
    payload = {"found": True, "addresses": ["smtp:privacy@acme.example"]}
    with pytest.raises(ExchangeOnlineError, match="no primary"):
        _client(lambda script: json.dumps(payload)).get_mailbox_addresses(
            "alice@acme.example"
        )


def test_parsed_addresses_are_lowercased():
    payload = {
        "found": True,
        "addresses": ["SMTP:Alice@Acme.Example", "smtp:Privacy@Acme.Example"],
    }
    result = _client(lambda script: json.dumps(payload)).get_mailbox_addresses(
        "alice@acme.example"
    )
    assert result.primary == "alice@acme.example"
    assert result.secondary == ("privacy@acme.example",)


def test_set_proxy_addresses_builds_add_and_remove():
    scripts = []

    def runner(script: str) -> str:
        scripts.append(script)
        return ""

    _client(runner).set_proxy_addresses(
        "alice@acme.example",
        add=["a@acme.example", "b@acme.example"],
        remove=["old@acme.example"],
    )

    script = scripts[0]
    assert "Set-Mailbox" in script
    assert (
        "-EmailAddresses @{Add='smtp:a@acme.example','smtp:b@acme.example'; "
        "Remove='smtp:old@acme.example'}"
    ) in script


def test_set_proxy_addresses_refuses_a_no_op():
    with pytest.raises(ValueError, match="no addresses"):
        _client(lambda script: "").set_proxy_addresses(
            "alice@acme.example", add=[], remove=[]
        )


@pytest.mark.parametrize("field", ["add", "remove"])
def test_set_proxy_addresses_refuses_malformed_addresses(field):
    def runner(script: str) -> str:
        raise AssertionError("runner must not be reached")

    kwargs = {"add": [], "remove": []}
    kwargs[field] = ["alice@acme.example'; Remove-Mailbox -Identity x #"]
    with pytest.raises(ValueError, match="Invalid address"):
        _client(runner).set_proxy_addresses("alice@acme.example", **kwargs)


@pytest.mark.parametrize(
    "bad",
    ["alice@acme.example'; Remove-Mailbox -Identity x #", "no-at-sign", "a@b"],
)
def test_malformed_addresses_are_refused_before_reaching_pwsh(bad):
    def runner(script: str) -> str:
        raise AssertionError("runner must not be reached")

    with pytest.raises(ValueError, match="Invalid address"):
        _client(runner).get_mailbox_addresses(bad)


def test_connect_block_escapes_embedded_quotes():
    scripts = []

    def runner(script: str) -> str:
        scripts.append(script)
        return json.dumps({"found": False})

    ExchangeOnlineClient(
        app_id="00000000-0000-0000-0000-000000000000",
        organization="acme'; Remove-Mailbox -Identity alice #",
        certificate_path="/tmp/cert.pfx",
        runner=runner,
    ).get_mailbox_addresses("alice@acme.example")

    assert "-Organization 'acme''; Remove-Mailbox -Identity alice #'" in scripts[0]


def test_certificate_password_is_referenced_not_interpolated(monkeypatch):
    monkeypatch.setenv(CERT_PASSWORD_ENV, "s3cr3t-value")
    scripts = []

    def runner(script: str) -> str:
        scripts.append(script)
        return json.dumps({"found": False})

    _client(runner).get_mailbox_addresses("alice@acme.example")

    assert "s3cr3t-value" not in scripts[0]
    assert f"$env:{CERT_PASSWORD_ENV}" in scripts[0]
    assert "-CertificatePassword" in scripts[0]


def test_certificate_password_clause_omitted_when_unset(monkeypatch):
    monkeypatch.delenv(CERT_PASSWORD_ENV, raising=False)
    scripts = []

    def runner(script: str) -> str:
        scripts.append(script)
        return json.dumps({"found": False})

    _client(runner).get_mailbox_addresses("alice@acme.example")

    assert "-CertificatePassword" not in scripts[0]


def test_script_silences_warnings_and_shields_the_real_error_from_disconnect():
    scripts = []

    def runner(script: str) -> str:
        scripts.append(script)
        return json.dumps({"found": False})

    _client(runner).get_mailbox_addresses("alice@acme.example")

    assert "$ErrorActionPreference = 'Stop'" in scripts[0]
    assert "$WarningPreference = 'SilentlyContinue'" in scripts[0]
    assert (
        "Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue"
        in scripts[0]
    )


def test_set_proxy_addresses_logs_the_write_only_after_it_succeeds(caplog):
    def failing_runner(script: str) -> str:
        raise ExchangeOnlineError("Set-Mailbox failed")

    with caplog.at_level(logging.INFO, logger="iamkit.clients.exchange"):
        with pytest.raises(ExchangeOnlineError):
            _client(failing_runner).set_proxy_addresses(
                "alice@acme.example", add=["support@acme.example"], remove=[]
            )
        assert caplog.records == []

        _client(lambda script: "").set_proxy_addresses(
            "alice@acme.example", add=["support@acme.example"], remove=[]
        )
        assert len(caplog.records) == 1
