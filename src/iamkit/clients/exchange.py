"""Exchange Online admin client — app-only certificate auth over pwsh.

SMTP aliases live on the mailbox as secondary proxy addresses. That property is
read-only in Microsoft Graph and computed-only in the azuread Terraform
provider, and Microsoft documents no REST admin API for third-party clients, so
the only supported write path is the ExchangeOnlineManagement PowerShell
module. This client shells out to `pwsh`, one connected session per call.

Auth: app-only with a certificate (client secrets are not supported for
Exchange Online app-only). If the .pfx is password-protected, export the
password as IAMKIT_EXO_CERT_PASSWORD — it is read inside the PowerShell
session from the inherited environment and never interpolated into the script
text or passed on a command line.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Callable

logger = logging.getLogger(__name__)

CERT_PASSWORD_ENV = "IAMKIT_EXO_CERT_PASSWORD"

# Connect-ExchangeOnline is a network handshake; without a ceiling a wedged
# connect blocks the caller forever with no diagnostic. Generous enough that a
# slow connect never trips it — TimeoutExpired propagates.
PWSH_TIMEOUT_SECONDS = 300

# Deliberately strict: every address reaching this module is interpolated into
# a PowerShell script, so anything that is not plainly an address is refused
# before it gets near pwsh. It is narrower than RFC 5321 on purpose, and the
# ceiling is real rather than theoretical: a local part containing an
# apostrophe or any other character outside this pattern's allowed set
# (o'brien@acme.example) is a valid, unquoted address that this client
# refuses outright, and reconcile time is where the operator finds that out.
# Widening it is a separate decision from the injection guard it currently
# is — it would leave _quote's escaping as the only thing between a config
# value and the script text.
_ADDRESS_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")

PwshRunner = Callable[[str], str]


class ExchangeOnlineError(RuntimeError):
    """A pwsh or Exchange Online invocation failed."""


@dataclass(frozen=True)
class MailboxAddresses:
    """The SMTP addresses currently on a mailbox.

    `primary` is the single `SMTP:` (uppercase) entry; `secondary` holds the
    `smtp:` (lowercase) entries in the order Exchange returned them. Non-SMTP
    entries (SIP:, X500:, SPO:) are dropped — nothing in iamkit manages them.
    """

    upn: str
    primary: str
    secondary: tuple[str, ...]


def _require_address(value: str, *, origin: str = "address") -> str:
    """Refuse anything that is not plainly an address, naming where it came from.

    A removal is drawn from what Exchange returned for the mailbox, not from
    config, so the two sides need different fixes and a bare `Invalid address`
    leaves the operator guessing which one they are looking at.
    """
    if not _ADDRESS_RE.fullmatch(value):
        raise ValueError(f"Invalid {origin}: {value!r}")
    return value.lower()


def _quote(value: str) -> str:
    """Single-quote a value for PowerShell, doubling embedded quotes."""
    return "'" + value.replace("'", "''") + "'"


def _unparseable(identity: str, raw: str) -> ExchangeOnlineError:
    return ExchangeOnlineError(
        f"Get-Mailbox returned unparseable output for {identity}: {raw!r}"
    )


def _default_runner(script: str) -> str:
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", "-"],
        input=script,
        capture_output=True,
        text=True,
        check=False,
        timeout=PWSH_TIMEOUT_SECONDS,
    )
    if proc.returncode != 0:
        raise ExchangeOnlineError(
            f"pwsh exited {proc.returncode}\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
        )
    if proc.stderr.strip():
        raise ExchangeOnlineError(f"pwsh wrote to stderr:\n{proc.stderr}")
    return proc.stdout


class ExchangeOnlineClient:
    """Runs Exchange Online admin cmdlets in a one-shot pwsh session.

    Each call connects, runs its cmdlet, and disconnects, so there is no
    session state to leak between calls — at the cost of paying the
    Connect-ExchangeOnline handshake every time.
    """

    def __init__(
        self,
        app_id: str,
        organization: str,
        certificate_path: str,
        *,
        runner: PwshRunner | None = None,
    ) -> None:
        self._app_id = app_id
        self._organization = organization
        self._certificate_path = certificate_path
        self._run = runner or _default_runner

    def _connect_block(self) -> str:
        parts = [
            "Connect-ExchangeOnline",
            f"-AppId {_quote(self._app_id)}",
            f"-Organization {_quote(self._organization)}",
            f"-CertificateFilePath {_quote(self._certificate_path)}",
            "-ShowBanner:$false",
        ]
        if os.environ.get(CERT_PASSWORD_ENV):
            parts.append(
                f"-CertificatePassword (ConvertTo-SecureString "
                f"-String $env:{CERT_PASSWORD_ENV} -AsPlainText -Force)"
            )
        return " ".join(parts)

    def _script(self, body: str) -> str:
        # $WarningPreference: ExchangeOnlineManagement emits warnings freely
        # (deprecation, REST-backend notices) and -ShowBanner:$false does not
        # cover them. $ErrorActionPreference governs errors only, so if pwsh
        # routes a warning to stderr, _default_runner's fatal-stderr rule would
        # turn a benign notice into a raised exception.
        #
        # -ErrorAction SilentlyContinue on the disconnect: PowerShell discards
        # the in-flight exception if finally throws, so a transient disconnect
        # failure would mask a genuine Set-Mailbox error and surface itself as
        # the root cause instead.
        return (
            "$ErrorActionPreference = 'Stop'\n"
            "$WarningPreference = 'SilentlyContinue'\n"
            f"{self._connect_block()}\n"
            "try {\n"
            f"{body}\n"
            "} finally {\n"
            "    Disconnect-ExchangeOnline -Confirm:$false"
            " -ErrorAction SilentlyContinue | Out-Null\n"
            "}\n"
        )

    def get_mailbox_addresses(self, upn: str) -> MailboxAddresses | None:
        """Return the mailbox's SMTP addresses, or None if it does not exist."""
        identity = _require_address(upn)
        body = (
            "    try {\n"
            f"        $mbx = Get-Mailbox -Identity {_quote(identity)}\n"
            "        @{ found = $true; addresses = @($mbx.EmailAddresses) } |"
            " ConvertTo-Json -Depth 3 -Compress\n"
            "    } catch {\n"
            "        if ($_.FullyQualifiedErrorId -like"
            " '*ManagementObjectNotFoundException*') {\n"
            "            @{ found = $false } | ConvertTo-Json -Compress\n"
            "        } else { throw }\n"
            "    }"
        )
        raw = self._run(self._script(body))
        try:
            payload = json.loads(raw.strip() or "null")
        except json.JSONDecodeError as exc:
            raise _unparseable(identity, raw) from exc
        if not isinstance(payload, dict):
            raise _unparseable(identity, raw)
        if not payload.get("found"):
            return None

        primary: str | None = None
        secondary: list[str] = []
        for entry in payload.get("addresses") or []:
            prefix, _, address = str(entry).partition(":")
            if prefix == "SMTP":
                primary = address.lower()
            elif prefix == "smtp":
                secondary.append(address.lower())
        if primary is None:
            raise ExchangeOnlineError(
                f"Mailbox {identity} reports no primary (SMTP:) address; "
                "refusing to reconcile against an incoherent mailbox"
            )
        return MailboxAddresses(
            upn=identity, primary=primary, secondary=tuple(secondary)
        )

    def set_proxy_addresses(
        self, upn: str, *, add: list[str], remove: list[str]
    ) -> None:
        """Add and/or remove secondary SMTP addresses on a mailbox."""
        identity = _require_address(upn)
        to_add = [
            _require_address(a, origin="address to add (declared in config)")
            for a in add
        ]
        to_remove = [
            _require_address(
                a,
                origin=(
                    "address to remove (returned by Exchange for this mailbox, "
                    "not declared in config)"
                ),
            )
            for a in remove
        ]
        if not to_add and not to_remove:
            raise ValueError(
                f"set_proxy_addresses called for {identity} with no addresses "
                "to add or remove"
            )

        clauses = []
        if to_add:
            joined = ",".join(_quote(f"smtp:{a}") for a in to_add)
            clauses.append(f"Add={joined}")
        if to_remove:
            joined = ",".join(_quote(f"smtp:{a}") for a in to_remove)
            clauses.append(f"Remove={joined}")
        table = "; ".join(clauses)

        body = (
            f"    Set-Mailbox -Identity {_quote(identity)} "
            f"-EmailAddresses @{{{table}}}"
        )
        self._run(self._script(body))
        # Logged after the call: in an IAM tool the log is the audit trail, so
        # it records what happened, not what was attempted.
        logger.info(
            "Set-Mailbox %s: add=%s remove=%s", identity, to_add, to_remove
        )
