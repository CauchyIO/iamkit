"""Mailbox SMTP alias executor.

Reconciles the `aliases` declared on users onto their Exchange Online
mailboxes as secondary proxy addresses. The reconciliation is deliberately
narrow: it can only add and remove lowercase `smtp:` addresses inside a
declared set of managed domains. The primary address, the .onmicrosoft.com
routing address, and every non-SMTP entry (SIP, X500, SPO) are structurally
out of reach.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from iamkit.clients.exchange import ExchangeOnlineError, MailboxAddresses
from iamkit.executors.base import BaseExecutor, ExecutionResult, OperationType
from iamkit.models.config import IAMConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MailboxAliasDesiredState:
    """Desired secondary SMTP addresses for a single mailbox."""

    name: str
    upn: str
    aliases: tuple[str, ...]


def resolve_desired_state(
    config: IAMConfig, *, allow_unmanaged_users: bool = False
) -> list[MailboxAliasDesiredState]:
    """Derive per-mailbox alias desired state from the config.

    Users with no aliases and disabled users are skipped. A `managed=False`
    principal that declares aliases raises unless the caller opts in: under
    IAM-P03 those accounts are read-only to IaC, and writing addresses to one
    is a decision the calling tenant must make deliberately, in the open.
    """
    states: list[MailboxAliasDesiredState] = []

    for user_key, user in sorted(config.users.items()):
        if not user.aliases:
            continue
        if not user.account_enabled:
            continue
        if not user.managed and not allow_unmanaged_users:
            raise ValueError(
                f"User '{user_key}' is managed=False but declares aliases. "
                "Writing addresses to a principal that IaC otherwise only reads "
                "is an IAM-P03 decision; pass allow_unmanaged_users=True to opt "
                "in explicitly."
            )
        states.append(
            MailboxAliasDesiredState(
                name=user_key, upn=user.email, aliases=tuple(user.aliases)
            )
        )

    return states


class MailboxAliasExecutor(BaseExecutor[MailboxAliasDesiredState]):
    """Reconciles declared aliases onto mailboxes, in scope, and no further."""

    def __init__(
        self,
        client,
        managed_domains: list[str],
        dry_run: bool = False,
        max_retries: int = 3,
    ) -> None:
        super().__init__(dry_run=dry_run, max_retries=max_retries)
        if not managed_domains:
            raise ValueError(
                "managed_domains must name at least one domain; an executor with "
                "no scope would treat every existing alias as removable"
            )
        normalised = [d.lower().lstrip("@") for d in managed_domains]
        for domain in normalised:
            if domain.endswith(".onmicrosoft.com"):
                raise ValueError(
                    f"Refusing to manage '{domain}': the .onmicrosoft.com address "
                    "is Exchange's routing address and must never be reconciled away"
                )
        self._client = client
        self._domains = frozenset(normalised)
        # One lookup per mailbox per run: plan() calls exists(), _needs_update()
        # and _get_changes() back to back, and each would otherwise round-trip.
        self._cache: dict[str, MailboxAddresses | None] = {}

    def get_resource_type(self) -> str:
        return "mailbox_aliases"

    def _current(self, resource: MailboxAliasDesiredState) -> MailboxAddresses | None:
        if resource.upn not in self._cache:
            self._cache[resource.upn] = self._client.get_mailbox_addresses(resource.upn)
        return self._cache[resource.upn]

    def _diff(
        self, resource: MailboxAliasDesiredState
    ) -> tuple[list[str], list[str]]:
        current = self._current(resource)
        if current is None:
            raise ExchangeOnlineError(
                f"No mailbox found for '{resource.upn}'. This executor manages "
                "addresses on existing mailboxes and never creates them."
            )

        desired: set[str] = set()
        for alias in resource.aliases:
            lowered = alias.lower()
            domain = lowered.rpartition("@")[2]
            if domain not in self._domains:
                raise ValueError(
                    f"Alias '{alias}' on '{resource.upn}' is outside the managed "
                    f"domains {sorted(self._domains)}"
                )
            if lowered == current.primary:
                raise ValueError(
                    f"Alias '{alias}' is the primary address of '{resource.upn}'; "
                    "changing the primary is a rename, not an alias"
                )
            desired.add(lowered)

        in_scope = {
            address
            for address in current.secondary
            if address.rpartition("@")[2] in self._domains
        }
        return sorted(desired - in_scope), sorted(in_scope - desired)

    def exists(self, resource: MailboxAliasDesiredState) -> bool:
        return self._current(resource) is not None

    def _needs_update(self, resource: MailboxAliasDesiredState) -> bool:
        add, remove = self._diff(resource)
        return bool(add or remove)

    def _get_changes(self, resource: MailboxAliasDesiredState) -> dict:
        add, remove = self._diff(resource)
        return {"add": add, "remove": remove}

    def create(self, resource: MailboxAliasDesiredState) -> ExecutionResult:
        raise ExchangeOnlineError(
            f"No mailbox found for '{resource.upn}'. This executor manages "
            "addresses on existing mailboxes and never creates them."
        )

    def update(self, resource: MailboxAliasDesiredState) -> ExecutionResult:
        add, remove = self._diff(resource)
        if not add and not remove:
            return ExecutionResult(
                success=True,
                operation=OperationType.NO_OP,
                resource_type=self.get_resource_type(),
                resource_name=resource.name,
                message=f"{resource.upn}: aliases already match",
            )
        self.execute_with_retry(
            self._client.set_proxy_addresses, resource.upn, add=add, remove=remove
        )
        self._cache.pop(resource.upn, None)
        return ExecutionResult(
            success=True,
            operation=OperationType.UPDATE,
            resource_type=self.get_resource_type(),
            resource_name=resource.name,
            message=f"{resource.upn}: +{len(add)} -{len(remove)} alias(es)",
            changes={"add": add, "remove": remove},
        )

    def delete(self, resource: MailboxAliasDesiredState) -> ExecutionResult:
        """Remove every in-scope alias from the mailbox, leaving it bare."""
        stripped = MailboxAliasDesiredState(
            name=resource.name, upn=resource.upn, aliases=()
        )
        return self.update(stripped)
