"""Mailbox SMTP alias executor.

Reconciles the `aliases` declared on users onto their Exchange Online
mailboxes as secondary proxy addresses. The reconciliation is deliberately
narrow: it can only add and remove addresses inside a declared set of
managed domains.

Three properties hold locally, in whatever case the client hands the mailbox's
addresses over: every address entering the diff — the primary, the current
secondaries, and the declared aliases — is folded before it is compared, and
the add and remove lists are emitted folded. (The mailbox's own UPN is not:
it is passed through to the client as given, and `_current` folds it only to
key the cache.)

* The primary address cannot be added (declaring it as an alias is refused)
  and cannot be removed (it is excluded from the removable set even when it
  also appears among the secondaries, which an AD-authored `proxyAddresses`
  list in a hybrid tenant can produce).
* The .onmicrosoft.com routing address cannot be reached because it can
  never be a managed domain: the executor refuses one at construction, and
  removals are drawn only from addresses whose domain is in that set.
* A declared alias that is already present is neither re-added nor removed,
  so a second pass over an applied change is a no-op.

Two properties are inherited from `iamkit.clients.exchange` rather than
enforced here, and are only as true as that module makes them:

* The `smtp:` prefix that marks an address secondary rather than primary is
  applied by the client; this module emits bare addresses.
* Non-SMTP entries (SIP, X500, SPO) are out of reach because
  `MailboxAddresses.secondary` is documented to hold only the stripped
  `smtp:` entries, and this module never reads past it.
"""

from __future__ import annotations

from dataclasses import dataclass

from iamkit.clients.exchange import ExchangeOnlineError, MailboxAddresses
from iamkit.executors.base import BaseExecutor, ExecutionResult, OperationType
from iamkit.models.config import IAMConfig


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
        normalised: list[str] = []
        for raw in managed_domains:
            domain = raw.strip().lower().lstrip("@")
            if not domain:
                raise ValueError(
                    f"managed_domains contains a blank entry ({raw!r}); every entry "
                    "must name a domain"
                )
            if domain.endswith(".onmicrosoft.com"):
                raise ValueError(
                    f"Refusing to manage '{domain}': the .onmicrosoft.com address "
                    "is Exchange's routing address and must never be reconciled away"
                )
            normalised.append(domain)
        self._client = client
        self._domains = frozenset(normalised)
        # One lookup per mailbox per run: plan() calls exists(), _needs_update()
        # and _get_changes() back to back, and each would otherwise round-trip.
        self._cache: dict[str, MailboxAddresses | None] = {}

    def get_resource_type(self) -> str:
        return "mailbox_aliases"

    def _current(self, resource: MailboxAliasDesiredState) -> MailboxAddresses | None:
        # Keyed on the folded UPN because the client normalises to lowercase
        # before it queries: without folding, one mailbox reached under two
        # casings gets two slots and a write invalidates only one of them.
        key = resource.upn.lower()
        if key not in self._cache:
            self._cache[key] = self._client.get_mailbox_addresses(resource.upn)
        return self._cache[key]

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
            if lowered == current.primary.lower():  # folded on both sides
                raise ValueError(
                    f"Alias '{alias}' is the primary address of '{resource.upn}'; "
                    "changing the primary is a rename, not an alias"
                )
            desired.add(lowered)

        # Every current address is folded before it is compared to anything, so
        # the whole diff is case-insensitive rather than only the parts the
        # client happens to have normalised. Unfolded, a mixed-case secondary
        # is both absent from `in_scope` under one casing and present under the
        # other, which turns a live alias into a remove paired with an add.
        #
        # The primary is then excluded explicitly, not just by virtue of being
        # undeclarable: if it also appears among the secondaries it is not in
        # `desired` (declaring it raises above), so it would otherwise fall
        # straight into the removal set.
        primary = current.primary.lower()
        in_scope = {
            address
            for address in (a.lower() for a in current.secondary)
            if address != primary and address.rpartition("@")[2] in self._domains
        }
        return sorted(desired - in_scope), sorted(in_scope - desired)

    def exists(self, resource: MailboxAliasDesiredState) -> bool:
        return self._current(resource) is not None

    def create_or_update(
        self, resource: MailboxAliasDesiredState
    ) -> ExecutionResult:
        # A missing mailbox, an out-of-scope alias, or an alias equal to the
        # primary must fail on every path including dry run: the base class
        # skips _get_changes when exists() is false, so a preview would
        # otherwise report a benign CREATE that the apply then rejects.
        self._diff(resource)
        return super().create_or_update(resource)

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
        # The gate lives here, not only in the base class's create_or_update:
        # delete() reaches the write through update() directly, so a gate one
        # level up would leave a dry-run deprovisioning run removing every
        # in-scope address for real.
        if self.dry_run:
            return ExecutionResult(
                success=True,
                operation=OperationType.UPDATE,
                resource_type=self.get_resource_type(),
                resource_name=resource.name,
                message=f"{resource.upn}: would apply +{len(add)} -{len(remove)} alias(es)",
                changes={"add": add, "remove": remove},
            )
        # Invalidated before the write, not after: a write that lands and then
        # raises would otherwise leave the cache holding pre-write state for
        # the rest of the run, so every later pass diffs against a mailbox that
        # no longer looks like that.
        self._cache.pop(resource.upn.lower(), None)
        # Called directly, not through execute_with_retry. The Linear plane
        # retries because its client raises httpx.HTTPStatusError, which
        # _is_transient_error classifies on a status code. Exchange errors
        # carry the whole pwsh stdout+stderr, so classification falls through
        # to a substring match over Exchange's own prose — "…couldn't be found.
        # timeout" and "proxy address smtp:x-503@… is already used" both read
        # as transient. Set-Mailbox @{Add=…} errors when the address is already
        # present and @{Remove=…} errors when it is not, so re-issuing a write
        # that already landed turns a success into a hard failure. The pwsh
        # path has its own PWSH_TIMEOUT_SECONDS ceiling and there is no rate
        # limit here worth riding out, so retrying buys nothing and costs this.
        self._client.set_proxy_addresses(resource.upn, add=add, remove=remove)
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
        result = self.update(stripped)
        if result.operation != OperationType.UPDATE:
            return result
        # Relabelled so the audit trail and the plan's glyph read as a removal;
        # update() is only the mechanism.
        return result.model_copy(update={"operation": OperationType.DELETE})
