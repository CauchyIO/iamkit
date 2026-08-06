"""Tests for the mailbox alias executor using a fake Exchange client."""

import pytest

from iamkit.clients.exchange import ExchangeOnlineError, MailboxAddresses
from iamkit.executors.base import OperationType
from iamkit.executors.exchange import (
    MailboxAliasDesiredState,
    MailboxAliasExecutor,
    resolve_desired_state,
)
from iamkit.models.config import IAMConfig
from iamkit.models.principals import User

DOMAINS = ["acme.example"]


class FakeExchangeClient:
    def __init__(self, mailboxes: dict[str, MailboxAddresses] | None = None) -> None:
        self.mailboxes = mailboxes or {}
        self.calls: list[tuple[str, list[str], list[str]]] = []

    def get_mailbox_addresses(self, upn: str) -> MailboxAddresses | None:
        return self.mailboxes.get(upn)

    def set_proxy_addresses(self, upn: str, *, add, remove) -> None:
        self.calls.append((upn, list(add), list(remove)))


class StatefulExchangeClient(FakeExchangeClient):
    """A fake that actually applies its writes, so a second pass sees them."""

    def set_proxy_addresses(self, upn: str, *, add, remove) -> None:
        super().set_proxy_addresses(upn, add=add, remove=remove)
        current = self.mailboxes[upn]
        secondary = [a for a in current.secondary if a not in remove]
        secondary.extend(add)
        self.mailboxes[upn] = MailboxAddresses(
            upn=current.upn, primary=current.primary, secondary=tuple(secondary),
        )


def _mailbox(*secondary: str) -> MailboxAddresses:
    return MailboxAddresses(
        upn="alice@acme.example",
        primary="alice@acme.example",
        secondary=tuple(secondary),
    )


def _state(*aliases: str) -> MailboxAliasDesiredState:
    return MailboxAliasDesiredState(
        name="alice", upn="alice@acme.example", aliases=tuple(aliases)
    )


class TestResolveDesiredState:
    def test_empty_config_yields_nothing(self):
        assert resolve_desired_state(IAMConfig()) == []

    def test_users_without_aliases_are_skipped(self):
        config = IAMConfig(users={
            "alice": User(name="alice", display_name="Alice", email="alice@acme.example"),
        })
        assert resolve_desired_state(config) == []

    def test_user_with_aliases_is_resolved(self):
        config = IAMConfig(users={
            "alice": User(
                name="alice", display_name="Alice", email="alice@acme.example",
                aliases=["privacy@acme.example"],
            ),
        })
        assert resolve_desired_state(config) == [
            MailboxAliasDesiredState(
                name="alice", upn="alice@acme.example",
                aliases=("privacy@acme.example",),
            )
        ]

    def test_disabled_user_is_skipped(self):
        config = IAMConfig(users={
            "alice": User(
                name="alice", display_name="Alice", email="alice@acme.example",
                aliases=["privacy@acme.example"], account_enabled=False,
            ),
        })
        assert resolve_desired_state(config) == []

    def test_disabled_unmanaged_user_is_skipped_not_refused(self):
        # IAM-P03 states that the disabled check runs before the managed check,
        # so a disabled managed=False principal is skipped rather than raised
        # on. Neither single-flag test above holds both flags at once, so
        # swapping the two guards would falsify the principle with a green
        # suite.
        config = IAMConfig(users={
            "alice": User(
                name="alice", display_name="Alice", email="alice@acme.example",
                aliases=["privacy@acme.example"], managed=False,
                account_enabled=False,
            ),
        })
        assert resolve_desired_state(config) == []

    def test_users_are_resolved_in_a_deterministic_order(self):
        # Export determinism is a repo-wide decision; with one aliased user the
        # sort in resolve_desired_state is unobservable.
        config = IAMConfig(users={
            "zoe": User(
                name="zoe", display_name="Zoe", email="zoe@acme.example",
                aliases=["z@acme.example"],
            ),
            "alice": User(
                name="alice", display_name="Alice", email="alice@acme.example",
                aliases=["privacy@acme.example"],
            ),
        })
        assert [s.name for s in resolve_desired_state(config)] == ["alice", "zoe"]

    def test_unmanaged_user_refused_by_default(self):
        config = IAMConfig(users={
            "alice": User(
                name="alice", display_name="Alice", email="alice@acme.example",
                aliases=["privacy@acme.example"], managed=False,
            ),
        })
        with pytest.raises(ValueError, match="allow_unmanaged_users"):
            resolve_desired_state(config)

    def test_unmanaged_user_included_on_explicit_opt_in(self):
        config = IAMConfig(users={
            "alice": User(
                name="alice", display_name="Alice", email="alice@acme.example",
                aliases=["privacy@acme.example"], managed=False,
            ),
        })
        states = resolve_desired_state(config, allow_unmanaged_users=True)
        assert [s.name for s in states] == ["alice"]


class TestExecutorConstruction:
    def test_empty_managed_domains_refused(self):
        with pytest.raises(ValueError, match="at least one domain"):
            MailboxAliasExecutor(FakeExchangeClient(), managed_domains=[])

    def test_onmicrosoft_domain_refused(self):
        with pytest.raises(ValueError, match="routing address"):
            MailboxAliasExecutor(
                FakeExchangeClient(), managed_domains=["acme.onmicrosoft.com"]
            )

    def test_blank_managed_domain_entry_refused(self):
        with pytest.raises(ValueError, match="blank entry"):
            MailboxAliasExecutor(
                FakeExchangeClient(), managed_domains=["  ", "acme.example"]
            )


class TestReconciliation:
    def test_missing_alias_is_added(self):
        client = FakeExchangeClient({"alice@acme.example": _mailbox()})
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        result = ex.create_or_update(_state("privacy@acme.example"))
        assert result.operation == OperationType.UPDATE
        assert client.calls == [
            ("alice@acme.example", ["privacy@acme.example"], [])
        ]

    def test_already_correct_is_a_no_op(self):
        client = FakeExchangeClient(
            {"alice@acme.example": _mailbox("privacy@acme.example")}
        )
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        result = ex.create_or_update(_state("privacy@acme.example"))
        assert result.operation == OperationType.NO_OP
        assert client.calls == []

    def test_undeclared_alias_in_a_managed_domain_is_removed(self):
        client = FakeExchangeClient(
            {"alice@acme.example": _mailbox("stale@acme.example")}
        )
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        ex.create_or_update(_state("privacy@acme.example"))
        assert client.calls == [
            ("alice@acme.example", ["privacy@acme.example"], ["stale@acme.example"])
        ]

    def test_routing_address_is_never_removed(self):
        client = FakeExchangeClient({
            "alice@acme.example": _mailbox(
                "alice@acme.onmicrosoft.com", "privacy@acme.example"
            )
        })
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        result = ex.create_or_update(_state("privacy@acme.example"))
        assert result.operation == OperationType.NO_OP
        assert client.calls == []

    def test_primary_among_the_secondaries_is_never_removed(self):
        # An AD-authored proxyAddresses list in a hybrid tenant can carry the
        # primary's address as a lowercase smtp: entry too. It is not declarable
        # as an alias, so without an explicit exclusion it lands in the removal
        # set — the one write this executor exists to prevent.
        client = FakeExchangeClient({
            "alice@acme.example": _mailbox(
                "alice@acme.example", "privacy@acme.example"
            )
        })
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        result = ex.create_or_update(_state("privacy@acme.example"))
        assert result.operation == OperationType.NO_OP
        assert client.calls == []

    def test_primary_among_the_secondaries_in_another_case_is_never_removed(self):
        # Same trap as above, but with the casing the client happens to apply
        # removed: the exclusion must be the executor's own, not one inherited
        # from ExchangeOnlineClient lowercasing everything on the way in.
        client = FakeExchangeClient({
            "alice@acme.example": MailboxAddresses(
                upn="alice@acme.example",
                primary="alice@acme.example",
                secondary=("Alice@acme.example", "privacy@acme.example"),
            )
        })
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        result = ex.create_or_update(_state("privacy@acme.example"))
        assert result.operation == OperationType.NO_OP
        assert client.calls == []

    def test_alias_equal_to_a_differently_cased_primary_is_refused(self):
        # The declaration-side half of the same exclusion: a primary handed
        # over in mixed case must still make the matching alias undeclarable.
        client = FakeExchangeClient({
            "alice@acme.example": MailboxAddresses(
                upn="alice@acme.example",
                primary="Alice@acme.example",
                secondary=(),
            )
        })
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        with pytest.raises(ValueError, match="primary address"):
            ex.create_or_update(_state("alice@acme.example"))

    @pytest.mark.parametrize(
        "present", ["Privacy@acme.example", "privacy@ACME.example"]
    )
    def test_declared_alias_already_present_in_another_case_is_left_alone(
        self, present
    ):
        # Two distinct failure shapes if the set arithmetic does not fold.
        # Mixed local part: the address passes the domain filter, so it lands
        # in the removable set under one casing while the declared alias is
        # missing under the other — a remove of a working address paired with
        # an add of the same one. Mixed domain: it fails the domain filter
        # entirely, so it looks absent and is spuriously added.
        client = FakeExchangeClient({"alice@acme.example": _mailbox(present)})
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        result = ex.create_or_update(_state("privacy@acme.example"))
        assert result.operation == OperationType.NO_OP
        assert client.calls == []

    def test_undeclared_alias_in_a_mixed_case_managed_domain_is_removed(self):
        # The other side of folding the scope filter, and a widening: pre-fold
        # this address failed the domain check and survived as unmanaged drift.
        # It is the same address as one in a managed domain, so it is in scope
        # and removable — intended, and pinned here because it is a delete.
        client = FakeExchangeClient(
            {"alice@acme.example": _mailbox("Old@ACME.example")}
        )
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        result = ex.create_or_update(_state())
        assert result.operation == OperationType.UPDATE
        assert client.calls == [("alice@acme.example", [], ["old@acme.example"])]

    def test_alias_on_an_unmanaged_domain_is_left_alone(self):
        client = FakeExchangeClient({
            "alice@acme.example": _mailbox("alice@legacy.example")
        })
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        result = ex.create_or_update(_state())
        assert result.operation == OperationType.NO_OP
        assert client.calls == []

    def test_declared_alias_outside_managed_domains_is_refused(self):
        client = FakeExchangeClient({"alice@acme.example": _mailbox()})
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        with pytest.raises(ValueError, match="outside the managed domains"):
            ex.create_or_update(_state("privacy@other.example"))

    def test_alias_equal_to_primary_is_refused(self):
        client = FakeExchangeClient({"alice@acme.example": _mailbox()})
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        with pytest.raises(ValueError, match="primary address"):
            ex.create_or_update(_state("alice@acme.example"))

    def test_missing_mailbox_raises_rather_than_creating(self):
        ex = MailboxAliasExecutor(FakeExchangeClient(), managed_domains=DOMAINS)
        with pytest.raises(ExchangeOnlineError, match="No mailbox"):
            ex.create_or_update(_state("privacy@acme.example"))

    def test_plan_on_a_missing_mailbox_raises_rather_than_proposing_a_create(self):
        ex = MailboxAliasExecutor(FakeExchangeClient(), managed_domains=DOMAINS)
        with pytest.raises(ExchangeOnlineError, match="No mailbox"):
            ex.plan([_state("privacy@acme.example")])

    def test_create_refuses_outright(self):
        ex = MailboxAliasExecutor(FakeExchangeClient(), managed_domains=DOMAINS)
        with pytest.raises(ExchangeOnlineError, match="never creates them"):
            ex.create(_state("privacy@acme.example"))

    def test_dry_run_over_a_missing_mailbox_raises(self):
        ex = MailboxAliasExecutor(
            FakeExchangeClient(), managed_domains=DOMAINS, dry_run=True
        )
        with pytest.raises(ExchangeOnlineError, match="No mailbox"):
            ex.create_or_update(_state("privacy@acme.example"))

    def test_dry_run_applies_nothing(self):
        client = FakeExchangeClient({"alice@acme.example": _mailbox()})
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS, dry_run=True)
        result = ex.create_or_update(_state("privacy@acme.example"))
        assert result.changes == {"add": ["privacy@acme.example"], "remove": []}
        assert client.calls == []

    def test_dry_run_delete_writes_nothing(self):
        # delete() reaches the write path through update() directly, so it
        # never passes the base class's create_or_update gate. Without a gate
        # inside update(), previewing a deprovisioning run deletes every
        # in-scope alias for real.
        client = FakeExchangeClient({
            "alice@acme.example": _mailbox(
                "privacy@acme.example", "stale@acme.example"
            )
        })
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS, dry_run=True)
        result = ex.delete(_state())
        assert result.operation == OperationType.DELETE
        assert result.changes == {
            "add": [],
            "remove": ["privacy@acme.example", "stale@acme.example"],
        }
        assert client.calls == []

    def test_dry_run_update_called_directly_writes_nothing(self):
        # The same hole one level up: any caller holding the executor can call
        # update() without going through create_or_update.
        client = FakeExchangeClient(
            {"alice@acme.example": _mailbox("stale@acme.example")}
        )
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS, dry_run=True)
        result = ex.update(_state("privacy@acme.example"))
        assert result.operation == OperationType.UPDATE
        assert result.changes == {
            "add": ["privacy@acme.example"],
            "remove": ["stale@acme.example"],
        }
        assert client.calls == []

    def test_plan_reports_without_applying(self):
        client = FakeExchangeClient({"alice@acme.example": _mailbox()})
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        plan = ex.plan([_state("privacy@acme.example")])
        assert len(plan.operations) == 1
        assert plan.operations[0].operation == OperationType.UPDATE
        assert client.calls == []

    def test_second_pass_over_an_applied_change_is_a_no_op(self):
        client = StatefulExchangeClient({"alice@acme.example": _mailbox()})
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)

        first = ex.create_or_update(_state("privacy@acme.example"))
        second = ex.create_or_update(_state("privacy@acme.example"))

        assert first.operation == OperationType.UPDATE
        assert second.operation == OperationType.NO_OP
        assert len(client.calls) == 1

    def test_a_failed_write_is_issued_once_and_not_retried(self):
        # Set-Mailbox is not idempotent — @{Add=} errors when the address is
        # already there and @{Remove=} when it is not — and the base class
        # classifies transience by substring over the whole pwsh output, so
        # Exchange's own prose ("…timeout") would decide to re-issue it.
        class FailingClient(FakeExchangeClient):
            def set_proxy_addresses(self, upn: str, *, add, remove) -> None:
                super().set_proxy_addresses(upn, add=add, remove=remove)
                raise ExchangeOnlineError(
                    "pwsh exited 1\n--- stderr ---\nSet-Mailbox: the operation "
                    "couldn't be performed. timeout"
                )

        client = FailingClient({"alice@acme.example": _mailbox()})
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        with pytest.raises(ExchangeOnlineError):
            ex.update(_state("privacy@acme.example"))
        assert len(client.calls) == 1

    def test_a_write_that_raises_still_invalidates_the_cache(self):
        # The write may have landed before the error. Holding pre-write state
        # for the rest of the run would have every later pass diff against a
        # mailbox that no longer looks like that.
        class CountingFailingClient(FakeExchangeClient):
            def __init__(self, mailboxes) -> None:
                super().__init__(mailboxes)
                self.reads = 0

            def get_mailbox_addresses(self, upn: str):
                self.reads += 1
                return super().get_mailbox_addresses(upn)

            def set_proxy_addresses(self, upn: str, *, add, remove) -> None:
                super().set_proxy_addresses(upn, add=add, remove=remove)
                raise ExchangeOnlineError("Set-Mailbox failed after writing")

        client = CountingFailingClient({"alice@acme.example": _mailbox()})
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        with pytest.raises(ExchangeOnlineError):
            ex.update(_state("privacy@acme.example"))
        reads_before = client.reads
        ex.exists(_state("privacy@acme.example"))
        assert client.reads == reads_before + 1

    def test_delete_removes_only_in_scope_aliases(self):
        client = FakeExchangeClient({
            "alice@acme.example": _mailbox(
                "stale@acme.example",
                "alice@acme.onmicrosoft.com",
                "alice@legacy.example",
            )
        })
        ex = MailboxAliasExecutor(client, managed_domains=DOMAINS)
        result = ex.delete(_state())
        assert result.operation == OperationType.DELETE
        assert client.calls == [
            ("alice@acme.example", [], ["stale@acme.example"])
        ]
