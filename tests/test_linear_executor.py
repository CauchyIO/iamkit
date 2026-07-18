"""Tests for Linear desired-state resolution and reconciliation scoping."""

from iamkit.clients.linear import LinearTeam, LinearUser
from iamkit.executors.linear import (
    LinearMembershipExecutor,
    collect_managed_teams,
    resolve_desired_state,
)
from iamkit.models.access import AccessPolicy, LinearAccessSpec
from iamkit.models.config import IAMConfig
from iamkit.models.enums import LinearRole
from iamkit.models.principals import LinearUserConfig, PlatformConfig, User


def _user(role: LinearRole, groups: list[str] | None = None) -> User:
    return User(
        name="alice", display_name="Alice Anvil", email="alice@acme.example",
        usage_location="NL", group_memberships=groups or [],
        platform_config=PlatformConfig(
            linear=LinearUserConfig(email="alice@acme.example", role=role)
        ),
    )


def test_configured_guest_role_is_respected():
    config = IAMConfig(users={"alice": _user(LinearRole.GUEST)})
    desired = resolve_desired_state(config)
    assert desired[0].role == LinearRole.GUEST


def test_collect_managed_teams():
    config = IAMConfig(
        access_policies={
            "eng": AccessPolicy(
                name="eng", linear=LinearAccessSpec(teams=["Eng", "Design"]),
            )
        }
    )
    assert collect_managed_teams(config) == {"Eng", "Design"}


class StubLinearClient:
    def __init__(self, users: list[LinearUser], teams: list[LinearTeam]) -> None:
        self._users, self._teams = users, teams

    def list_users(self) -> list[LinearUser]:
        return self._users

    def list_teams(self) -> list[LinearTeam]:
        return self._teams


def test_unmanaged_teams_are_never_removed():
    current_user = LinearUser(
        id="u1", name="Alice", email="alice@acme.example",
        is_admin=False, is_guest=False, is_active=True,
    )
    teams = [
        LinearTeam(id="t1", name="Eng", member_ids=["u1"]),
        LinearTeam(id="t2", name="Random", member_ids=["u1"]),
    ]
    executor = LinearMembershipExecutor(
        client=StubLinearClient([current_user], teams),
        managed_teams={"Eng", "Design"},
    )
    config = IAMConfig(users={"alice": _user(LinearRole.MEMBER)})
    desired = resolve_desired_state(config)[0]  # no policies -> no teams
    changes = executor._get_changes(desired)
    assert changes.get("teams_to_remove") == ["Eng"]  # "Random" untouched
