"""Linear workspace membership executor.

Derives desired state from access policies, diffs against current
Linear workspace state, and applies role + team membership changes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from iamkit.clients.linear import LinearClient, LinearTeam, LinearUser
from iamkit.executors.base import BaseExecutor, ExecutionPlan, ExecutionResult, OperationType
from iamkit.models.config import IAMConfig
from iamkit.models.enums import LinearRole

logger = logging.getLogger(__name__)

_ROLE_PRIORITY = {LinearRole.GUEST: 0, LinearRole.MEMBER: 1, LinearRole.ADMIN: 2}


@dataclass
class LinearMemberDesiredState:
    """Desired Linear state for a single user, derived from access policies."""

    email: str
    display_name: str
    role: LinearRole
    teams: list[str]


@dataclass
class _CurrentState:
    """Snapshot of current Linear workspace state."""

    users_by_email: dict[str, LinearUser] = field(default_factory=dict)
    teams_by_name: dict[str, LinearTeam] = field(default_factory=dict)


def resolve_desired_state(config: IAMConfig) -> list[LinearMemberDesiredState]:
    """Derive per-user Linear desired state from access policies.

    For each user with a LinearUserConfig:
      - Find all access policies where policy.group is in the user's
        group_memberships and policy.linear is set
      - effective_role = highest privilege across matching policies
      - effective_teams = union of all team lists
    """
    result: list[LinearMemberDesiredState] = []

    for user in config.users.values():
        linear_cfg = user.platform_config.linear
        if linear_cfg is None:
            continue
        if not user.account_enabled:
            continue

        effective_role = linear_cfg.role
        effective_teams: set[str] = set()

        for policy in config.access_policies.values():
            if policy.group is None or policy.linear is None:
                continue
            if policy.group in user.group_memberships:
                effective_teams.update(policy.linear.teams)
                if _ROLE_PRIORITY[policy.linear.role] > _ROLE_PRIORITY[effective_role]:
                    effective_role = policy.linear.role

        result.append(
            LinearMemberDesiredState(
                email=linear_cfg.email,
                display_name=user.display_name,
                role=effective_role,
                teams=sorted(effective_teams),
            )
        )

    return result


def collect_managed_teams(config: IAMConfig) -> set[str]:
    """All Linear teams referenced by any access policy — the reconciliation scope.

    Teams outside this set are never touched, so manually-managed teams
    survive reconciliation.
    """
    teams: set[str] = set()
    for policy in config.access_policies.values():
        if policy.linear is not None:
            teams.update(policy.linear.teams)
    return teams


class LinearMembershipExecutor(BaseExecutor[LinearMemberDesiredState]):
    """Reconciles Linear workspace membership against desired state."""

    def __init__(
        self,
        client: LinearClient,
        *,
        managed_teams: set[str],
        dry_run: bool = False,
        max_retries: int = 3,
    ) -> None:
        super().__init__(dry_run=dry_run, max_retries=max_retries)
        self._client = client
        self._managed_teams = managed_teams
        self._current: _CurrentState | None = None

    def get_resource_type(self) -> str:
        return "linear_member"

    def _get_resource_name(self, resource: LinearMemberDesiredState) -> str:
        return resource.email

    def _load_current_state(self) -> _CurrentState:
        if self._current is not None:
            return self._current
        users = self._client.list_users()
        teams = self._client.list_teams()
        self._current = _CurrentState(
            users_by_email={u.email: u for u in users if u.is_active},
            teams_by_name={t.name: t for t in teams},
        )
        return self._current

    def exists(self, resource: LinearMemberDesiredState) -> bool:
        state = self._load_current_state()
        return resource.email in state.users_by_email

    def _needs_update(self, resource: LinearMemberDesiredState) -> bool:
        return bool(self._get_changes(resource))

    def _get_changes(self, resource: LinearMemberDesiredState) -> dict[str, Any]:
        state = self._load_current_state()
        current_user = state.users_by_email.get(resource.email)
        if current_user is None:
            return {}

        changes: dict[str, Any] = {}

        # Role diff
        current_is_admin = current_user.is_admin
        desired_is_admin = resource.role == LinearRole.ADMIN
        if current_is_admin != desired_is_admin:
            current_role = "admin" if current_is_admin else "member"
            desired_role = "admin" if desired_is_admin else "member"
            changes["role"] = {"current": current_role, "desired": desired_role}

        # Team membership diff
        current_team_names: set[str] = set()
        for team in state.teams_by_name.values():
            if current_user.id in team.member_ids:
                current_team_names.add(team.name)

        desired_teams = set(resource.teams)
        teams_to_add = desired_teams - current_team_names
        teams_to_remove = (current_team_names & self._managed_teams) - desired_teams

        if teams_to_add:
            changes["teams_to_add"] = sorted(teams_to_add)
        if teams_to_remove:
            changes["teams_to_remove"] = sorted(teams_to_remove)

        return changes

    def plan(self, resources: list[LinearMemberDesiredState]) -> ExecutionPlan:
        plan = ExecutionPlan()
        for resource in resources:
            name = self._get_resource_name(resource)
            if not self.exists(resource):
                plan.add_operation(
                    operation=OperationType.CREATE,
                    resource_type=self.get_resource_type(),
                    resource_name=name,
                    changes={"role": resource.role.value, "teams": resource.teams},
                )
            else:
                changes = self._get_changes(resource)
                op = OperationType.UPDATE if changes else OperationType.NO_OP
                plan.add_operation(
                    operation=op,
                    resource_type=self.get_resource_type(),
                    resource_name=name,
                    changes=changes,
                )
        return plan

    def create(self, resource: LinearMemberDesiredState) -> ExecutionResult:
        # Inviting new users is out of scope for now — flag it.
        return ExecutionResult(
            success=False,
            operation=OperationType.SKIPPED,
            resource_type=self.get_resource_type(),
            resource_name=resource.email,
            message=f"User not in workspace — manual invite required for {resource.email}",
        )

    def update(self, resource: LinearMemberDesiredState) -> ExecutionResult:
        state = self._load_current_state()
        current_user = state.users_by_email[resource.email]
        changes = self._get_changes(resource)

        if not changes:
            return ExecutionResult(
                success=True,
                operation=OperationType.NO_OP,
                resource_type=self.get_resource_type(),
                resource_name=resource.email,
                message="Already in desired state",
            )

        if self.dry_run:
            return ExecutionResult(
                success=True,
                operation=OperationType.UPDATE,
                resource_type=self.get_resource_type(),
                resource_name=resource.email,
                message=f"Would update: {changes}",
                changes=changes,
            )

        # Apply role change
        if "role" in changes:
            desired_admin = changes["role"]["desired"] == "admin"
            self.execute_with_retry(
                self._client.update_user_role,
                current_user.id,
                admin=desired_admin,
            )

        # Apply team additions
        for team_name in changes.get("teams_to_add", []):
            team = state.teams_by_name[team_name]
            self.execute_with_retry(
                self._client.add_team_member,
                team.id,
                current_user.id,
            )

        # Apply team removals
        for team_name in changes.get("teams_to_remove", []):
            team = state.teams_by_name[team_name]
            self.execute_with_retry(
                self._client.remove_team_member,
                team.id,
                current_user.id,
            )

        return ExecutionResult(
            success=True,
            operation=OperationType.UPDATE,
            resource_type=self.get_resource_type(),
            resource_name=resource.email,
            message=f"Applied: {changes}",
            changes=changes,
        )

    def delete(self, resource: LinearMemberDesiredState) -> ExecutionResult:
        # Deactivation is out of scope for now.
        return ExecutionResult(
            success=False,
            operation=OperationType.SKIPPED,
            resource_type=self.get_resource_type(),
            resource_name=resource.email,
            message="User deactivation not yet implemented",
        )
