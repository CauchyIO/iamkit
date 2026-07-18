"""Linear GraphQL API client for workspace membership management."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

LINEAR_API_URL = "https://api.linear.app/graphql"


@dataclass
class LinearUser:
    """A Linear workspace member."""

    id: str
    name: str
    email: str
    is_admin: bool
    is_guest: bool
    is_active: bool


@dataclass
class LinearTeam:
    """A Linear team with its member IDs."""

    id: str
    name: str
    member_ids: list[str]


class LinearClient:
    """Thin wrapper around the Linear GraphQL API.

    Auth via LINEAR_API_KEY env var (passed as Bearer token).
    """

    def __init__(
        self,
        api_key: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._api_key = api_key or os.environ["LINEAR_API_KEY"]
        self._http = httpx.Client(
            base_url=LINEAR_API_URL,
            headers={
                "Authorization": self._api_key,
                "Content-Type": "application/json",
            },
            timeout=30,
            transport=transport,
        )

    def _query(self, query: str, variables: dict | None = None) -> dict:
        payload: dict = {"query": query}
        if variables:
            payload["variables"] = variables
        resp = self._http.post("", json=payload)
        resp.raise_for_status()
        body = resp.json()
        if "errors" in body:
            raise LinearAPIError(body["errors"])
        return body["data"]

    # -- Queries --

    def list_users(self) -> list[LinearUser]:
        users: list[LinearUser] = []
        cursor: str | None = None
        while True:
            data = self._query(
                """
                query($after: String) {
                    users(first: 100, after: $after) {
                        nodes { id name email active admin guest }
                        pageInfo { hasNextPage endCursor }
                    }
                }
                """,
                variables={"after": cursor},
            )
            conn = data["users"]
            users.extend(
                LinearUser(
                    id=n["id"],
                    name=n["name"],
                    email=n["email"],
                    is_admin=n["admin"],
                    is_guest=n.get("guest", False),
                    is_active=n["active"],
                )
                for n in conn["nodes"]
            )
            if not conn["pageInfo"]["hasNextPage"]:
                return users
            cursor = conn["pageInfo"]["endCursor"]

    def list_teams(self) -> list[LinearTeam]:
        teams: list[LinearTeam] = []
        cursor: str | None = None
        while True:
            data = self._query(
                """
                query($after: String) {
                    teams(first: 100, after: $after) {
                        nodes {
                            id
                            name
                            members(first: 250) {
                                nodes { id }
                                pageInfo { hasNextPage endCursor }
                            }
                        }
                        pageInfo { hasNextPage endCursor }
                    }
                }
                """,
                variables={"after": cursor},
            )
            conn = data["teams"]
            for n in conn["nodes"]:
                if n["members"]["pageInfo"]["hasNextPage"]:
                    raise LinearAPIError(
                        f"Team '{n['name']}' has more than 250 members; "
                        "refusing to reconcile against a truncated member list"
                    )
                teams.append(
                    LinearTeam(
                        id=n["id"],
                        name=n["name"],
                        member_ids=[m["id"] for m in n["members"]["nodes"]],
                    )
                )
            if not conn["pageInfo"]["hasNextPage"]:
                return teams
            cursor = conn["pageInfo"]["endCursor"]

    # -- Mutations --

    def update_user_role(self, user_id: str, *, admin: bool) -> None:
        """Promote or demote a workspace member."""
        data = self._query(
            """
            mutation($id: String!, $admin: Boolean!) {
                userUpdate(id: $id, input: { admin: $admin }) {
                    success
                }
            }
            """,
            variables={"id": user_id, "admin": admin},
        )
        if not data["userUpdate"]["success"]:
            raise LinearAPIError(f"userUpdate reported failure for user {user_id}")
        logger.info("Updated user %s: admin=%s", user_id, admin)

    def add_team_member(self, team_id: str, user_id: str) -> None:
        data = self._query(
            """
            mutation($teamId: String!, $userId: String!) {
                teamMembershipCreate(input: { teamId: $teamId, userId: $userId }) {
                    success
                }
            }
            """,
            variables={"teamId": team_id, "userId": user_id},
        )
        if not data["teamMembershipCreate"]["success"]:
            raise LinearAPIError(
                f"teamMembershipCreate reported failure for user {user_id} in team {team_id}"
            )
        logger.info("Added user %s to team %s", user_id, team_id)

    def remove_team_member(self, team_id: str, user_id: str) -> None:
        # Linear requires the membership ID, not user+team.
        # First find the membership, then delete it.
        data = self._query(
            """
            query($teamId: String!) {
                team(id: $teamId) {
                    memberships {
                        nodes { id user { id } }
                    }
                }
            }
            """,
            variables={"teamId": team_id},
        )
        membership_id: str | None = None
        for m in data["team"]["memberships"]["nodes"]:
            if m["user"]["id"] == user_id:
                membership_id = m["id"]
                break
        if membership_id is None:
            raise LinearAPIError(
                f"No membership found for user {user_id} in team {team_id}"
            )
        data = self._query(
            """
            mutation($id: String!) {
                teamMembershipDelete(id: $id) {
                    success
                }
            }
            """,
            variables={"id": membership_id},
        )
        if not data["teamMembershipDelete"]["success"]:
            raise LinearAPIError(
                f"teamMembershipDelete reported failure for membership {membership_id}"
            )
        logger.info("Removed user %s from team %s", user_id, team_id)

    def close(self) -> None:
        self._http.close()


class LinearAPIError(Exception):
    """Raised when the Linear API returns errors."""
