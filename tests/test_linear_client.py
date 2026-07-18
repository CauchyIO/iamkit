"""Tests for the Linear GraphQL client using a mock transport."""

import json

import httpx
import pytest

from iamkit.clients.linear import LinearAPIError, LinearClient


def _user_node(i: int) -> dict:
    return {
        "id": f"u{i}", "name": f"User {i}", "email": f"u{i}@acme.example",
        "active": True, "admin": False, "guest": False,
    }


def _paged_users_handler(request: httpx.Request) -> httpx.Response:
    variables = json.loads(request.content).get("variables") or {}
    if variables.get("after") is None:
        nodes, page = [_user_node(1), _user_node(2)], {"hasNextPage": True, "endCursor": "c2"}
    else:
        assert variables["after"] == "c2"
        nodes, page = [_user_node(3)], {"hasNextPage": False, "endCursor": None}
    return httpx.Response(
        200, json={"data": {"users": {"nodes": nodes, "pageInfo": page}}}
    )


def test_list_users_follows_pagination():
    client = LinearClient(
        api_key="test", transport=httpx.MockTransport(_paged_users_handler)
    )
    users = client.list_users()
    assert [u.id for u in users] == ["u1", "u2", "u3"]


def test_list_teams_raises_on_truncated_members():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"teams": {
            "nodes": [{
                "id": "t1", "name": "Eng",
                "members": {
                    "nodes": [{"id": "u1"}],
                    "pageInfo": {"hasNextPage": True, "endCursor": "x"},
                },
            }],
            "pageInfo": {"hasNextPage": False, "endCursor": None},
        }}})

    client = LinearClient(api_key="test", transport=httpx.MockTransport(handler))
    with pytest.raises(LinearAPIError, match="more than 250 members"):
        client.list_teams()


def test_update_user_role_raises_when_success_false():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"data": {"userUpdate": {"success": False}}}
        )

    client = LinearClient(api_key="test", transport=httpx.MockTransport(handler))
    with pytest.raises(LinearAPIError, match="userUpdate"):
        client.update_user_role("u1", admin=True)
