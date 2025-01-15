"""Test quota handling."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from gafaelfawr.factory import Factory
from gafaelfawr.models.token import TokenUserInfo
from gafaelfawr.models.userinfo import Group

from ..support.config import reconfigure
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_info(client: AsyncClient, factory: Factory) -> None:
    await reconfigure("github-quota", factory)
    user_info = TokenUserInfo(
        username="example", groups=[Group(name="bar", id=12312)]
    )
    token_service = factory.create_token_service()
    token = await token_service.create_session_token(
        user_info, scopes={"user:token"}, ip_address="127.0.0.1"
    )

    r = await client.get(
        "/auth/api/v1/user-info", headers={"Authorization": f"bearer {token}"}
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": "example",
        "groups": [{"name": "bar", "id": 12312}],
        "quota": {
            "api": {"datalinker": 1000, "test": 1},
            "notebook": {"cpu": 8.0, "memory": 4.0, "spawn": True},
        },
    }

    user_info.groups = [Group(name="foo", id=12313)]
    token = await token_service.create_session_token(
        user_info, scopes={"user:token"}, ip_address="127.0.0.1"
    )

    r = await client.get(
        "/auth/api/v1/user-info", headers={"Authorization": f"bearer {token}"}
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": "example",
        "groups": [{"name": "foo", "id": 12313}],
        "quota": {
            "api": {"datalinker": 1000, "test": 2},
            "notebook": {"cpu": 8.0, "memory": 8.0, "spawn": True},
        },
    }


@pytest.mark.asyncio
async def test_no_spawn(client: AsyncClient, factory: Factory) -> None:
    await reconfigure("github-quota", factory)
    token_data = await create_session_token(
        factory, group_names=["blocked", "bar"], scopes={"read:all"}
    )
    assert token_data.groups

    r = await client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {token_data.token}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": token_data.username,
        "name": token_data.name,
        "email": token_data.email,
        "uid": token_data.uid,
        "gid": token_data.gid,
        "groups": [
            g.model_dump(mode="json")
            for g in sorted(token_data.groups, key=lambda g: g.name)
        ],
        "quota": {
            "api": {"datalinker": 1000, "test": 1},
            "notebook": {"cpu": 8.0, "memory": 4.0, "spawn": False},
        },
    }
