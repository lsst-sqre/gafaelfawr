"""Test quota handling."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient

from gafaelfawr.factory import Factory
from gafaelfawr.models.token import TokenGroup, TokenUserInfo

from ..support.config import reconfigure


@pytest.mark.asyncio
async def test_info(
    client: AsyncClient, factory: Factory, tmp_path: Path
) -> None:
    await reconfigure(tmp_path, "github-quota", factory)
    user_info = TokenUserInfo(
        username="example", groups=[TokenGroup(name="bar", id=12312)]
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        token = await token_service.create_session_token(
            user_info, scopes=["user:token"], ip_address="127.0.0.1"
        )

    r = await client.get(
        "/auth/api/v1/user-info", headers={"Authorization": f"bearer {token}"}
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": "example",
        "groups": [{"name": "bar", "id": 12312}],
        "quota": {
            "api": {"datalinker": 1000},
            "notebook": {"cpu": 8.0, "memory": 4.0},
        },
    }

    user_info.groups = [TokenGroup(name="foo", id=12313)]
    async with factory.session.begin():
        token = await token_service.create_session_token(
            user_info, scopes=["user:token"], ip_address="127.0.0.1"
        )

    r = await client.get(
        "/auth/api/v1/user-info", headers={"Authorization": f"bearer {token}"}
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": "example",
        "groups": [{"name": "foo", "id": 12313}],
        "quota": {
            "api": {"datalinker": 1000},
            "notebook": {"cpu": 8.0, "memory": 8.0},
        },
    }
