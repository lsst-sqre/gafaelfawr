"""Test quota handling."""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient

from gafaelfawr.config import Config
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


@pytest.mark.asyncio
async def test_rate_limit_override(
    client: AsyncClient, factory: Factory
) -> None:
    config = await reconfigure("github-quota", factory)
    assert config.quota
    token_data = await create_session_token(
        factory,
        group_names=["foo"],
        scopes={"admin:token", "read:all"},
    )
    assert token_data.groups
    default_quota = config.quota.calculate_quota({"foo"})
    assert default_quota
    headers = {"Authorization": f"bearer {token_data.token}"}

    overrides: dict[str, Any] = {
        "bypass": [],
        "default": {"api": {"test": 10}},
        "groups": {},
    }
    r = await client.put(
        "/auth/api/v1/quota-overrides", json=overrides, headers=headers
    )
    assert r.status_code == 200
    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "test"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.headers["X-RateLimit-Limit"] == "10"
    assert r.headers["X-RateLimit-Remaining"] == "9"

    r = await client.get("/auth/api/v1/user-info", headers=headers)
    expected_user_info: dict[str, Any] = {
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
            "api": {"datalinker": 1000, "test": 10},
            "notebook": {"cpu": 8.0, "memory": 8.0, "spawn": True},
        },
    }
    assert r.json() == expected_user_info

    overrides["default"]["notebook"] = {"cpu": 1, "memory": 1, "spawn": False}
    r = await client.put(
        "/auth/api/v1/quota-overrides", json=overrides, headers=headers
    )
    assert r.status_code == 200
    expected_user_info["quota"]["notebook"] = overrides["default"]["notebook"]
    r = await client.get("/auth/api/v1/user-info", headers=headers)
    assert r.json() == expected_user_info

    overrides["bypass"] = ["foo"]
    r = await client.put(
        "/auth/api/v1/quota-overrides", json=overrides, headers=headers
    )
    assert r.status_code == 200
    expected_user_info["quota"] = {"api": {}}
    r = await client.get("/auth/api/v1/user-info", headers=headers)
    assert r.json() == expected_user_info

    # Return to normal behavior by deleting the overrides.
    r = await client.delete("/auth/api/v1/quota-overrides", headers=headers)
    assert r.status_code == 204
    expected_user_info["quota"] = default_quota.model_dump(mode="json")
    r = await client.get("/auth/api/v1/user-info", headers=headers)
    assert r.json() == expected_user_info


@pytest.mark.asyncio
async def test_rate_limit_override_only(
    client: AsyncClient, factory: Factory, config: Config
) -> None:
    """Check behavior when there is an override and no base quota."""
    assert not config.quota
    token_data = await create_session_token(
        factory, group_names=["admin"], scopes={"admin:token", "read:all"}
    )
    assert token_data.groups
    headers = {"Authorization": f"bearer {token_data.token}"}

    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "test"},
        headers=headers,
    )
    assert r.status_code == 200
    assert "X-RateLimit-Limit" not in r.headers

    overrides: dict[str, Any] = {
        "bypass": [],
        "default": {
            "notebook": {"cpu": 1.0, "memory": 4.0, "spawn": True},
            "api": {"test": 10},
        },
        "groups": {},
    }
    r = await client.put(
        "/auth/api/v1/quota-overrides", json=overrides, headers=headers
    )
    assert r.status_code == 200
    assert r.json() == overrides
    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "test"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.headers["X-RateLimit-Limit"] == "10"
    assert r.headers["X-RateLimit-Remaining"] == "9"
    assert r.headers["X-RateLimit-Used"] == "1"
    assert r.headers["X-RateLimit-Resource"] == "test"

    r = await client.get("/auth/api/v1/user-info", headers=headers)
    expected_user_info = {
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
            "api": {"test": 10},
            "notebook": {"cpu": 1.0, "memory": 4.0, "spawn": True},
        },
    }
    assert r.json() == expected_user_info

    # Add the user's group to bypass.
    overrides["bypass"] = ["admin"]
    r = await client.put(
        "/auth/api/v1/quota-overrides", json=overrides, headers=headers
    )
    assert r.status_code == 200
    assert r.json() == overrides
    expected_user_info["quota"] = {"api": {}}
    r = await client.get("/auth/api/v1/user-info", headers=headers)
    assert r.status_code == 200
    assert r.json() == expected_user_info


@pytest.mark.asyncio
async def test_permissions(client: AsyncClient, factory: Factory) -> None:
    user_token_data = await create_session_token(
        factory, group_names=["foo"], scopes=set()
    )
    user_headers = {"Authorization": f"bearer {user_token_data.token}"}
    admin_token_data = await create_session_token(
        factory, group_names=["admin"], scopes={"admin:token"}
    )
    admin_headers = {"Authorization": f"bearer {admin_token_data.token}"}

    r = await client.get("/auth/api/v1/quota-overrides", headers=user_headers)
    assert r.status_code == 404
    overrides: dict[str, Any] = {
        "bypass": [],
        "default": {"api": {"test": 10}},
        "groups": {},
    }
    r = await client.put(
        "/auth/api/v1/quota-overrides", json=overrides, headers=user_headers
    )
    assert r.status_code == 403
    r = await client.put(
        "/auth/api/v1/quota-overrides", json=overrides, headers=admin_headers
    )
    assert r.status_code == 200
    r = await client.get("/auth/api/v1/quota-overrides", headers=user_headers)
    assert r.status_code == 200
    assert r.json() == overrides
    r = await client.delete(
        "/auth/api/v1/quota-overrides", headers=user_headers
    )
    assert r.status_code == 403
    r = await client.delete(
        "/auth/api/v1/quota-overrides", headers=admin_headers
    )
    assert r.status_code == 204
