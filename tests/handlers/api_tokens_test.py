"""Tests for the ``/auth/api/v1/users/*/tokens`` and related routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest

from gafaelfawr.models.token import TokenGroup, TokenUserInfo

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_token_info(setup: SetupTest) -> None:
    userinfo = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=45613,
        groups=[TokenGroup(name="foo", id=12313)],
    )
    token_manager = setup.factory.create_token_manager()
    session_token = await token_manager.create_session_token(userinfo)

    r = await setup.client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {session_token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data == {
        "username": "example",
        "token_type": "session",
        "scopes": [],
        "created": ANY,
        "expires": ANY,
    }
    now = datetime.now(tz=timezone.utc)
    created = datetime.fromtimestamp(data["created"], tz=timezone.utc)
    assert now - timedelta(seconds=2) <= created <= now
    expires = created + timedelta(minutes=setup.config.issuer.exp_minutes)
    assert datetime.fromtimestamp(data["expires"], tz=timezone.utc) == expires

    r = await setup.client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {session_token}"},
    )
    assert r.status_code == 200
    session_user_info = r.json()
    assert session_user_info == {
        "username": "example",
        "name": "Example Person",
        "uid": 45613,
        "groups": [
            {
                "name": "foo",
                "id": 12313,
            }
        ],
    }

    # Check the same with a user token, which has some additional associated
    # data.
    expires = now + timedelta(days=100)
    data = await token_manager.get_data(session_token)
    user_token = await token_manager.create_user_token(
        data, token_name="some-token", scopes=["exec:admin"], expires=expires
    )

    r = await setup.client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {user_token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data == {
        "username": "example",
        "token_type": "user",
        "token_name": "some-token",
        "scopes": ["exec:admin"],
        "created": ANY,
        "expires": int(expires.timestamp()),
    }

    r = await setup.client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {user_token}"},
    )
    assert r.status_code == 200
    assert r.json() == session_user_info
