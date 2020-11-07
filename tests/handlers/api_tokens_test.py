"""Tests for the ``/auth/api/v1/users/*/tokens`` and related routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest

from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.models.state import State
from gafaelfawr.models.token import Token, TokenGroup, TokenUserInfo

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_create_delete_modify(setup: SetupTest) -> None:
    userinfo = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=45613,
        groups=[TokenGroup(name="foo", id=12313)],
    )
    token_manager = setup.factory.create_token_manager()
    session_token = await token_manager.create_session_token(
        userinfo, scopes=["read:all", "exec:admin"]
    )
    state = State(token=session_token)

    r = await setup.client.get(
        "/auth/api/v1/login", cookies={COOKIE_NAME: state.as_cookie()}
    )
    assert r.status_code == 200
    csrf = r.json()["csrf"]

    now = datetime.now(tz=timezone.utc)
    expires = now + timedelta(days=100)
    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"X-CSRF-Token": csrf},
        cookies={COOKIE_NAME: state.as_cookie()},
        json={
            "token_name": "some token",
            "scopes": ["read:all"],
            "expires": int(expires.timestamp()),
        },
    )
    assert r.status_code == 201
    assert r.json() == {"token": ANY}
    user_token = Token.from_str(r.json()["token"])
    token_url = r.headers["Location"]
    assert token_url == f"/auth/api/v1/users/example/tokens/{user_token.key}"

    r = await setup.client.get(
        token_url, cookies={COOKIE_NAME: state.as_cookie()}
    )
    assert r.status_code == 200
    info = r.json()
    assert info == {
        "token": user_token.key,
        "username": "example",
        "token_name": "some token",
        "token_type": "user",
        "scopes": ["read:all"],
        "created": ANY,
        "expires": int(expires.timestamp()),
    }

    # Check that this is the same information as is returned by the token-info
    # route.
    r = await setup.client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {user_token}"},
    )
    assert r.status_code == 200
    assert r.json() == info

    # Listing all tokens for this user should return the user token and a
    # session token.
    r = await setup.client.get(
        "/auth/api/v1/users/example/tokens",
        cookies={COOKIE_NAME: state.as_cookie()},
    )
    assert r.status_code == 200
    assert r.json() == sorted(
        [
            {
                "token": session_token.key,
                "username": "example",
                "token_type": "session",
                "scopes": ["exec:admin", "read:all"],
                "created": ANY,
                "expires": ANY,
            },
            info,
        ],
        key=lambda t: t["token"],
    )

    # Change the name, scope, and expiration of the token.
    expires = now + timedelta(days=200)
    r = await setup.client.patch(
        token_url,
        headers={"X-CSRF-Token": csrf},
        cookies={COOKIE_NAME: state.as_cookie()},
        json={
            "token_name": "happy token",
            "scopes": ["exec:admin"],
            "expires": int(expires.timestamp()),
        },
    )
    assert r.status_code == 201
    assert r.json() == {
        "token": user_token.key,
        "username": "example",
        "token_name": "happy token",
        "token_type": "user",
        "scopes": ["exec:admin"],
        "created": ANY,
        "expires": int(expires.timestamp()),
    }

    # Delete the token.
    r = await setup.client.delete(
        token_url,
        headers={"X-CSRF-Token": csrf},
        cookies={COOKIE_NAME: state.as_cookie()},
    )
    assert r.status_code == 204
    r = await setup.client.get(
        token_url, cookies={COOKIE_NAME: state.as_cookie()}
    )
    assert r.status_code == 404

    # Deleting again should return 404.
    r = await setup.client.delete(
        token_url,
        headers={"X-CSRF-Token": csrf},
        cookies={COOKIE_NAME: state.as_cookie()},
    )
    assert r.status_code == 404

    # This user should now have only one token.
    r = await setup.client.get(
        "/auth/api/v1/users/example/tokens",
        cookies={COOKIE_NAME: state.as_cookie()},
    )
    assert r.status_code == 200
    assert len(r.json()) == 1


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
        "token": session_token.key,
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
        "token": user_token.key,
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

    # Test getting a list of tokens for a user.
    state = State(token=session_token)
    r = await setup.client.get(
        "/auth/api/v1/users/example/tokens",
        cookies={COOKIE_NAME: state.as_cookie()},
    )


@pytest.mark.asyncio
async def test_auth_required(setup: SetupTest) -> None:
    userinfo = TokenUserInfo(
        username="example", name="Example Person", uid=45613
    )
    token_manager = setup.factory.create_token_manager()
    token = await token_manager.create_session_token(userinfo)
    state = State(token=token)

    r = await setup.client.get(
        "/auth/api/v1/login", cookies={COOKIE_NAME: state.as_cookie()}
    )
    assert r.status_code == 200
    csrf = r.json()["csrf"]

    # Replace the cookie with one containing the CSRF token but not the
    # authentication token.
    state = State(csrf=csrf)
    del setup.client.cookies[COOKIE_NAME]
    setup.client.cookies[COOKIE_NAME] = state.as_cookie()

    r = await setup.client.get(
        "/auth/api/v1/users/example/tokens", allow_redirects=False
    )
    assert r.status_code == 307

    r = await setup.client.get(
        "/auth/api/v1/users/example/tokens",
        headers={"Authorization": f"bearer {token}"},
        allow_redirects=False,
    )
    assert r.status_code == 307

    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
        allow_redirects=False,
    )
    assert r.status_code == 307

    r = await setup.client.get(
        f"/auth/api/v1/users/example/tokens/{token.key}", allow_redirects=False
    )
    assert r.status_code == 307

    r = await setup.client.delete(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"X-CSRF-Token": csrf},
        allow_redirects=False,
    )
    assert r.status_code == 307

    r = await setup.client.patch(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
        allow_redirects=False,
    )
    assert r.status_code == 307


@pytest.mark.asyncio
async def test_csrf_required(setup: SetupTest) -> None:
    userinfo = TokenUserInfo(
        username="example", name="Example Person", uid=45613
    )
    token_manager = setup.factory.create_token_manager()
    token = await token_manager.create_session_token(userinfo)
    state = State(token=token)

    r = await setup.client.get(
        "/auth/api/v1/login", cookies={COOKIE_NAME: state.as_cookie()}
    )
    assert r.status_code == 200
    csrf = r.json()["csrf"]

    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens",
        cookies={COOKIE_NAME: state.as_cookie()},
        json={"token_name": "some token"},
    )
    assert r.status_code == 403

    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens",
        cookies={COOKIE_NAME: state.as_cookie()},
        headers={"X-CSRF-Token": f"XXX{csrf}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 403

    r = await setup.client.delete(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        cookies={COOKIE_NAME: state.as_cookie()},
    )
    assert r.status_code == 403

    r = await setup.client.delete(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
        cookies={COOKIE_NAME: state.as_cookie()},
    )
    assert r.status_code == 403

    r = await setup.client.patch(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        cookies={COOKIE_NAME: state.as_cookie()},
        json={"token_name": "some token"},
    )
    assert r.status_code == 403

    r = await setup.client.patch(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
        cookies={COOKIE_NAME: state.as_cookie()},
        json={"token_name": "some token"},
    )
    assert r.status_code == 403
