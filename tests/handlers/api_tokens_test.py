"""Tests for the ``/auth/api/v1/users/*/tokens`` and related routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest

from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.models.state import State
from gafaelfawr.models.token import Token, TokenGroup, TokenUserInfo
from tests.support.constants import TEST_HOSTNAME

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_create_delete_modify(setup: SetupTest) -> None:
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=45613,
        groups=[TokenGroup(name="foo", id=12313)],
    )
    token_service = setup.factory.create_token_service()
    session_token = await token_service.create_session_token(
        user_info, scopes=["read:all", "exec:admin"]
    )
    setup.login(session_token)

    r = await setup.client.get("/auth/api/v1/login")
    assert r.status_code == 200
    csrf = r.json()["csrf"]

    now = datetime.now(tz=timezone.utc)
    expires = now + timedelta(days=100)
    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"X-CSRF-Token": csrf},
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

    r = await setup.client.get(token_url)
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
    # route.  This is a bit tricky to do since the cookie will take precedence
    # over the Authorization header, but we can't just delete the cookie since
    # we'll lose the CSRF token.  Save the cookie and delete it, and then
    # later restore it.
    cookie = setup.client.cookies.pop(COOKIE_NAME)
    r = await setup.client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {user_token}"},
    )
    assert r.status_code == 200
    assert r.json() == info
    setup.client.cookies.set(COOKIE_NAME, cookie, domain=TEST_HOSTNAME)

    # Listing all tokens for this user should return the user token and a
    # session token.
    r = await setup.client.get("/auth/api/v1/users/example/tokens")
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
    r = await setup.client.delete(token_url, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 204
    r = await setup.client.get(token_url)
    assert r.status_code == 404

    # Deleting again should return 404.
    r = await setup.client.delete(token_url, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 404

    # This user should now have only one token.
    r = await setup.client.get("/auth/api/v1/users/example/tokens")
    assert r.status_code == 200
    assert len(r.json()) == 1


@pytest.mark.asyncio
async def test_token_info(setup: SetupTest) -> None:
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=45613,
        groups=[TokenGroup(name="foo", id=12313)],
    )
    token_service = setup.factory.create_token_service()
    session_token = await token_service.create_session_token(user_info)

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
    data = await token_service.get_data(session_token)
    user_token = await token_service.create_user_token(
        data,
        data.username,
        token_name="some-token",
        scopes=["exec:admin"],
        expires=expires,
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
    user_info = TokenUserInfo(
        username="example", name="Example Person", uid=45613
    )
    token_service = setup.factory.create_token_service()
    token = await token_service.create_session_token(user_info)
    setup.login(token)
    state = State(token=token)

    r = await setup.client.get("/auth/api/v1/login")
    assert r.status_code == 200
    csrf = r.json()["csrf"]

    # Replace the cookie with one containing the CSRF token but not the
    # authentication token.
    state = State(csrf=csrf)
    del setup.client.cookies[COOKIE_NAME]
    setup.client.cookies[COOKIE_NAME] = state.as_cookie()

    r = await setup.client.get("/auth/api/v1/users/example/tokens")
    assert r.status_code == 401

    r = await setup.client.get(
        "/auth/api/v1/users/example/tokens",
        headers={"Authorization": f"bearer {token}"},
    )
    assert r.status_code == 401

    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 401

    r = await setup.client.get(
        f"/auth/api/v1/users/example/tokens/{token.key}"
    )
    assert r.status_code == 401

    r = await setup.client.delete(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 401

    r = await setup.client.patch(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_csrf_required(setup: SetupTest) -> None:
    token_data = await setup.create_session_token()
    setup.login(token_data.token)
    token_service = setup.factory.create_token_service()
    user_token = await token_service.create_user_token(
        token_data, token_data.username, token_name="foo"
    )

    r = await setup.client.get("/auth/api/v1/login")
    assert r.status_code == 200
    csrf = r.json()["csrf"]

    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens", json={"token_name": "some token"}
    )
    assert r.status_code == 403

    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 403

    r = await setup.client.delete(
        f"/auth/api/v1/users/example/tokens/{user_token.key}"
    )
    assert r.status_code == 403

    r = await setup.client.delete(
        f"/auth/api/v1/users/example/tokens/{user_token.key}",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
    )
    assert r.status_code == 403

    r = await setup.client.patch(
        f"/auth/api/v1/users/example/tokens/{user_token.key}",
        json={"token_name": "some token"},
    )
    assert r.status_code == 403

    r = await setup.client.patch(
        f"/auth/api/v1/users/example/tokens/{user_token.key}",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_modify_nonuser(setup: SetupTest) -> None:
    token_data = await setup.create_session_token()
    token = token_data.token
    setup.login(token)

    r = await setup.client.get("/auth/api/v1/login")
    assert r.status_code == 200
    csrf = r.json()["csrf"]

    r = await setup.client.patch(
        f"/auth/api/v1/users/{token_data.username}/tokens/{token.key}",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "happy token"},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"


@pytest.mark.asyncio
async def test_wrong_user(setup: SetupTest) -> None:
    token_data = await setup.create_session_token()
    setup.login(token_data.token)
    token_service = setup.factory.create_token_service()
    user_info = TokenUserInfo(
        username="other-person", name="Some Other Person", uid=137123
    )
    other_session_token = await token_service.create_session_token(user_info)
    other_session_data = await token_service.get_data(other_session_token)
    assert other_session_data
    other_token = await token_service.create_user_token(
        other_session_data, "other-person", token_name="foo"
    )

    r = await setup.client.get("/auth/api/v1/login")
    assert r.status_code == 200
    csrf = r.json()["csrf"]

    # Get a token list.
    r = await setup.client.get("/auth/api/v1/users/other-person/tokens")
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"

    # Create a new user token.
    r = await setup.client.post(
        "/auth/api/v1/users/other-person/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "happy token"},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"

    # Get an individual token.
    r = await setup.client.get(
        f"/auth/api/v1/users/other-person/tokens/{other_token.key}"
    )
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"

    # Ensure you can't see someone else's token under your username either.
    r = await setup.client.get(
        f"/auth/api/v1/users/{token_data.username}/tokens/{other_token.key}"
    )
    assert r.status_code == 404

    # Delete a token.
    r = await setup.client.delete(
        f"/auth/api/v1/users/other-person/tokens/{other_token.key}",
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"
    r = await setup.client.delete(
        f"/auth/api/v1/users/{token_data.username}/tokens/{other_token.key}",
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 404

    # Modify a token.
    r = await setup.client.patch(
        f"/auth/api/v1/users/other-person/tokens/{other_token.key}",
        json={"token_name": "happy token"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"
    r = await setup.client.patch(
        f"/auth/api/v1/users/{token_data.username}/tokens/{other_token.key}",
        json={"token_name": "happy token"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_no_expires(setup: SetupTest) -> None:
    """Test creating a user token that doesn't expire."""
    token_data = await setup.create_session_token()
    setup.login(token_data.token)

    r = await setup.client.get("/auth/api/v1/login")
    assert r.status_code == 200
    csrf = r.json()["csrf"]

    r = await setup.client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 201
    token_url = r.headers["Location"]

    r = await setup.client.get(token_url)
    assert "expires" not in r.json()

    # Create a user token with an expiration and then adjust it to not expire.
    now = datetime.now(tz=timezone.utc).replace(microsecond=0)
    expires = now + timedelta(days=2)
    r = await setup.client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={
            "token_name": "another token",
            "expires": int(expires.timestamp()),
        },
    )
    assert r.status_code == 201
    user_token = Token.from_str(r.json()["token"])
    token_service = setup.factory.create_token_service()
    user_token_data = await token_service.get_data(user_token)
    assert user_token_data
    assert user_token_data.expires == expires
    token_url = r.headers["Location"]

    r = await setup.client.get(token_url)
    assert r.json()["expires"] == int(expires.timestamp())

    r = await setup.client.patch(
        token_url,
        headers={"X-CSRF-Token": csrf},
        json={"expires": None},
    )
    assert r.status_code == 201
    assert "expires" not in r.json()

    # Check that the expiration was also changed in Redis.
    token_service = setup.factory.create_token_service()
    user_token_data = await token_service.get_data(user_token)
    assert user_token_data
    assert user_token_data.expires is None


@pytest.mark.asyncio
async def test_duplicate_token_name(setup: SetupTest) -> None:
    """Test duplicate token names."""
    token_data = await setup.create_session_token()
    setup.login(token_data.token)

    r = await setup.client.get("/auth/api/v1/login")
    assert r.status_code == 200
    csrf = r.json()["csrf"]

    r = await setup.client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 201
    r = await setup.client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 422
    assert r.json()["detail"]["type"] == "duplicate_token_name"

    # Create a token with a different name and then try to modify the name to
    # conflict.
    r = await setup.client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "another token"},
    )
    assert r.status_code == 201
    token_url = r.headers["Location"]
    r = await setup.client.patch(
        token_url,
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 422
    assert r.json()["detail"]["type"] == "duplicate_token_name"
