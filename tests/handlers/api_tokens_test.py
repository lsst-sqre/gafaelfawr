"""Tests for the ``/auth/api/v1/users/*/tokens`` and related routes."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import ANY

import pytest
from _pytest.logging import LogCaptureFixture
from httpx import AsyncClient

from gafaelfawr.config import Config
from gafaelfawr.constants import COOKIE_NAME, UID_BOT_MIN
from gafaelfawr.factory import Factory
from gafaelfawr.models.state import State
from gafaelfawr.models.token import Token, TokenGroup, TokenUserInfo
from gafaelfawr.util import current_datetime, format_datetime_for_logging

from ..support.config import reconfigure
from ..support.constants import TEST_HOSTNAME
from ..support.cookies import clear_session_cookie, set_session_cookie
from ..support.firestore import MockFirestore
from ..support.ldap import MockLDAP
from ..support.logging import parse_log
from ..support.slack import MockSlack
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_create_delete_modify(
    client: AsyncClient, factory: Factory, caplog: LogCaptureFixture
) -> None:
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        email="example@example.com",
        uid=45613,
        groups=[TokenGroup(name="foo", id=12313)],
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        session_token = await token_service.create_session_token(
            user_info,
            scopes=["read:all", "exec:admin", "user:token"],
            ip_address="127.0.0.1",
        )
    csrf = await set_session_cookie(client, session_token)

    caplog.clear()
    expires = current_datetime() + timedelta(days=100)
    r = await client.post(
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

    # Check the logging.
    assert parse_log(caplog) == [
        {
            "event": "Created new user token",
            "httpRequest": {
                "requestMethod": "POST",
                "requestUrl": (
                    f"https://{TEST_HOSTNAME}/auth/api/v1/users/example/tokens"
                ),
                "remoteIp": "127.0.0.1",
            },
            "scopes": ["exec:admin", "read:all", "user:token"],
            "severity": "info",
            "token": session_token.key,
            "token_key": user_token.key,
            "token_expires": format_datetime_for_logging(expires),
            "token_name": "some token",
            "token_scopes": ["read:all"],
            "token_source": "cookie",
            "token_userinfo": {
                "email": "example@example.com",
                "name": "Example Person",
                "uid": 45613,
                "groups": [{"id": 12313, "name": "foo"}],
            },
            "user": "example",
        }
    ]

    r = await client.get(token_url)
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
    cookie = client.cookies.pop(COOKIE_NAME)
    r = await client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {user_token}"},
    )
    assert r.status_code == 200
    assert r.json() == info
    client.cookies.set(COOKIE_NAME, cookie, domain=TEST_HOSTNAME)

    # Listing all tokens for this user should return the user token and a
    # session token.
    r = await client.get("/auth/api/v1/users/example/tokens")
    assert r.status_code == 200
    data = r.json()

    # Adjust for sorting, which will be by creation date and then token.
    assert len(data) == 2
    if data[0] == info:
        session_info = data[1]
    else:
        assert data[1] == info
        session_info = data[0]
    assert session_info == {
        "token": session_token.key,
        "username": "example",
        "token_type": "session",
        "scopes": ["exec:admin", "read:all", "user:token"],
        "created": ANY,
        "expires": ANY,
    }

    # Modifying a user token fails with permission denied.
    new_expires = current_datetime() + timedelta(days=200)
    r = await client.patch(
        token_url,
        headers={"X-CSRF-Token": csrf},
        json={
            "token_name": "happy token",
            "scopes": ["exec:admin"],
            "expires": int(new_expires.timestamp()),
        },
    )
    assert r.status_code == 403
    assert r.json()["detail"][0]["type"] == "permission_denied"

    # Get a token admin token, which will be allowed to modify the token.
    async with factory.session.begin():
        admin_token = await token_service.create_session_token(
            user_info, scopes=["admin:token"], ip_address="127.0.0.1"
        )
    csrf = await set_session_cookie(client, admin_token)

    # Change the name, scope, and expiration of the token.
    caplog.clear()
    new_expires = current_datetime() + timedelta(days=200)
    r = await client.patch(
        token_url,
        headers={"X-CSRF-Token": csrf},
        json={
            "token_name": "happy token",
            "scopes": ["exec:admin"],
            "expires": int(new_expires.timestamp()),
        },
    )
    assert r.status_code == 200
    assert r.json() == {
        "token": user_token.key,
        "username": "example",
        "token_name": "happy token",
        "token_type": "user",
        "scopes": ["exec:admin"],
        "created": ANY,
        "expires": int(new_expires.timestamp()),
    }

    # Check the logging.  Regression test for a bug where new expirations
    # would be logged as raw datetime objects instead of formatted dates.
    assert parse_log(caplog) == [
        {
            "event": "Modified token",
            "httpRequest": {
                "requestMethod": "PATCH",
                "requestUrl": f"https://{TEST_HOSTNAME}{token_url}",
                "remoteIp": "127.0.0.1",
            },
            "scopes": ["admin:token"],
            "severity": "info",
            "token": admin_token.key,
            "token_key": user_token.key,
            "token_expires": format_datetime_for_logging(new_expires),
            "token_name": "happy token",
            "token_scopes": ["exec:admin"],
            "token_source": "cookie",
            "user": "example",
        }
    ]

    # Go back to the previous authentication and delete the token.
    csrf = await set_session_cookie(client, session_token)
    caplog.clear()
    r = await client.delete(token_url, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 204
    r = await client.get(token_url)
    assert r.status_code == 404

    # Check the logging.
    assert parse_log(caplog) == [
        {
            "event": "Deleted token",
            "httpRequest": {
                "requestMethod": "DELETE",
                "requestUrl": f"https://{TEST_HOSTNAME}{token_url}",
                "remoteIp": "127.0.0.1",
            },
            "scopes": ["exec:admin", "read:all", "user:token"],
            "severity": "info",
            "token": session_token.key,
            "token_key": user_token.key,
            "token_source": "cookie",
            "token_username": "example",
            "user": "example",
        }
    ]

    # Deleting again should return 404.
    r = await client.delete(token_url, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 404

    # This user should now have just the two session tokens we created.
    r = await client.get("/auth/api/v1/users/example/tokens")
    assert r.status_code == 200
    assert len(r.json()) == 2

    # We should be able to see the change history for the token.
    r = await client.get(token_url + "/change-history")
    assert r.status_code == 200
    assert r.json() == [
        {
            "token": user_token.key,
            "username": "example",
            "token_type": "user",
            "token_name": "happy token",
            "scopes": ["exec:admin"],
            "expires": int(new_expires.timestamp()),
            "actor": "example",
            "action": "revoke",
            "ip_address": "127.0.0.1",
            "event_time": ANY,
        },
        {
            "token": user_token.key,
            "username": "example",
            "token_type": "user",
            "token_name": "happy token",
            "scopes": ["exec:admin"],
            "expires": int(new_expires.timestamp()),
            "actor": "example",
            "action": "edit",
            "old_token_name": "some token",
            "old_scopes": ["read:all"],
            "old_expires": int(expires.timestamp()),
            "ip_address": "127.0.0.1",
            "event_time": ANY,
        },
        {
            "token": user_token.key,
            "username": "example",
            "token_type": "user",
            "token_name": "some token",
            "scopes": ["read:all"],
            "expires": int(expires.timestamp()),
            "actor": "example",
            "action": "create",
            "ip_address": "127.0.0.1",
            "event_time": ANY,
        },
    ]


@pytest.mark.asyncio
async def test_token_info(
    client: AsyncClient, config: Config, factory: Factory
) -> None:
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        email="example@example.com",
        uid=45613,
        gid=12345,
        groups=[TokenGroup(name="foo", id=12313)],
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        session_token = await token_service.create_session_token(
            user_info,
            scopes=["exec:admin", "user:token"],
            ip_address="127.0.0.1",
        )

    r = await client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {session_token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data == {
        "token": session_token.key,
        "username": "example",
        "token_type": "session",
        "scopes": ["exec:admin", "user:token"],
        "created": ANY,
        "expires": ANY,
    }
    now = datetime.now(tz=timezone.utc)
    created = datetime.fromtimestamp(data["created"], tz=timezone.utc)
    assert now - timedelta(seconds=5) <= created <= now
    expires = created + config.token_lifetime
    assert datetime.fromtimestamp(data["expires"], tz=timezone.utc) == expires

    r = await client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {session_token}"},
    )
    assert r.status_code == 200
    session_user_info = r.json()
    assert session_user_info == {
        "username": "example",
        "name": "Example Person",
        "email": "example@example.com",
        "uid": 45613,
        "gid": 12345,
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
    async with factory.session.begin():
        user_token = await token_service.create_user_token(
            data,
            data.username,
            token_name="some-token",
            scopes=["exec:admin"],
            expires=expires,
            ip_address="127.0.0.1",
        )

    r = await client.get(
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

    r = await client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {user_token}"},
    )
    assert r.status_code == 200
    assert r.json() == session_user_info

    # Test getting a list of tokens for a user.
    state = State(token=session_token)
    r = await client.get(
        "/auth/api/v1/users/example/tokens",
        cookies={COOKIE_NAME: state.to_cookie()},
    )


@pytest.mark.asyncio
async def test_auth_required(
    client: AsyncClient, factory: Factory, mock_slack: MockSlack
) -> None:
    token_data = await create_session_token(factory)
    token = token_data.token
    csrf = await set_session_cookie(client, token)

    # Replace the cookie with one containing the CSRF token but not the
    # authentication token.
    clear_session_cookie(client)
    client.cookies[COOKIE_NAME] = State(csrf=csrf).to_cookie()

    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"username": "bot-foo", "token_type": "service"},
    )
    assert r.status_code == 401

    r = await client.get("/auth/api/v1/users/example/tokens")
    assert r.status_code == 401

    r = await client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 401

    r = await client.get(f"/auth/api/v1/users/example/tokens/{token.key}")
    assert r.status_code == 401

    r = await client.get(
        f"/auth/api/v1/users/example/tokens/{token.key}/change-history"
    )
    assert r.status_code == 401

    r = await client.delete(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 401

    r = await client.patch(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 401

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_csrf_required(
    client: AsyncClient, factory: Factory, mock_slack: MockSlack
) -> None:
    token_data = await create_session_token(factory, scopes=["admin:token"])
    csrf = await set_session_cookie(client, token_data.token)
    token_service = factory.create_token_service()
    async with factory.session.begin():
        user_token = await token_service.create_user_token(
            token_data,
            token_data.username,
            token_name="foo",
            scopes=[],
            ip_address="127.0.0.1",
        )

    r = await client.post(
        "/auth/api/v1/tokens",
        json={"username": "bot-foo", "token_type": "service"},
    )
    assert r.status_code == 403
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
        json={"username": "bot-foo", "token_type": "service"},
    )
    assert r.status_code == 403

    r = await client.post(
        "/auth/api/v1/users/example/tokens", json={"token_name": "some token"}
    )
    assert r.status_code == 403

    r = await client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 403

    r = await client.delete(
        f"/auth/api/v1/users/example/tokens/{user_token.key}"
    )
    assert r.status_code == 403

    r = await client.delete(
        f"/auth/api/v1/users/example/tokens/{user_token.key}",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
    )
    assert r.status_code == 403

    r = await client.patch(
        f"/auth/api/v1/users/example/tokens/{user_token.key}",
        json={"token_name": "some token"},
    )
    assert r.status_code == 403

    r = await client.patch(
        f"/auth/api/v1/users/example/tokens/{user_token.key}",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 403

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_no_bootstrap(
    client: AsyncClient,
    config: Config,
    factory: Factory,
    mock_slack: MockSlack,
) -> None:
    token_data = await create_session_token(factory)
    token = token_data.token
    bootstrap_token = str(config.bootstrap_token)

    r = await client.get(
        "/auth/api/v1/users/example/tokens",
        headers={"Authorization": f"bearer {bootstrap_token}"},
    )
    assert r.status_code == 401

    r = await client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"Authorization": f"bearer {bootstrap_token}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 401

    r = await client.get(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"Authorization": f"bearer {bootstrap_token}"},
    )
    assert r.status_code == 401

    r = await client.delete(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"Authorization": f"bearer {bootstrap_token}"},
    )
    assert r.status_code == 401

    r = await client.patch(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"Authorization": f"bearer {bootstrap_token}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 401

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_no_scope(
    client: AsyncClient, factory: Factory, mock_slack: MockSlack
) -> None:
    token_data = await create_session_token(factory)
    token_service = factory.create_token_service()
    async with factory.session.begin():
        token = await token_service.create_user_token(
            token_data,
            token_data.username,
            token_name="user",
            scopes=[],
            ip_address="127.0.0.1",
        )

    r = await client.get(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"Authorization": f"bearer {token}"},
    )
    assert r.status_code == 403

    r = await client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"Authorization": f"bearer {token}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 403

    r = await client.get(
        f"/auth/api/v1/users/{token_data.username}/tokens/{token.key}",
        headers={"Authorization": f"bearer {token}"},
    )
    assert r.status_code == 403

    r = await client.delete(
        f"/auth/api/v1/users/{token_data.username}/tokens/{token.key}",
        headers={"Authorization": f"bearer {token}"},
    )
    assert r.status_code == 403

    r = await client.patch(
        f"/auth/api/v1/users/{token_data.username}/tokens/{token.key}",
        headers={"Authorization": f"bearer {token}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 403

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_modify_nonuser(
    client: AsyncClient, factory: Factory, mock_slack: MockSlack
) -> None:
    token_data = await create_session_token(factory)
    token = token_data.token
    csrf = await set_session_cookie(client, token)

    r = await client.patch(
        f"/auth/api/v1/users/{token_data.username}/tokens/{token.key}",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "happy token"},
    )
    assert r.status_code == 403
    assert r.json()["detail"][0]["type"] == "permission_denied"

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_wrong_user(
    client: AsyncClient, factory: Factory, mock_slack: MockSlack
) -> None:
    token_data = await create_session_token(factory)
    csrf = await set_session_cookie(client, token_data.token)
    token_service = factory.create_token_service()
    user_info = TokenUserInfo(
        username="other-person", name="Some Other Person", uid=137123
    )
    async with factory.session.begin():
        other_session_token = await token_service.create_session_token(
            user_info, scopes=["user:token"], ip_address="127.0.0.1"
        )
    other_session_data = await token_service.get_data(other_session_token)
    assert other_session_data
    async with factory.session.begin():
        other_token = await token_service.create_user_token(
            other_session_data,
            "other-person",
            token_name="foo",
            scopes=[],
            ip_address="127.0.0.1",
        )

    # Get a token list.
    r = await client.get("/auth/api/v1/users/other-person/tokens")
    assert r.status_code == 403
    assert r.json()["detail"][0]["type"] == "permission_denied"

    # Create a new user token.
    r = await client.post(
        "/auth/api/v1/users/other-person/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "happy token"},
    )
    assert r.status_code == 403
    assert r.json()["detail"][0]["type"] == "permission_denied"

    # Get an individual token.
    r = await client.get(
        f"/auth/api/v1/users/other-person/tokens/{other_token.key}"
    )
    assert r.status_code == 403
    assert r.json()["detail"][0]["type"] == "permission_denied"

    # Get the history of an individual token.
    r = await client.get(
        f"/auth/api/v1/users/other-person/tokens/{other_token.key}"
        "/change-history"
    )
    assert r.status_code == 403
    assert r.json()["detail"][0]["type"] == "permission_denied"

    # Ensure you can't see someone else's token under your username either.
    r = await client.get(
        f"/auth/api/v1/users/{token_data.username}/tokens/{other_token.key}"
    )
    assert r.status_code == 404

    # Or their history.
    r = await client.get(
        f"/auth/api/v1/users/{token_data.username}/tokens/{other_token.key}"
        "/change-history"
    )
    assert r.status_code == 404

    # Delete a token.
    r = await client.delete(
        f"/auth/api/v1/users/other-person/tokens/{other_token.key}",
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403
    assert r.json()["detail"][0]["type"] == "permission_denied"
    r = await client.delete(
        f"/auth/api/v1/users/{token_data.username}/tokens/{other_token.key}",
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 404

    # Modify a token.
    r = await client.patch(
        f"/auth/api/v1/users/other-person/tokens/{other_token.key}",
        json={"token_name": "happy token"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403
    assert r.json()["detail"][0]["type"] == "permission_denied"
    r = await client.patch(
        f"/auth/api/v1/users/{token_data.username}/tokens/{other_token.key}",
        json={"token_name": "happy token"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 404

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_no_expires(client: AsyncClient, factory: Factory) -> None:
    """Test creating a user token that doesn't expire."""
    token_data = await create_session_token(
        factory, scopes=["admin:token", "user:token"]
    )
    csrf = await set_session_cookie(client, token_data.token)

    r = await client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 201
    token_url = r.headers["Location"]

    r = await client.get(token_url)
    assert "expires" not in r.json()

    # Create a user token with an expiration and then adjust it to not expire.
    now = datetime.now(tz=timezone.utc).replace(microsecond=0)
    expires = now + timedelta(days=2)
    r = await client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={
            "token_name": "another token",
            "expires": int(expires.timestamp()),
        },
    )
    assert r.status_code == 201
    user_token = Token.from_str(r.json()["token"])
    token_service = factory.create_token_service()
    user_token_data = await token_service.get_data(user_token)
    assert user_token_data and user_token_data.expires == expires
    token_url = r.headers["Location"]

    r = await client.get(token_url)
    assert r.json()["expires"] == int(expires.timestamp())

    r = await client.patch(
        token_url,
        headers={"X-CSRF-Token": csrf},
        json={"expires": None},
    )
    assert r.status_code == 200
    assert "expires" not in r.json()

    # Check that the expiration was also changed in Redis.
    user_token_data = await token_service.get_data(user_token)
    assert user_token_data and user_token_data.expires is None


@pytest.mark.asyncio
async def test_duplicate_token_name(
    client: AsyncClient, factory: Factory, mock_slack: MockSlack
) -> None:
    """Test duplicate token names."""
    token_data = await create_session_token(
        factory, scopes=["admin:token", "user:token"]
    )
    csrf = await set_session_cookie(client, token_data.token)

    r = await client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 201
    r = await client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "duplicate_token_name"

    # Create a token with a different name and then try to modify the name to
    # conflict.
    r = await client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "another token"},
    )
    assert r.status_code == 201
    token_url = r.headers["Location"]
    r = await client.patch(
        token_url,
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "duplicate_token_name"

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_bad_expires(
    client: AsyncClient, factory: Factory, mock_slack: MockSlack
) -> None:
    """Test creating or modifying a token with bogus expirations."""
    token_data = await create_session_token(
        factory, scopes=["user:token", "admin:token"]
    )
    csrf = await set_session_cookie(client, token_data.token)

    now = int(time.time())
    bad_expires = [-now, -1, 0, now, now + (5 * 60) - 1]
    for bad_expire in bad_expires:
        r = await client.post(
            f"/auth/api/v1/users/{token_data.username}/tokens",
            headers={"X-CSRF-Token": csrf},
            json={"token_name": "some token", "expires": bad_expire},
        )
        assert r.status_code == 422
        data = r.json()
        assert data["detail"][0]["loc"] == ["body", "expires"]
        assert data["detail"][0]["type"] == "invalid_expires"

    # Create a valid token.
    r = await client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 201
    token_url = r.headers["Location"]

    # Now try modifying the expiration time to the same bogus values.
    for bad_expire in bad_expires:
        r = await client.patch(
            token_url,
            headers={"X-CSRF-Token": csrf},
            json={"expires": bad_expire},
        )
        assert r.status_code == 422
        data = r.json()
        assert data["detail"][0]["loc"] == ["body", "expires"]
        assert data["detail"][0]["type"] == "invalid_expires"

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_bad_scopes(
    client: AsyncClient,
    config: Config,
    factory: Factory,
    mock_slack: MockSlack,
) -> None:
    """Test creating or modifying a token with bogus scopes."""
    known_scopes = list(config.known_scopes.keys())
    assert len(known_scopes) > 4
    token_data = await create_session_token(
        factory, scopes=known_scopes[:3] + ["other:scope", "user:token"]
    )
    csrf = await set_session_cookie(client, token_data.token)

    # Check that we reject both an unknown scope and a scope that's present on
    # the session but isn't valid in the configuration.
    for bad_scope in ("some:random-thing", "other:scope"):
        r = await client.post(
            f"/auth/api/v1/users/{token_data.username}/tokens",
            headers={"X-CSRF-Token": csrf},
            json={"token_name": "some token", "scopes": [bad_scope]},
        )
        assert r.status_code == 422
        data = r.json()
        assert data["detail"][0]["loc"] == ["body", "scopes"]
        assert data["detail"][0]["type"] == "invalid_scopes"

    # Create a valid token with all of the scopes as the session.
    r = await client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token", "scopes": known_scopes[:3]},
    )
    assert r.status_code == 201
    token_url = r.headers["Location"]

    # Now try modifying it with the invalid scope.
    for bad_scope in ("some:random-thing", "other:scope"):
        r = await client.patch(
            token_url,
            headers={"X-CSRF-Token": csrf},
            json={"scopes": [known_scopes[1], bad_scope]},
        )
        assert r.status_code == 422
        data = r.json()
        assert data["detail"][0]["loc"] == ["body", "scopes"]
        assert data["detail"][0]["type"] == "invalid_scopes"

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_create_admin(
    client: AsyncClient,
    config: Config,
    factory: Factory,
    caplog: LogCaptureFixture,
) -> None:
    """Test creating a token through the admin interface."""
    token_data = await create_session_token(factory, scopes=["exec:admin"])
    csrf = await set_session_cookie(client, token_data.token)

    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"username": "bot-a-service", "token_type": "service"},
    )
    assert r.status_code == 403

    token_data = await create_session_token(factory, scopes=["admin:token"])
    csrf = await set_session_cookie(client, token_data.token)

    now = datetime.now(tz=timezone.utc)
    expires = now + timedelta(days=2)
    caplog.clear()
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"X-CSRF-Token": csrf},
        json={
            "username": "bot-a-service",
            "token_type": "service",
            "scopes": ["admin:token"],
            "expires": int(expires.timestamp()),
            "name": "A Service",
            "uid": 1234,
            "gid": 4567,
            "email": "service@example.com",
            "groups": [{"name": "some-group", "id": 12381}],
        },
    )
    assert r.status_code == 201
    assert r.json() == {"token": ANY}
    service_token = Token.from_str(r.json()["token"])
    token_url = f"/auth/api/v1/users/bot-a-service/tokens/{service_token.key}"
    assert r.headers["Location"] == token_url

    # Check the logging.
    assert parse_log(caplog) == [
        {
            "event": "Created new service token",
            "httpRequest": {
                "requestMethod": "POST",
                "requestUrl": f"https://{TEST_HOSTNAME}/auth/api/v1/tokens",
                "remoteIp": "127.0.0.1",
            },
            "scopes": ["admin:token"],
            "severity": "info",
            "token": token_data.token.key,
            "token_key": service_token.key,
            "token_expires": format_datetime_for_logging(expires),
            "token_scopes": ["admin:token"],
            "token_source": "cookie",
            "token_userinfo": {
                "name": "A Service",
                "email": "service@example.com",
                "uid": 1234,
                "gid": 4567,
                "groups": [{"name": "some-group", "id": 12381}],
            },
            "token_username": "bot-a-service",
            "user": token_data.username,
        }
    ]

    # Check API information about the token.
    clear_session_cookie(client)
    r = await client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {str(service_token)}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "token": service_token.key,
        "username": "bot-a-service",
        "token_type": "service",
        "scopes": ["admin:token"],
        "created": ANY,
        "expires": int(expires.timestamp()),
    }
    r = await client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {str(service_token)}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": "bot-a-service",
        "name": "A Service",
        "email": "service@example.com",
        "uid": 1234,
        "gid": 4567,
        "groups": [{"name": "some-group", "id": 12381}],
    }

    # Check a bunch of invalid ways to create a new token for another user.
    caplog.clear()
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={"username": "a-user", "token_type": "session"},
    )
    assert r.status_code == 422
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={"username": "a-user", "token_type": "user"},
    )
    assert r.status_code == 422
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={
            "username": "a-user",
            "token_type": "user",
            "token_name": "some token",
            "expires": int(datetime.now(tz=timezone.utc).timestamp()),
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "invalid_expires"
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={
            "username": "a-user",
            "token_type": "user",
            "token_name": "some token",
            "scopes": ["bogus:scope"],
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "invalid_scopes"

    # Create a new token for another user.
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={
            "username": "a-user",
            "token_type": "user",
            "token_name": "some token",
        },
    )
    assert r.status_code == 201
    assert r.json() == {"token": ANY}
    user_token = Token.from_str(r.json()["token"])
    token_url = f"/auth/api/v1/users/a-user/tokens/{user_token.key}"
    assert r.headers["Location"] == token_url

    assert parse_log(caplog) == [
        {
            "event": "Created new user token as administrator",
            "httpRequest": {
                "requestMethod": "POST",
                "requestUrl": f"https://{TEST_HOSTNAME}/auth/api/v1/tokens",
                "remoteIp": "127.0.0.1",
            },
            "scopes": ["admin:token"],
            "severity": "info",
            "token": service_token.key,
            "token_key": user_token.key,
            "token_expires": None,
            "token_name": "some token",
            "token_scopes": [],
            "token_source": "bearer",
            "token_userinfo": {},
            "token_username": "a-user",
            "user": "bot-a-service",
        }
    ]

    # Check the API information about that token.
    r = await client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {str(user_token)}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "token": user_token.key,
        "username": "a-user",
        "token_type": "user",
        "token_name": "some token",
        "scopes": [],
        "created": ANY,
    }
    r = await client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {str(user_token)}"},
    )
    assert r.status_code == 200
    assert r.json() == {"username": "a-user"}

    # Check handling of duplicate token name errors.
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={
            "username": "a-user",
            "token_type": "user",
            "token_name": "some token",
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "duplicate_token_name"

    # Check handling of an invalid username.
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={
            "username": "invalid(user)",
            "token_type": "user",
            "token_name": "some token",
        },
    )
    assert r.status_code == 422

    # Check that the bootstrap token also works.
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(config.bootstrap_token)}"},
        json={"username": "bot-other-service", "token_type": "service"},
    )
    assert r.status_code == 201


@pytest.mark.asyncio
async def test_create_admin_ldap(
    tmp_path: Path, client: AsyncClient, factory: Factory, mock_ldap: MockLDAP
) -> None:
    """Create a token through the admin interface with LDAP user data."""
    config = await reconfigure(tmp_path, "oidc-ldap", factory)
    token_data = await create_session_token(factory, scopes=["admin:token"])
    csrf = await set_session_cookie(client, token_data.token)

    assert config.ldap
    assert config.ldap.user_base_dn
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "some-user",
        [
            {
                "displayName": ["Some User"],
                "mail": ["user@example.com"],
                "uidNumber": ["1234"],
            }
        ],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        "some-user",
        [{"cn": ["some-group"], "gidNumber": ["12381"]}],
    )

    # Create a new service token with no user metadata.
    now = datetime.now(tz=timezone.utc)
    expires = int((now + timedelta(days=2)).timestamp())
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"X-CSRF-Token": csrf},
        json={
            "username": "some-user",
            "token_name": "test token",
            "token_type": "user",
            "scopes": ["admin:token"],
            "expires": expires,
        },
    )
    assert r.status_code == 201
    service_token = Token.from_str(r.json()["token"])

    # Check that all the user metadata is fleshed out from LDAP.
    clear_session_cookie(client)
    r = await client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {str(service_token)}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": "some-user",
        "name": "Some User",
        "email": "user@example.com",
        "uid": 1234,
        "groups": [{"name": "some-group", "id": 12381}],
    }

    # Create a new token, but this time provide different user metadata.
    csrf = await set_session_cookie(client, token_data.token)
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"X-CSRF-Token": csrf},
        json={
            "username": "some-user",
            "token_name": "other token",
            "token_type": "user",
            "scopes": ["admin:token"],
            "expires": expires,
            "name": "Another Name",
            "email": "another@example.com",
            "uid": 2222,
            "groups": [{"name": "another-group", "id": 11111}],
        },
    )
    assert r.status_code == 201
    service_token = Token.from_str(r.json()["token"])

    # Now that data should override what's in LDAP.
    clear_session_cookie(client)
    r = await client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {str(service_token)}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": "some-user",
        "name": "Another Name",
        "email": "another@example.com",
        "uid": 2222,
        "groups": [{"name": "another-group", "id": 11111}],
    }

    # Create a token for a user not found in LDAP, and without metadata.
    csrf = await set_session_cookie(client, token_data.token)
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"X-CSRF-Token": csrf},
        json={
            "username": "other-user",
            "token_name": "other token",
            "token_type": "user",
            "scopes": [],
            "expires": expires,
        },
    )
    assert r.status_code == 201
    service_token = Token.from_str(r.json()["token"])

    # Getting metadata should not throw an exception.
    clear_session_cookie(client)
    r = await client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {str(service_token)}"},
    )
    assert r.status_code == 200
    assert r.json() == {"username": "other-user", "groups": []}


@pytest.mark.asyncio
async def test_create_admin_firestore(
    tmp_path: Path,
    client: AsyncClient,
    factory: Factory,
    mock_firestore: MockFirestore,
) -> None:
    """Create a token through the admin interface with LDAP user data."""
    await reconfigure(tmp_path, "oidc-firestore", factory)
    firestore_storage = factory.create_firestore_storage()
    await firestore_storage.initialize()
    token_data = await create_session_token(factory, scopes=["admin:token"])
    csrf = await set_session_cookie(client, token_data.token)

    # Create a new service token with no user metadata.
    now = datetime.now(tz=timezone.utc)
    expires = int((now + timedelta(days=2)).timestamp())
    r = await client.post(
        "/auth/api/v1/tokens",
        headers={"X-CSRF-Token": csrf},
        json={
            "username": "bot-user",
            "token_type": "service",
            "expires": expires,
        },
    )
    assert r.status_code == 201
    service_token = Token.from_str(r.json()["token"])

    # Check that the UID came from Firestore.
    clear_session_cookie(client)
    r = await client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {str(service_token)}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": "bot-user",
        "uid": UID_BOT_MIN,
    }


@pytest.mark.asyncio
async def test_no_form_post(
    client: AsyncClient,
    factory: Factory,
    caplog: LogCaptureFixture,
    mock_slack: MockSlack,
) -> None:
    """Ensure that the token creation API does not support a form POST.

    To ensure that web security rules are followed, we need to be sure that
    the token creation endpoint only supports JSON POST and not the form
    encoding.  This will ensure that the API call requires a CORS preflight
    (which we will reject).

    The creation API is used as a proxy for testing all the APIs.  Only POST
    needs to be tested; PUT, PATCH, and DELETE always require CORS.
    """
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        email="example@example.com",
        uid=45613,
        groups=[TokenGroup(name="foo", id=12313)],
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        session_token = await token_service.create_session_token(
            user_info,
            scopes=["read:all", "exec:admin", "user:token"],
            ip_address="127.0.0.1",
        )
    csrf = await set_session_cookie(client, session_token)

    expires = current_datetime() + timedelta(days=100)
    r = await client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"X-CSRF-Token": csrf},
        data={
            "token_name": "some token",
            "scopes": "read:all",
            "expires": int(expires.timestamp()),
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "type_error.dict"

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_scope_modify(
    client: AsyncClient, factory: Factory, caplog: LogCaptureFixture
) -> None:
    """Ensure modifying the scope updates Redis.

    In Gafaelfawr 5.0.2 and earlier, modifying only the token scope didn't
    change Redis and therefore wasn't reflected in the ``/auth`` route.
    """
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        email="example@example.com",
        uid=45613,
        groups=[TokenGroup(name="foo", id=12313)],
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        session_token = await token_service.create_session_token(
            user_info,
            scopes=["admin:token", "read:all", "exec:admin", "user:token"],
            ip_address="127.0.0.1",
        )
    csrf = await set_session_cookie(client, session_token)

    expires = current_datetime() + timedelta(days=100)
    r = await client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"X-CSRF-Token": csrf},
        json={
            "token_name": "some token",
            "scopes": [],
            "expires": int(expires.timestamp()),
        },
    )
    assert r.status_code == 201
    assert r.json() == {"token": ANY}
    user_token = Token.from_str(r.json()["token"])
    token_url = r.headers["Location"]
    assert token_url == f"/auth/api/v1/users/example/tokens/{user_token.key}"

    r = await client.get(token_url)
    assert r.status_code == 200
    assert r.json() == {
        "token": user_token.key,
        "username": "example",
        "token_name": "some token",
        "token_type": "user",
        "scopes": [],
        "created": ANY,
        "expires": int(expires.timestamp()),
    }

    # This token should get access denied when hitting the /auth route with a
    # required read:all scope.
    cookie = client.cookies.pop(COOKIE_NAME)
    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers={"Authorization": f"bearer {user_token}"},
    )
    assert r.status_code == 403
    client.cookies.set(COOKIE_NAME, cookie, domain=TEST_HOSTNAME)

    # Modify the scopes to include read:all, and then check the token
    # information again.
    r = await client.patch(
        token_url,
        headers={"X-CSRF-Token": csrf},
        json={"scopes": ["read:all"]},
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

    # Now remove the cookie and test the token-info and auth routes with the
    # new token.  It should allow access when protected by read:all.
    client.cookies.pop(COOKIE_NAME)
    r = await client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {user_token}"},
    )
    assert r.status_code == 200
    assert r.json() == info

    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers={"Authorization": f"bearer {user_token}"},
    )
    assert r.status_code == 200
