"""Tests for the /auth route."""

from __future__ import annotations

import base64
from datetime import timedelta
from unittest.mock import ANY

import pytest
from httpx import AsyncClient

from gafaelfawr.config import Config
from gafaelfawr.constants import COOKIE_NAME, MINIMUM_LIFETIME
from gafaelfawr.factory import Factory
from gafaelfawr.models.auth import AuthError, AuthErrorChallenge, AuthType
from gafaelfawr.models.token import Token, TokenUserInfo
from gafaelfawr.util import current_datetime

from ..support.constants import TEST_HOSTNAME
from ..support.cookies import clear_session_cookie, set_session_cookie
from ..support.headers import (
    assert_unauthorized_is_correct,
    parse_www_authenticate,
)
from ..support.slack import MockSlack
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_no_auth(
    client: AsyncClient, config: Config, mock_slack: MockSlack
) -> None:
    r = await client.get("/auth", params={"scope": "exec:admin"})
    assert_unauthorized_is_correct(r, config)

    r = await client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "bearer"}
    )
    assert_unauthorized_is_correct(r, config)

    r = await client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "bogus"}
    )
    assert r.status_code == 422

    r = await client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "basic"}
    )
    assert_unauthorized_is_correct(r, config, AuthType.Basic)

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_invalid(
    client: AsyncClient, factory: Factory, mock_slack: MockSlack
) -> None:
    token = await create_session_token(factory)

    r = await client.get(
        "/auth", headers={"Authorization": f"bearer {token.token}"}
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "value_error.missing"

    r = await client.get(
        "/auth",
        headers={"Authorization": f"bearer {token.token}"},
        params={"scope": "exec:admin", "satisfy": "foo"},
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "type_error.enum"

    r = await client.get(
        "/auth",
        headers={"Authorization": f"bearer {token.token}"},
        params={"scope": "exec:admin", "auth_type": "foo"},
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "type_error.enum"

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_invalid_auth(
    client: AsyncClient, config: Config, mock_slack: MockSlack
) -> None:
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer"},
    )
    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config.realm
    assert authenticate.error == AuthError.invalid_request

    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "token foo"},
    )
    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config.realm
    assert authenticate.error == AuthError.invalid_request

    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer token"},
    )
    assert r.status_code == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config.realm
    assert authenticate.error == AuthError.invalid_token

    # Create a nonexistent token.
    token = Token()
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config.realm
    assert authenticate.error == AuthError.invalid_token

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_access_denied(
    client: AsyncClient,
    config: Config,
    factory: Factory,
    mock_slack: MockSlack,
) -> None:
    token_data = await create_session_token(factory)

    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config.realm
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "exec:admin"
    assert "Token missing required scope" in r.text

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_auth_forbidden(
    client: AsyncClient, config: Config, mock_slack: MockSlack
) -> None:
    r = await client.get(
        "/auth/forbidden",
        params=[("scope", "exec:test"), ("scope", "exec:admin")],
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config.realm
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "exec:admin exec:test"
    assert "Token missing required scope" in r.text

    r = await client.get(
        "/auth/forbidden", params={"scope": "exec:admin", "auth_type": "basic"}
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Basic
    assert authenticate.realm == config.realm
    assert "Token missing required scope" in r.text

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_satisfy_all(
    client: AsyncClient,
    config: Config,
    factory: Factory,
    mock_slack: MockSlack,
) -> None:
    token_data = await create_session_token(factory, scopes=["exec:test"])

    r = await client.get(
        "/auth",
        params=[("scope", "exec:test"), ("scope", "exec:admin")],
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config.realm
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "exec:admin exec:test"
    assert "Token missing required scope" in r.text

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_success(client: AsyncClient, factory: Factory) -> None:
    token_data = await create_session_token(
        factory, group_names=["admin"], scopes=["exec:admin", "read:all"]
    )

    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == token_data.username
    assert r.headers["X-Auth-Request-Email"] == token_data.email


@pytest.mark.asyncio
async def test_success_minimal(client: AsyncClient, factory: Factory) -> None:
    user_info = TokenUserInfo(username="user", uid=1234)
    token_service = factory.create_token_service()
    async with factory.session.begin():
        token = await token_service.create_session_token(
            user_info, scopes=["read:all"], ip_address="127.0.0.1"
        )

    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers={"Authorization": f"Bearer   {token}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "user"
    assert "X-Auth-Request-Email" not in r.headers


@pytest.mark.asyncio
async def test_notebook(client: AsyncClient, factory: Factory) -> None:
    token_data = await create_session_token(
        factory, group_names=["admin"], scopes=["exec:admin", "read:all"]
    )
    assert token_data.expires

    r = await client.get(
        "/auth",
        params={"scope": "exec:admin", "notebook": "true"},
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    notebook_token = Token.from_str(r.headers["X-Auth-Request-Token"])
    assert notebook_token != token_data.token

    r = await client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"Bearer {notebook_token}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "token": notebook_token.key,
        "username": token_data.username,
        "token_type": "notebook",
        "scopes": ["exec:admin", "read:all"],
        "created": ANY,
        "expires": int(token_data.expires.timestamp()),
        "parent": token_data.token.key,
    }

    r = await client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"Bearer {notebook_token}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": token_data.username,
        "name": token_data.name,
        "email": token_data.email,
        "uid": token_data.uid,
        "gid": token_data.gid,
        "groups": token_data.groups,
    }

    # Requesting a token with the same parameters returns the same token.
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin", "notebook": "true"},
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    assert notebook_token == Token.from_str(r.headers["X-Auth-Request-Token"])


@pytest.mark.asyncio
async def test_internal(client: AsyncClient, factory: Factory) -> None:
    token_data = await create_session_token(
        factory,
        group_names=["admin"],
        scopes=["exec:admin", "read:all", "read:some"],
    )
    assert token_data.expires

    r = await client.get(
        "/auth",
        params={
            "scope": "exec:admin",
            "delegate_to": "a-service",
            "delegate_scope": " read:some  ,read:all  ",
        },
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    internal_token = Token.from_str(r.headers["X-Auth-Request-Token"])
    assert internal_token != token_data.token

    r = await client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"Bearer {internal_token}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "token": internal_token.key,
        "username": token_data.username,
        "token_type": "internal",
        "scopes": ["read:all", "read:some"],
        "service": "a-service",
        "created": ANY,
        "expires": int(token_data.expires.timestamp()),
        "parent": token_data.token.key,
    }

    r = await client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"Bearer {internal_token}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": token_data.username,
        "name": token_data.name,
        "email": token_data.email,
        "uid": token_data.uid,
        "gid": token_data.gid,
        "groups": token_data.groups,
    }

    # Requesting a token with the same parameters returns the same token.
    r = await client.get(
        "/auth",
        params={
            "scope": "exec:admin",
            "delegate_to": "a-service",
            "delegate_scope": "read:all,read:some",
        },
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    assert internal_token == Token.from_str(r.headers["X-Auth-Request-Token"])


@pytest.mark.asyncio
async def test_internal_scopes(client: AsyncClient, factory: Factory) -> None:
    """Delegated scopes are optional and dropped if not available."""
    token_data = await create_session_token(factory, scopes=["read:some"])
    assert token_data.expires

    r = await client.get(
        "/auth",
        params={
            "scope": "read:some",
            "delegate_to": "a-service",
            "delegate_scope": "read:all,read:some",
        },
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    internal_token = Token.from_str(r.headers["X-Auth-Request-Token"])

    r = await client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"Bearer {internal_token}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "token": internal_token.key,
        "username": token_data.username,
        "token_type": "internal",
        "scopes": ["read:some"],
        "service": "a-service",
        "created": ANY,
        "expires": int(token_data.expires.timestamp()),
        "parent": token_data.token.key,
    }

    # If the intersection of desired and available scopes is empty, we still
    # get a token with no scopes.
    r = await client.get(
        "/auth",
        params={
            "scope": "read:some",
            "delegate_to": "a-service",
            "delegate_scope": "read:all",
        },
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    internal_token = Token.from_str(r.headers["X-Auth-Request-Token"])

    r = await client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"Bearer {internal_token}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "token": internal_token.key,
        "username": token_data.username,
        "token_type": "internal",
        "scopes": [],
        "service": "a-service",
        "created": ANY,
        "expires": int(token_data.expires.timestamp()),
        "parent": token_data.token.key,
    }


@pytest.mark.asyncio
async def test_internal_errors(
    client: AsyncClient, factory: Factory, mock_slack: MockSlack
) -> None:
    token_data = await create_session_token(factory, scopes=["read:some"])

    # Cannot request a notebook token and an internal token at the same time.
    r = await client.get(
        "/auth",
        params={
            "scope": "read:some",
            "notebook": "true",
            "delegate_to": "a-service",
            "delegate_scope": "read:some",
        },
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 422

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_success_any(client: AsyncClient, factory: Factory) -> None:
    """Test ``satisfy=any`` as an ``/auth`` parameter.

    Ask for either ``exec:admin`` or ``exec:test`` and pass in credentials
    with only ``exec:test``.  Ensure they are accepted.
    """
    token_data = await create_session_token(
        factory, group_names=["test"], scopes=["exec:test"]
    )

    r = await client.get(
        "/auth",
        params=[
            ("scope", "exec:admin"),
            ("scope", "exec:test"),
            ("satisfy", "any"),
        ],
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == token_data.username


@pytest.mark.asyncio
async def test_basic(client: AsyncClient, factory: Factory) -> None:
    token_data = await create_session_token(
        factory, group_names=["test"], scopes=["exec:admin"]
    )

    basic = f"{token_data.token}:x-oauth-basic".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == token_data.username

    basic = f"x-oauth-basic:{token_data.token}".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic  {basic_b64}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == token_data.username

    # We currently fall back on using the username if x-oauth-basic doesn't
    # appear anywhere in the auth string.
    basic = f"{token_data.token}:something-else".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == token_data.username


@pytest.mark.asyncio
async def test_basic_failure(
    client: AsyncClient, config: Config, mock_slack: MockSlack
) -> None:
    basic_b64 = base64.b64encode(b"bogus-string").decode()
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config.realm
    assert authenticate.error == AuthError.invalid_request

    for basic in (b"foo:foo", b"x-oauth-basic:foo", b"foo:x-oauth-basic"):
        basic_b64 = base64.b64encode(basic).decode()
        r = await client.get(
            "/auth",
            params={"scope": "exec:admin", "auth_type": "basic"},
            headers={"Authorization": f"Basic {basic_b64}"},
        )
        assert_unauthorized_is_correct(r, config, AuthType.Basic)

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_ajax_unauthorized(client: AsyncClient, config: Config) -> None:
    """Test that AJAX requests without auth get 403, not 401."""
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert r.status_code == 403
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config.realm


@pytest.mark.asyncio
async def test_success_unicode_name(
    client: AsyncClient, factory: Factory
) -> None:
    user_info = TokenUserInfo(username="user", uid=1234, name="名字")
    token_service = factory.create_token_service()
    async with factory.session.begin():
        token = await token_service.create_session_token(
            user_info, scopes=["read:all"], ip_address="127.0.0.1"
        )

    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "user"


@pytest.mark.asyncio
async def test_minimum_lifetime(
    config: Config, client: AsyncClient, factory: Factory
) -> None:
    user_info = TokenUserInfo(username="user", uid=1234, name="Some User")
    token_service = factory.create_token_service()
    async with factory.session.begin():
        token = await token_service.create_session_token(
            user_info,
            scopes=["read:all", "user:token"],
            ip_address="127.0.0.1",
        )
        token_data = await token_service.get_data(token)
        assert token_data

    # Required lifetime is within MINIMUM_LIFETIME of maximum token lifetime.
    minimum_lifetime = MINIMUM_LIFETIME - timedelta(seconds=1)
    r = await client.get(
        "/auth",
        params={
            "scope": "read:all",
            "notebook": "true",
            "minimum_lifetime": int(
                (config.token_lifetime - minimum_lifetime).total_seconds()
            ),
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "invalid_minimum_lifetime"

    # Create a user token with a short lifetime.
    async with factory.session.begin():
        expires = current_datetime() + timedelta(hours=1)
        token = await token_service.create_user_token(
            token_data,
            "user",
            token_name="token",
            scopes=["read:all"],
            expires=expires,
            ip_address="127.0.0.1",
        )

    # Try to authenticate with a longer requested lifetime.
    r = await client.get(
        "/auth",
        params={
            "scope": "read:all",
            "notebook": "true",
            "minimum_lifetime": 4000,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.error == AuthError.invalid_token

    # Required lifetime is shorter than token lifetime.
    r = await client.get(
        "/auth",
        params={
            "scope": "read:all",
            "notebook": "true",
            "minimum_lifetime": 3000,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200

    # If this is an AJAX request, we should return 403 rather than 401 if the
    # required lifetime isn't long enough, to avoid the redirect spam from
    # failing AJAX requests.
    r = await client.get(
        "/auth",
        params={
            "scope": "read:all",
            "notebook": "true",
            "minimum_lifetime": 4000,
        },
        headers={
            "Authorization": f"Bearer {token}",
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    assert r.status_code == 403
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.error == AuthError.invalid_token


@pytest.mark.asyncio
async def test_default_minimum_lifetime(
    config: Config, client: AsyncClient, factory: Factory
) -> None:
    user_info = TokenUserInfo(username="user", uid=1234, name="Some User")
    token_service = factory.create_token_service()

    # Create a token and then change it to expire in one minute.  We only
    # change Redis, which is canonical; no need to change the database as
    # well.
    async with factory.session.begin():
        token = await token_service.create_session_token(
            user_info, scopes=["user:token"], ip_address="127.0.0.1"
        )
        token_data = await token_service.get_data(token)
        assert token_data
        token_data.expires = current_datetime() + timedelta(minutes=1)
        await token_service._token_redis_store.store_data(token_data)

    # Check that one can authenticate with this token.
    r = await client.get(
        "/auth",
        params={"scope": "user:token"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200

    # Attempt to get an internal and a notebook token with no required minimum
    # lifetime.  Both should fail because the created tokens would not have a
    # long enough lifetime.
    r = await client.get(
        "/auth",
        params={"scope": "user:token", "notebook": "true"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.error == AuthError.invalid_token
    r = await client.get(
        "/auth",
        params={"scope": "user:token", "delegate_to": "some-service"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.error == AuthError.invalid_token


@pytest.mark.asyncio
async def test_authorization_filtering(
    client: AsyncClient, factory: Factory
) -> None:
    token_data = await create_session_token(factory, scopes=["read:all"])

    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    assert "Authorization" not in r.headers

    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers={"Authorization": f"bearer {token_data.token}"},
    )
    assert r.status_code == 200
    assert "Authorization" not in r.headers

    basic = f"{token_data.token}:x-oauth-basic".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers=[
            ("Authorization", f"Basic {basic_b64}"),
            ("Authorization", "token some-other-token"),
        ],
    )
    assert r.status_code == 200
    assert r.headers["Authorization"] == "token some-other-token"

    basic = f"x-oauth-basic:{token_data.token}".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers=[
            ("Authorization", f"BASIC {basic_b64}"),
            ("Authorization", f"bearer {token_data.token}"),
        ],
    )
    assert r.status_code == 200
    assert "Authorization" not in r.headers

    basic = f"{token_data.token}:something-else".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 200
    assert "Authorization" not in r.headers

    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers=[
            ("Authorization", f"Basic  {basic_b64}"),
            ("Authorization", "some broken stuff"),
            ("Authorization", f"BEARER   {token_data.token}"),
            ("Authorization", "basic"),
            ("Authorization", "basic notreally:base64"),
        ],
    )
    assert r.status_code == 200
    assert r.headers.get_list("Authorization") == [
        "some broken stuff",
        "basic",
        "basic notreally:base64",
    ]


@pytest.mark.asyncio
async def test_cookie_filtering(client: AsyncClient, factory: Factory) -> None:
    token_data = await create_session_token(factory, scopes=["read:all"])
    await set_session_cookie(client, token_data.token)

    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert "Cookie" not in r.headers

    client.cookies.set("_other", "somevalue", domain=TEST_HOSTNAME)
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["Cookie"] == "_other=somevalue"

    clear_session_cookie(client)
    del client.cookies["_other"]
    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers={
            "Authorization": f"bearer {token_data.token}",
            "Cookie": f"foo=bar; {COOKIE_NAME}=blah; {COOKIE_NAME}blah=blah",
        },
    )
    assert r.status_code == 200
    assert r.headers["Cookie"] == f"foo=bar; {COOKIE_NAME}blah=blah"

    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers=[
            ("Authorization", f"bearer {token_data.token}"),
            ("Cookie", f"{COOKIE_NAME}=blah; foo=bar; invalid"),
            ("Cookie", f"also invalid; {COOKIE_NAME}=stuff"),
            ("Cookie", f"{COOKIE_NAME}stuff"),
        ],
    )
    assert r.status_code == 200
    assert r.headers.get_list("Cookie") == [
        "foo=bar; invalid",
        "also invalid",
        f"{COOKIE_NAME}stuff",
    ]


@pytest.mark.asyncio
async def test_delegate_authorization(
    client: AsyncClient, factory: Factory
) -> None:
    token_data = await create_session_token(factory, scopes=["read:all"])

    r = await client.get(
        "/auth",
        params={
            "scope": "read:all",
            "notebook": "true",
            "use_authorization": "true",
        },
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    notebook_token = r.headers["X-Auth-Request-Token"]
    assert notebook_token != token_data.token
    assert r.headers["Authorization"] == f"Bearer {notebook_token}"

    r = await client.get(
        "/auth",
        params={
            "scope": "read:all",
            "delegate_to": "service",
            "delegate_scopes": "read:all",
            "use_authorization": "true",
        },
        headers=[
            ("Authorization", f"Bearer {token_data.token}"),
            ("Authorization", "token some-other-token"),
        ],
    )
    assert r.status_code == 200
    internal_token = r.headers["X-Auth-Request-Token"]
    assert internal_token != token_data.token
    assert internal_token != notebook_token
    assert r.headers["Authorization"] == f"Bearer {internal_token}"

    # If there's no delegation but use_authorization is true, don't pass along
    # any Authorization headers.
    r = await client.get(
        "/auth",
        params={"scope": "read:all", "use_authorization": "true"},
        headers=[
            ("Authorization", f"Bearer {token_data.token}"),
            ("Authorization", "token some-other-token"),
        ],
    )
    assert r.status_code == 200
    assert "Authorization" not in r.headers
