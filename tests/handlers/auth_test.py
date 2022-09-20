"""Tests for the /auth route."""

from __future__ import annotations

import base64
from datetime import timedelta
from unittest.mock import ANY

import pytest
from httpx import AsyncClient

from gafaelfawr.auth import AuthError, AuthErrorChallenge, AuthType
from gafaelfawr.config import Config
from gafaelfawr.constants import MINIMUM_LIFETIME
from gafaelfawr.factory import Factory
from gafaelfawr.models.token import Token, TokenUserInfo
from gafaelfawr.util import current_datetime

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
        headers={"Authorization": f"Bearer {token}"},
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
async def test_internal_errors(
    client: AsyncClient, factory: Factory, mock_slack: MockSlack
) -> None:
    token_data = await create_session_token(factory, scopes=["read:some"])

    # Delegating a token with a scope the original doesn't have will fail.
    r = await client.get(
        "/auth",
        params={
            "scope": "read:some",
            "delegate_to": "a-service",
            "delegate_scope": "read:all",
        },
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "read:all read:some"

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
        headers={"Authorization": f"Basic {basic_b64}"},
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
async def test_required_lifetime(
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
    minimum_lifetime = timedelta(seconds=MINIMUM_LIFETIME - 1)
    r = await client.get(
        "/auth",
        params={
            "scope": "read:all",
            "notebook": "true",
            "required_lifetime": int(
                (config.token_lifetime - minimum_lifetime).total_seconds()
            ),
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "invalid_required_lifetime"

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
            "required_lifetime": 4000,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
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
            "required_lifetime": 3000,
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
            "required_lifetime": 4000,
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
