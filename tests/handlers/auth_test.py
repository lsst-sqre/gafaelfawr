"""Tests for the /auth route."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest

from gafaelfawr.auth import AuthError, AuthErrorChallenge, AuthType
from gafaelfawr.models.token import Token
from tests.support.headers import parse_www_authenticate

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_no_auth(setup: SetupTest) -> None:
    r = await setup.client.get("/auth", params={"scope": "exec:admin"})
    assert r.status_code == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm

    r = await setup.client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "bearer"}
    )
    assert r.status_code == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm

    r = await setup.client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "bogus"}
    )
    assert r.status_code == 422

    r = await setup.client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "basic"}
    )
    assert r.status_code == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Basic
    assert authenticate.realm == setup.config.realm


@pytest.mark.asyncio
async def test_invalid(setup: SetupTest) -> None:
    token = await setup.create_session_token()
    print(token.token)
    r = await setup.client.get(
        "/auth", headers={"Authorization": f"bearer {token.token}"}
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "value_error.missing"

    r = await setup.client.get(
        "/auth",
        headers={"Authorization": f"bearer {token.token}"},
        params={"scope": "exec:admin", "satisfy": "foo"},
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "type_error.enum"

    r = await setup.client.get(
        "/auth",
        headers={"Authorization": f"bearer {token.token}"},
        params={"scope": "exec:admin", "auth_type": "foo"},
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "type_error.enum"


@pytest.mark.asyncio
async def test_invalid_auth(setup: SetupTest) -> None:
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer"},
    )
    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_request

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "token foo"},
    )
    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_request

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer token"},
    )
    assert r.status_code == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_token

    # Create a nonexistent token.
    token = Token()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_token


@pytest.mark.asyncio
async def test_access_denied(setup: SetupTest) -> None:
    token_data = await setup.create_session_token()

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "exec:admin"
    assert "Token missing required scope" in r.text


@pytest.mark.asyncio
async def test_auth_forbidden(setup: SetupTest) -> None:
    r = await setup.client.get(
        "/auth/forbidden",
        params=[("scope", "exec:test"), ("scope", "exec:admin")],
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "exec:admin exec:test"
    assert "Token missing required scope" in r.text

    r = await setup.client.get(
        "/auth/forbidden", params={"scope": "exec:admin", "auth_type": "basic"}
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Basic
    assert authenticate.realm == setup.config.realm
    assert "Token missing required scope" in r.text


@pytest.mark.asyncio
async def test_satisfy_all(setup: SetupTest) -> None:
    token_data = await setup.create_session_token(scopes=["exec:test"])

    r = await setup.client.get(
        "/auth",
        params=[("scope", "exec:test"), ("scope", "exec:admin")],
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "exec:admin exec:test"
    assert "Token missing required scope" in r.text


@pytest.mark.asyncio
async def test_success(setup: SetupTest) -> None:
    token_data = await setup.create_session_token(
        group_names=["admin"], scopes=["exec:admin", "read:all"]
    )

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"Bearer {token_data.token}",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Client-Ip"] == "192.0.2.1"
    assert r.headers["X-Auth-Request-Token-Scopes"] == "exec:admin read:all"
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-User"] == token_data.username
    assert r.headers["X-Auth-Request-Uid"] == str(token_data.uid)
    assert r.headers["X-Auth-Request-Groups"] == "admin"


@pytest.mark.asyncio
async def test_notebook(setup: SetupTest) -> None:
    token_data = await setup.create_session_token(
        group_names=["admin"], scopes=["exec:admin", "read:all"]
    )
    assert token_data.expires

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin", "notebook": "true"},
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    notebook_token = Token.from_str(r.headers["X-Auth-Request-Token"])
    assert notebook_token != token_data.token

    r = await setup.client.get(
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

    # Requesting a token with the same parameters returns the same token.
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin", "notebook": "true"},
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    assert notebook_token == Token.from_str(r.headers["X-Auth-Request-Token"])


@pytest.mark.asyncio
async def test_internal(setup: SetupTest) -> None:
    token_data = await setup.create_session_token(
        group_names=["admin"], scopes=["exec:admin", "read:all", "read:some"]
    )
    assert token_data.expires

    r = await setup.client.get(
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

    r = await setup.client.get(
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

    # Requesting a token with the same parameters returns the same token.
    r = await setup.client.get(
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
async def test_internal_errors(setup: SetupTest) -> None:
    token_data = await setup.create_session_token(scopes=["read:some"])

    # Delegating a token with a scope the original doesn't have will fail.
    r = await setup.client.get(
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
    r = await setup.client.get(
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


@pytest.mark.asyncio
async def test_success_any(setup: SetupTest) -> None:
    """Test ``satisfy=any`` as an ``/auth`` parameter.

    Ask for either ``exec:admin`` or ``exec:test`` and pass in credentials
    with only ``exec:test``.  Ensure they are accepted but also the headers
    don't claim the client has ``exec:admin``.
    """
    token_data = await setup.create_session_token(
        group_names=["test"], scopes=["exec:test"]
    )

    r = await setup.client.get(
        "/auth",
        params=[
            ("scope", "exec:admin"),
            ("scope", "exec:test"),
            ("satisfy", "any"),
        ],
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    scopes = "exec:admin exec:test"
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == "exec:test"
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == scopes
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "any"
    assert r.headers["X-Auth-Request-Groups"] == "test"


@pytest.mark.asyncio
async def test_basic(setup: SetupTest) -> None:
    token_data = await setup.create_session_token(
        group_names=["test"], scopes=["exec:admin"]
    )

    basic = f"{token_data.token}:x-oauth-basic".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == token_data.username

    basic = f"x-oauth-basic:{token_data.token}".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
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
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == token_data.username


@pytest.mark.asyncio
async def test_basic_failure(setup: SetupTest) -> None:
    basic_b64 = base64.b64encode(b"bogus-string").decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_request

    for basic in (b"foo:foo", b"x-oauth-basic:foo", b"foo:x-oauth-basic"):
        basic_b64 = base64.b64encode(basic).decode()
        r = await setup.client.get(
            "/auth",
            params={"scope": "exec:admin", "auth_type": "basic"},
            headers={"Authorization": f"Basic {basic_b64}"},
        )
        assert r.status_code == 401
        authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
        assert not isinstance(authenticate, AuthErrorChallenge)
        assert authenticate.auth_type == AuthType.Basic
        assert authenticate.realm == setup.config.realm


@pytest.mark.asyncio
async def test_ajax_unauthorized(setup: SetupTest) -> None:
    """Test that AJAX requests without auth get 403, not 401."""
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert r.status_code == 403
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
