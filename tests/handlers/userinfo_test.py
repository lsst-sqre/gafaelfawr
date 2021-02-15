"""Tests for the ``/auth/userinfo`` route."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest

from gafaelfawr.auth import AuthError, AuthErrorChallenge, AuthType
from tests.support.headers import parse_www_authenticate

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture

    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_userinfo(setup: SetupTest) -> None:
    token_data = await setup.create_session_token()
    issuer = setup.factory.create_token_issuer()
    oidc_token = issuer.issue_token(token_data, jti="some-jti")

    r = await setup.client.get(
        "/auth/userinfo",
        headers={"Authorization": f"Bearer {oidc_token.encoded}"},
    )

    assert r.status_code == 200
    assert r.json() == oidc_token.claims


@pytest.mark.asyncio
async def test_no_auth(setup: SetupTest) -> None:
    r = await setup.client.get("/auth/userinfo")

    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm


@pytest.mark.asyncio
async def test_invalid(setup: SetupTest, caplog: LogCaptureFixture) -> None:
    token_data = await setup.create_session_token()
    issuer = setup.factory.create_token_issuer()
    oidc_token = issuer.issue_token(token_data, jti="some-jti")

    caplog.clear()
    r = await setup.client.get(
        "/auth/userinfo",
        headers={"Authorization": f"token {oidc_token.encoded}"},
    )

    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_request
    assert authenticate.error_description == "Unknown Authorization type token"

    log = json.loads(caplog.record_tuples[0][2])
    assert log == {
        "error": "Unknown Authorization type token",
        "event": "Invalid request",
        "level": "warning",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth/userinfo",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "user_agent": ANY,
    }

    r = await setup.client.get(
        "/auth/userinfo",
        headers={"Authorization": f"bearer{oidc_token.encoded}"},
    )

    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_request
    assert authenticate.error_description == "Malformed Authorization header"

    caplog.clear()
    r = await setup.client.get(
        "/auth/userinfo",
        headers={"Authorization": f"bearer XXX{oidc_token.encoded}"},
    )

    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_token
    assert authenticate.error_description

    log = json.loads(caplog.record_tuples[0][2])
    assert log == {
        "error": ANY,
        "event": "Invalid token",
        "level": "warning",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth/userinfo",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "token_source": "bearer",
        "user_agent": ANY,
    }
