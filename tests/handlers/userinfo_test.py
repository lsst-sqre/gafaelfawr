"""Tests for the ``/auth/userinfo`` route."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import ANY

from gafaelfawr.auth import AuthError, AuthErrorChallenge, AuthType
from tests.support.headers import parse_www_authenticate

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture
    from httpx import AsyncClient

    from tests.setup import SetupTest


async def test_userinfo(
    setup: SetupTest, client: AsyncClient, caplog: LogCaptureFixture
) -> None:
    token = setup.create_token()

    caplog.clear()
    r = await client.get(
        "/auth/userinfo", headers={"Authorization": f"Bearer {token.encoded}"}
    )

    assert r.status_code == 200
    assert r.json() == token.claims

    log = json.loads(caplog.record_tuples[0][2])
    assert log == {
        "event": "Returned user information",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth/userinfo",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "scope": "",
        "token": token.jti,
        "token_source": "bearer",
        "user": token.username,
        "user_agent": ANY,
    }


async def test_no_auth(
    setup: SetupTest, client: AsyncClient, caplog: LogCaptureFixture
) -> None:
    caplog.clear()
    r = await client.get("/auth/userinfo")

    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm

    log = json.loads(caplog.record_tuples[0][2])
    assert log == {
        "event": "No token found, returning unauthorized",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth/userinfo",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "user_agent": ANY,
    }


async def test_invalid(
    setup: SetupTest, client: AsyncClient, caplog: LogCaptureFixture
) -> None:
    token = setup.create_token()

    caplog.clear()
    r = await client.get(
        "/auth/userinfo", headers={"Authorization": f"token {token.encoded}"}
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

    r = await client.get(
        "/auth/userinfo", headers={"Authorization": f"bearer{token.encoded}"}
    )

    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_request
    assert authenticate.error_description == "Malformed Authorization header"

    caplog.clear()
    r = await client.get(
        "/auth/userinfo",
        headers={"Authorization": f"bearer XXX{token.encoded}"},
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
