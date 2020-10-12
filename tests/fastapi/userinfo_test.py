"""Tests for the ``/auth/userinfo`` route."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import ANY

from gafaelfawr.fastapi.dependencies import config
from gafaelfawr.handlers.util import AuthError, AuthErrorChallenge, AuthType
from tests.support.app import create_fastapi_test_app, create_test_client
from tests.support.headers import parse_www_authenticate
from tests.support.tokens import create_test_token

if TYPE_CHECKING:
    from pathlib import Path

    from _pytest.logging import LogCaptureFixture


async def test_userinfo(tmp_path: Path, caplog: LogCaptureFixture) -> None:
    app = await create_fastapi_test_app(tmp_path)
    token = create_test_token(config())

    caplog.clear()
    async with create_test_client(app) as client:
        r = await client.get(
            "/auth/userinfo",
            headers={"Authorization": f"Bearer {token.encoded}"},
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


async def test_no_auth(tmp_path: Path, caplog: LogCaptureFixture) -> None:
    app = await create_fastapi_test_app(tmp_path)

    caplog.clear()
    async with create_test_client(app) as client:
        r = await client.get("/auth/userinfo")

    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config().realm

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


async def test_invalid(tmp_path: Path, caplog: LogCaptureFixture) -> None:
    app = await create_fastapi_test_app(tmp_path)
    token = create_test_token(config())

    caplog.clear()
    async with create_test_client(app) as client:
        r = await client.get(
            "/auth/userinfo",
            headers={"Authorization": f"token {token.encoded}"},
        )

    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config().realm
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

    async with create_test_client(app) as client:
        r = await client.get(
            "/auth/userinfo",
            headers={"Authorization": f"bearer{token.encoded}"},
        )

    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config().realm
    assert authenticate.error == AuthError.invalid_request
    assert authenticate.error_description == "Malformed Authorization header"

    caplog.clear()
    async with create_test_client(app) as client:
        r = await client.get(
            "/auth/userinfo",
            headers={"Authorization": f"bearer XXX{token.encoded}"},
        )

    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config().realm
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
