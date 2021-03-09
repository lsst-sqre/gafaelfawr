"""Tests for logging in the /auth route."""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture

    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_success(setup: SetupTest, caplog: LogCaptureFixture) -> None:
    token_data = await setup.create_session_token(scopes=["exec:admin"])

    # Successful request with X-Forwarded-For and a bearer token.
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"Bearer {token_data.token}",
            "X-Original-Uri": "/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    expected = {
        "auth_uri": "/foo",
        "event": "Token authorized",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth",
        "remote": "192.0.2.1",
        "request_id": ANY,
        "required_scope": "exec:admin",
        "satisfy": "all",
        "scope": "exec:admin",
        "token": token_data.token.key,
        "token_source": "bearer",
        "user": token_data.username,
        "user_agent": ANY,
    }
    data = json.loads(caplog.record_tuples[-1][2])
    assert data == expected

    # Successful request with HTTP Basic authentication in the username.
    basic = f"{token_data.token}:x-oauth-basic".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"Basic {basic_b64}",
            "X-Original-Uri": "/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    expected["token_source"] = "basic-username"
    data = json.loads(caplog.record_tuples[-1][2])
    assert data == expected

    # The same with HTTP Basic in the password.
    basic = f"x-oauth-basic:{token_data.token}".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"Basic {basic_b64}",
            "X-Original-Uri": "/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    expected["token_source"] = "basic-password"
    data = json.loads(caplog.record_tuples[-1][2])
    assert data == expected


@pytest.mark.asyncio
async def test_authorization_failed(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    token_data = await setup.create_session_token(scopes=["exec:admin"])

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:test", "satisfy": "any"},
        headers={
            "Authorization": f"Bearer {token_data.token}",
            "X-Original-Uri": "/foo",
        },
    )

    assert r.status_code == 403
    data = json.loads(caplog.record_tuples[-1][2])
    assert data == {
        "auth_uri": "/foo",
        "error": "Token missing required scope",
        "event": "Permission denied",
        "level": "warning",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "required_scope": "exec:test",
        "satisfy": "any",
        "scope": "exec:admin",
        "token": token_data.token.key,
        "token_source": "bearer",
        "user": token_data.username,
        "user_agent": ANY,
    }


@pytest.mark.asyncio
async def test_original_url(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    token_data = await setup.create_session_token()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"bearer {token_data.token}",
            "X-Original-Url": "https://example.com/test",
        },
    )
    assert r.status_code == 403
    expected = {
        "auth_uri": "https://example.com/test",
        "error": "Token missing required scope",
        "event": "Permission denied",
        "level": "warning",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "required_scope": "exec:admin",
        "satisfy": "all",
        "scope": "user:token",
        "token": token_data.token.key,
        "token_source": "bearer",
        "user": token_data.username,
        "user_agent": ANY,
    }
    data = json.loads(caplog.record_tuples[-1][2])
    assert data == expected

    # Check with both X-Original-URI and X-Original-URL.  The former should
    # override the latter.
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"bearer {token_data.token}",
            "X-Original-URI": "/foo",
            "X-Original-URL": "https://example.com/test",
        },
    )
    assert r.status_code == 403
    expected["auth_uri"] = "/foo"
    data = json.loads(caplog.record_tuples[-1][2])
    assert data == expected


@pytest.mark.asyncio
async def test_chained_x_forwarded(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    token_data = await setup.create_session_token()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"bearer {token_data.token}",
            "X-Forwarded-For": "2001:db8:85a3:8d3:1319:8a2e:370:734, 10.0.0.1",
            "X-Forwarded-Proto": "https, http",
            "X-Original-Uri": "/foo",
        },
    )

    assert r.status_code == 403
    data = json.loads(caplog.record_tuples[-1][2])
    assert data == {
        "auth_uri": "/foo",
        "error": "Token missing required scope",
        "event": "Permission denied",
        "level": "warning",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth",
        "remote": "2001:db8:85a3:8d3:1319:8a2e:370:734",
        "request_id": ANY,
        "required_scope": "exec:admin",
        "satisfy": "all",
        "scope": "user:token",
        "token": token_data.token.key,
        "token_source": "bearer",
        "user": token_data.username,
        "user_agent": ANY,
    }


@pytest.mark.asyncio
async def test_invalid_token(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer blah"},
    )
    assert r.status_code == 401
    data = json.loads(caplog.record_tuples[-1][2])
    assert data == {
        "auth_uri": "NONE",
        "error": "Token does not start with gt-",
        "event": "Invalid token",
        "level": "warning",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "required_scope": "exec:admin",
        "satisfy": "all",
        "token_source": "bearer",
        "user_agent": ANY,
    }
