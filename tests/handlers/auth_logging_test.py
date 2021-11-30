"""Tests for logging in the /auth route."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

from tests.support.logging import parse_log
from tests.support.tokens import create_session_token

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture
    from httpx import AsyncClient

    from gafaelfawr.factory import ComponentFactory


@pytest.mark.asyncio
async def test_success(
    client: AsyncClient, factory: ComponentFactory, caplog: LogCaptureFixture
) -> None:
    token_data = await create_session_token(factory, scopes=["exec:admin"])

    # Successful request with X-Forwarded-For and a bearer token.
    caplog.clear()
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"Bearer {token_data.token}",
            "X-Original-Uri": "/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    expected_log = {
        "auth_uri": "/foo",
        "event": "Token authorized",
        "level": "info",
        "method": "GET",
        "path": "/auth",
        "remote": "192.0.2.1",
        "required_scope": "exec:admin",
        "satisfy": "all",
        "scope": "exec:admin",
        "token": token_data.token.key,
        "token_source": "bearer",
        "user": token_data.username,
    }
    assert parse_log(caplog) == [expected_log]

    # Successful request with HTTP Basic authentication in the username.
    basic = f"{token_data.token}:x-oauth-basic".encode()
    basic_b64 = base64.b64encode(basic).decode()
    caplog.clear()
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"Basic {basic_b64}",
            "X-Original-Uri": "/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    expected_log["token_source"] = "basic-username"
    assert parse_log(caplog) == [expected_log]

    # The same with HTTP Basic in the password.
    basic = f"x-oauth-basic:{token_data.token}".encode()
    basic_b64 = base64.b64encode(basic).decode()
    caplog.clear()
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"Basic {basic_b64}",
            "X-Original-Uri": "/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    expected_log["token_source"] = "basic-password"
    assert parse_log(caplog) == [expected_log]


@pytest.mark.asyncio
async def test_authorization_failed(
    client: AsyncClient, factory: ComponentFactory, caplog: LogCaptureFixture
) -> None:
    token_data = await create_session_token(factory, scopes=["exec:admin"])

    caplog.clear()
    r = await client.get(
        "/auth",
        params={"scope": "exec:test", "satisfy": "any"},
        headers={
            "Authorization": f"Bearer {token_data.token}",
            "X-Original-Uri": "/foo",
        },
    )

    assert r.status_code == 403
    assert parse_log(caplog) == [
        {
            "auth_uri": "/foo",
            "error": "Token missing required scope",
            "event": "Permission denied",
            "level": "warning",
            "method": "GET",
            "path": "/auth",
            "remote": "127.0.0.1",
            "required_scope": "exec:test",
            "satisfy": "any",
            "scope": "exec:admin",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        }
    ]


@pytest.mark.asyncio
async def test_original_url(
    client: AsyncClient, factory: ComponentFactory, caplog: LogCaptureFixture
) -> None:
    token_data = await create_session_token(factory)

    caplog.clear()
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"bearer {token_data.token}",
            "X-Original-Url": "https://example.com/test",
        },
    )
    assert r.status_code == 403
    expected_log = {
        "auth_uri": "https://example.com/test",
        "error": "Token missing required scope",
        "event": "Permission denied",
        "level": "warning",
        "method": "GET",
        "path": "/auth",
        "remote": "127.0.0.1",
        "required_scope": "exec:admin",
        "satisfy": "all",
        "scope": "user:token",
        "token": token_data.token.key,
        "token_source": "bearer",
        "user": token_data.username,
    }
    assert parse_log(caplog) == [expected_log]

    # Check with both X-Original-URI and X-Original-URL.  The former should
    # override the latter.
    caplog.clear()
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"bearer {token_data.token}",
            "X-Original-URI": "/foo",
            "X-Original-URL": "https://example.com/test",
        },
    )
    assert r.status_code == 403
    expected_log["auth_uri"] = "/foo"
    assert parse_log(caplog) == [expected_log]


@pytest.mark.asyncio
async def test_chained_x_forwarded(
    client: AsyncClient, factory: ComponentFactory, caplog: LogCaptureFixture
) -> None:
    token_data = await create_session_token(factory)

    caplog.clear()
    r = await client.get(
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
    assert parse_log(caplog) == [
        {
            "auth_uri": "/foo",
            "error": "Token missing required scope",
            "event": "Permission denied",
            "level": "warning",
            "method": "GET",
            "path": "/auth",
            "remote": "2001:db8:85a3:8d3:1319:8a2e:370:734",
            "required_scope": "exec:admin",
            "satisfy": "all",
            "scope": "user:token",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        }
    ]


@pytest.mark.asyncio
async def test_invalid_token(
    client: AsyncClient, caplog: LogCaptureFixture
) -> None:
    caplog.clear()
    r = await client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer blah"},
    )

    assert r.status_code == 401
    assert parse_log(caplog) == [
        {
            "auth_uri": "NONE",
            "error": "Token does not start with gt-",
            "event": "Invalid token",
            "level": "warning",
            "method": "GET",
            "path": "/auth",
            "remote": "127.0.0.1",
            "required_scope": "exec:admin",
            "satisfy": "all",
            "token_source": "bearer",
        }
    ]
