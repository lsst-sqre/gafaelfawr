"""Tests for logging and metrics in the ``/ingress/auth`` route."""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import ANY

import pytest
from httpx import AsyncClient
from safir.datetime import format_datetime_for_logging
from safir.metrics import MockEventPublisher

from gafaelfawr.dependencies.context import context_dependency
from gafaelfawr.factory import Factory
from gafaelfawr.models.token import Token

from ..support.constants import TEST_HOSTNAME
from ..support.logging import parse_log
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_success(
    client: AsyncClient, factory: Factory, caplog: pytest.LogCaptureFixture
) -> None:
    token_data = await create_session_token(factory, scopes={"exec:admin"})

    # Successful request with X-Forwarded-For and a bearer token.
    caplog.clear()
    r = await client.get(
        "/ingress/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"Bearer {token_data.token}",
            "X-Original-Uri": "/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    expected_log: dict[str, Any] = {
        "auth_uri": "/foo",
        "event": "Token authorized",
        "httpRequest": {
            "requestMethod": "GET",
            "requestUrl": (
                f"https://{TEST_HOSTNAME}/ingress/auth?scope=exec%3Aadmin"
            ),
            "remoteIp": "192.0.2.1",
        },
        "required_scopes": ["exec:admin"],
        "satisfy": "all",
        "scopes": ["exec:admin"],
        "severity": "info",
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
        "/ingress/auth",
        params={"scope": "exec:admin", "service": "service-one"},
        headers={
            "Authorization": f"Basic {basic_b64}",
            "X-Original-Uri": "/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    url = expected_log["httpRequest"]["requestUrl"]
    expected_log["httpRequest"]["requestUrl"] += "&service=service-one"
    expected_log["token_source"] = "basic-username"
    assert parse_log(caplog) == [expected_log]

    # The same with HTTP Basic in the password.
    basic = f"x-oauth-basic:{token_data.token}".encode()
    basic_b64 = base64.b64encode(basic).decode()
    caplog.clear()
    r = await client.get(
        "/ingress/auth",
        params={"scope": "exec:admin", "service": "service-two"},
        headers={
            "Authorization": f"Basic {basic_b64}",
            "X-Original-Uri": "/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    expected_log["httpRequest"]["requestUrl"] = url + "&service=service-two"
    expected_log["token_source"] = "basic-password"
    assert parse_log(caplog) == [expected_log]

    # Check the logged metrics events.
    events = context_dependency._events
    assert events
    assert isinstance(events.auth_user, MockEventPublisher)
    events.auth_user.published.assert_published_all(
        [
            {"username": token_data.username, "service": None},
            {"username": token_data.username, "service": "service-one"},
            {"username": token_data.username, "service": "service-two"},
        ]
    )
    assert isinstance(events.auth_bot, MockEventPublisher)
    events.auth_bot.published.assert_published_all([])


@pytest.mark.asyncio
async def test_authz_failed(
    client: AsyncClient, factory: Factory, caplog: pytest.LogCaptureFixture
) -> None:
    token_data = await create_session_token(factory, scopes={"exec:admin"})

    caplog.clear()
    r = await client.get(
        "/ingress/auth",
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
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": (
                    f"https://{TEST_HOSTNAME}/ingress/auth"
                    "?scope=exec%3Atest&satisfy=any"
                ),
                "remoteIp": "127.0.0.1",
            },
            "required_scopes": ["exec:test"],
            "satisfy": "any",
            "scopes": ["exec:admin"],
            "severity": "warning",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        }
    ]


@pytest.mark.asyncio
async def test_original_url(
    client: AsyncClient, factory: Factory, caplog: pytest.LogCaptureFixture
) -> None:
    token_data = await create_session_token(factory)

    caplog.clear()
    r = await client.get(
        "/ingress/auth",
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
        "httpRequest": {
            "requestMethod": "GET",
            "requestUrl": (
                f"https://{TEST_HOSTNAME}/ingress/auth?scope=exec%3Aadmin"
            ),
            "remoteIp": "127.0.0.1",
        },
        "required_scopes": ["exec:admin"],
        "satisfy": "all",
        "scopes": ["user:token"],
        "severity": "warning",
        "token": token_data.token.key,
        "token_source": "bearer",
        "user": token_data.username,
    }
    assert parse_log(caplog) == [expected_log]

    # Check with both X-Original-URI and X-Original-URL.  The former should
    # override the latter.
    caplog.clear()
    r = await client.get(
        "/ingress/auth",
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
async def test_x_forwarded(
    client: AsyncClient, factory: Factory, caplog: pytest.LogCaptureFixture
) -> None:
    token_data = await create_session_token(factory)

    caplog.clear()
    r = await client.get(
        "/ingress/auth",
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
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": (
                    f"https://{TEST_HOSTNAME}/ingress/auth?scope=exec%3Aadmin"
                ),
                "remoteIp": "2001:db8:85a3:8d3:1319:8a2e:370:734",
            },
            "required_scopes": ["exec:admin"],
            "satisfy": "all",
            "scopes": ["user:token"],
            "severity": "warning",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        }
    ]


@pytest.mark.asyncio
async def test_invalid_token(
    client: AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.clear()
    r = await client.get(
        "/ingress/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer blah", "X-Original-Uri": "/foo"},
    )

    assert r.status_code == 401
    assert parse_log(caplog) == [
        {
            "auth_uri": "/foo",
            "error": "Token does not start with gt-",
            "event": "Invalid token",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": (
                    f"https://{TEST_HOSTNAME}/ingress/auth?scope=exec%3Aadmin"
                ),
                "remoteIp": "127.0.0.1",
            },
            "required_scopes": ["exec:admin"],
            "satisfy": "all",
            "severity": "warning",
            "token_source": "bearer",
        }
    ]


@pytest.mark.asyncio
async def test_notebook(
    client: AsyncClient, factory: Factory, caplog: pytest.LogCaptureFixture
) -> None:
    token_data = await create_session_token(
        factory, group_names=["admin"], scopes={"exec:admin", "read:all"}
    )
    assert token_data.expires

    caplog.clear()
    r = await client.get(
        "/ingress/auth",
        params={"scope": "exec:admin", "notebook": "true"},
        headers={
            "Authorization": f"Bearer {token_data.token}",
            "X-Original-Uri": "/foo",
        },
    )
    assert r.status_code == 200
    notebook_token = Token.from_str(r.headers["X-Auth-Request-Token"])

    assert parse_log(caplog) == [
        {
            "auth_uri": "/foo",
            "event": "Token authorized",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "required_scopes": ["exec:admin"],
            "satisfy": "all",
            "scopes": ["exec:admin", "read:all"],
            "severity": "info",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        },
        {
            "auth_uri": "/foo",
            "event": "Created new notebook token",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "required_scopes": ["exec:admin"],
            "satisfy": "all",
            "scopes": ["exec:admin", "read:all"],
            "severity": "info",
            "token": token_data.token.key,
            "token_key": notebook_token.key,
            "token_expires": format_datetime_for_logging(token_data.expires),
            "token_source": "bearer",
            "token_userinfo": {
                "email": token_data.email,
                "name": token_data.name,
                "uid": token_data.uid,
                "gid": token_data.gid,
                "groups": [{"id": 1000, "name": "admin"}],
            },
            "user": token_data.username,
        },
    ]


@pytest.mark.asyncio
async def test_internal(
    client: AsyncClient, factory: Factory, caplog: pytest.LogCaptureFixture
) -> None:
    token_data = await create_session_token(
        factory, group_names=["admin"], scopes={"exec:admin", "read:all"}
    )
    assert token_data.expires

    caplog.clear()
    r = await client.get(
        "/ingress/auth",
        params={
            "scope": "exec:admin",
            "delegate_to": "a-service",
            "delegate_scope": "read:all",
        },
        headers={
            "Authorization": f"Bearer {token_data.token}",
            "X-Original-Uri": "/foo",
        },
    )
    assert r.status_code == 200
    notebook_token = Token.from_str(r.headers["X-Auth-Request-Token"])

    assert parse_log(caplog) == [
        {
            "auth_uri": "/foo",
            "event": "Token authorized",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "required_scopes": ["exec:admin"],
            "satisfy": "all",
            "scopes": ["exec:admin", "read:all"],
            "severity": "info",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        },
        {
            "auth_uri": "/foo",
            "event": "Created new internal token",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "required_scopes": ["exec:admin"],
            "satisfy": "all",
            "scopes": ["exec:admin", "read:all"],
            "severity": "info",
            "token": token_data.token.key,
            "token_key": notebook_token.key,
            "token_expires": format_datetime_for_logging(token_data.expires),
            "token_scopes": ["read:all"],
            "token_service": "a-service",
            "token_source": "bearer",
            "token_userinfo": {
                "email": token_data.email,
                "name": token_data.name,
                "uid": token_data.uid,
                "gid": token_data.gid,
                "groups": [{"id": 1000, "name": "admin"}],
            },
            "user": token_data.username,
        },
    ]


@pytest.mark.asyncio
async def test_bot_metrics(client: AsyncClient, factory: Factory) -> None:
    token_data = await create_session_token(
        factory, username="bot-something", scopes={"read:all"}
    )
    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "service"},
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200

    events = context_dependency._events
    assert events
    assert isinstance(events.auth_bot, MockEventPublisher)
    events.auth_bot.published.assert_published_all(
        [{"username": "bot-something", "service": "service"}]
    )
    assert isinstance(events.auth_user, MockEventPublisher)
    events.auth_user.published.assert_published_all([])
