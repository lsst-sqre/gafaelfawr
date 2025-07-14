"""Tests for logging and metrics in the ``/ingress/auth`` route."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import ANY

import pytest
from httpx import AsyncClient
from safir.datetime import format_datetime_for_logging
from safir.metrics import MockEventPublisher
from safir.testing.logging import parse_log_tuples

from gafaelfawr.dependencies.context import context_dependency
from gafaelfawr.factory import Factory
from gafaelfawr.models.token import Token

from ..support.config import reconfigure
from ..support.constants import TEST_HOSTNAME
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_success(
    client: AsyncClient, factory: Factory, caplog: pytest.LogCaptureFixture
) -> None:
    await reconfigure("github-quota", factory)
    token_data = await create_session_token(factory, scopes={"exec:admin"})

    # Successful request with X-Forwarded-For and a bearer token.
    caplog.clear()
    r = await client.get(
        "/ingress/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"Bearer {token_data.token}",
            "X-Original-URL": "https://example.com/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    expected_log: dict[str, Any] = {
        "auth_uri": "https://example.com/foo",
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
        "service": None,
        "severity": "info",
        "token": token_data.token.key,
        "token_source": "bearer",
        "user": token_data.username,
    }
    assert parse_log_tuples("gafaelfawr", caplog.record_tuples) == [
        expected_log
    ]

    # Successful request with HTTP Basic authentication in the username, using
    # a service without a quota.
    basic = f"{token_data.token}:x-oauth-basic".encode()
    basic_b64 = base64.b64encode(basic).decode()
    caplog.clear()
    r = await client.get(
        "/ingress/auth",
        params={"scope": "exec:admin", "service": "service-one"},
        headers={
            "Authorization": f"Basic {basic_b64}",
            "X-Original-URL": "https://example.com/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    url = expected_log["httpRequest"]["requestUrl"]
    expected_log["httpRequest"]["requestUrl"] += "&service=service-one"
    expected_log["service"] = "service-one"
    expected_log["token_source"] = "basic-username"
    assert parse_log_tuples("gafaelfawr", caplog.record_tuples) == [
        expected_log
    ]

    # The same with HTTP Basic in the password, using a service with a quota.
    basic = f"x-oauth-basic:{token_data.token}".encode()
    basic_b64 = base64.b64encode(basic).decode()
    caplog.clear()
    r = await client.get(
        "/ingress/auth",
        params={"scope": "exec:admin", "service": "test"},
        headers={
            "Authorization": f"Basic {basic_b64}",
            "X-Original-URL": "https://example.com/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    expected_log["httpRequest"]["requestUrl"] = url + "&service=test"
    expected_log["quota"] = {"limit": 1, "used": 1, "reset": ANY}
    expected_log["service"] = "test"
    expected_log["token_source"] = "basic-password"
    seen_log = parse_log_tuples("gafaelfawr", caplog.record_tuples)
    assert seen_log == [expected_log]
    reset_time = datetime.fromisoformat(seen_log[0]["quota"]["reset"])
    reset_time = reset_time.replace(tzinfo=UTC)
    expected_reset = datetime.now(tz=UTC) + timedelta(minutes=1)
    assert expected_reset - timedelta(seconds=1) < reset_time < expected_reset

    # Check the logged metrics events.
    events = context_dependency._events
    assert events
    assert isinstance(events.auth_user, MockEventPublisher)
    events.auth_user.published.assert_published_all(
        [
            {
                "username": token_data.username,
                "service": None,
                "quota": None,
                "quota_used": None,
            },
            {
                "username": token_data.username,
                "service": "service-one",
                "quota": None,
                "quota_used": None,
            },
            {
                "username": token_data.username,
                "service": "test",
                "quota": 1,
                "quota_used": 1,
            },
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
            "X-Original-URL": "https://example.com/foo",
        },
    )

    assert r.status_code == 403
    assert parse_log_tuples("gafaelfawr", caplog.record_tuples) == [
        {
            "auth_uri": "https://example.com/foo",
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
            "service": None,
            "severity": "info",
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
        "service": None,
        "severity": "info",
        "token": token_data.token.key,
        "token_source": "bearer",
        "user": token_data.username,
    }
    assert parse_log_tuples("gafaelfawr", caplog.record_tuples) == [
        expected_log
    ]


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
            "X-Original-URL": "https://example.com/foo",
        },
    )

    assert r.status_code == 403
    assert parse_log_tuples("gafaelfawr", caplog.record_tuples) == [
        {
            "auth_uri": "https://example.com/foo",
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
            "service": None,
            "severity": "info",
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
        headers={
            "Authorization": "Bearer blah",
            "X-Original-URL": "https://example.com/foo",
        },
    )

    assert r.status_code == 401
    assert parse_log_tuples("gafaelfawr", caplog.record_tuples) == [
        {
            "auth_uri": "https://example.com/foo",
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
            "service": None,
            "severity": "info",
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
            "X-Original-URL": "https://example.com/foo",
        },
    )
    assert r.status_code == 200
    notebook_token = Token.from_str(r.headers["X-Auth-Request-Token"])

    assert parse_log_tuples("gafaelfawr", caplog.record_tuples) == [
        {
            "auth_uri": "https://example.com/foo",
            "event": "Created new notebook token",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "required_scopes": ["exec:admin"],
            "satisfy": "all",
            "scopes": ["exec:admin", "read:all"],
            "service": None,
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
        {
            "auth_uri": "https://example.com/foo",
            "event": "Token authorized",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "required_scopes": ["exec:admin"],
            "satisfy": "all",
            "scopes": ["exec:admin", "read:all"],
            "service": None,
            "severity": "info",
            "token": token_data.token.key,
            "token_source": "bearer",
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
            "X-Original-URL": "https://example.com/foo",
        },
    )
    assert r.status_code == 200
    notebook_token = Token.from_str(r.headers["X-Auth-Request-Token"])

    assert parse_log_tuples("gafaelfawr", caplog.record_tuples) == [
        {
            "auth_uri": "https://example.com/foo",
            "event": "Created new internal token",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "required_scopes": ["exec:admin"],
            "satisfy": "all",
            "scopes": ["exec:admin", "read:all"],
            "service": None,
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
        {
            "auth_uri": "https://example.com/foo",
            "event": "Token authorized",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "required_scopes": ["exec:admin"],
            "satisfy": "all",
            "scopes": ["exec:admin", "read:all"],
            "service": None,
            "severity": "info",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        },
    ]


@pytest.mark.asyncio
async def test_rate_limit_events(
    client: AsyncClient, factory: Factory, caplog: pytest.LogCaptureFixture
) -> None:
    await reconfigure("github-quota", factory)
    token_data = await create_session_token(factory, scopes={"read:all"})
    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "test"},
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    caplog.clear()
    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "test"},
        headers={
            "Authorization": f"Bearer {token_data.token}",
            "X-Forwarded-For": "192.0.2.1",
            "X-Original-Url": "https://example.com/foo",
        },
    )
    assert r.status_code == 403
    assert r.headers["X-Error-Status"] == "429"

    assert parse_log_tuples("gafaelfawr", caplog.record_tuples) == [
        {
            "auth_uri": "https://example.com/foo",
            "error": "Rate limit (1/15m) exceeded",
            "event": "Request rejected due to rate limits",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": (
                    f"https://{TEST_HOSTNAME}/ingress/auth?scope=read%3Aall&"
                    "service=test"
                ),
                "remoteIp": "192.0.2.1",
            },
            "quota": {
                "limit": 1,
                "reset": ANY,
                "used": 1,
            },
            "required_scopes": ["read:all"],
            "satisfy": "all",
            "scopes": ["read:all"],
            "service": "test",
            "severity": "info",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        }
    ]

    events = context_dependency._events
    assert events
    assert isinstance(events.auth_user, MockEventPublisher)
    events.auth_user.published.assert_published_all(
        [
            {
                "username": token_data.username,
                "service": "test",
                "quota": 1,
                "quota_used": 1,
            }
        ]
    )
    assert isinstance(events.rate_limit, MockEventPublisher)
    events.rate_limit.published.assert_published_all(
        [
            {
                "username": token_data.username,
                "is_bot": False,
                "service": "test",
                "quota": 1,
            }
        ]
    )


@pytest.mark.asyncio
async def test_bot_events(client: AsyncClient, factory: Factory) -> None:
    await reconfigure("github-quota", factory)
    token_data = await create_session_token(
        factory, username="bot-something", scopes={"read:all"}
    )
    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "test"},
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 200
    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "test"},
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 403
    assert r.headers["X-Error-Status"] == "429"

    events = context_dependency._events
    assert events
    assert isinstance(events.auth_bot, MockEventPublisher)
    events.auth_bot.published.assert_published_all(
        [
            {
                "username": "bot-something",
                "service": "test",
                "quota": 1,
                "quota_used": 1,
            }
        ]
    )
    assert isinstance(events.auth_user, MockEventPublisher)
    events.auth_user.published.assert_published_all([])
    assert isinstance(events.rate_limit, MockEventPublisher)
    events.rate_limit.published.assert_published_all(
        [
            {
                "username": "bot-something",
                "is_bot": True,
                "service": "test",
                "quota": 1,
            }
        ]
    )
