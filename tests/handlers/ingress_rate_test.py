"""Tests for API rate limiting."""

import json
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

import pytest
from httpx import AsyncClient

from gafaelfawr.factory import Factory
from gafaelfawr.models.auth import AuthError, AuthErrorChallenge

from ..support.config import reconfigure
from ..support.headers import parse_www_authenticate
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_rate_limit(client: AsyncClient, factory: Factory) -> None:
    await reconfigure("github-quota", factory)
    token_data = await create_session_token(
        factory, group_names=["foo"], scopes={"read:all"}
    )
    headers = {"Authorization": f"bearer {token_data.token}"}
    now = datetime.now(tz=UTC)
    expected = now + timedelta(minutes=1) - timedelta(seconds=1)

    # Two requests should be allowed, one from the default quota and a second
    # from the additional quota from the foo group.
    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "test"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.headers["X-RateLimit-Limit"] == "2"
    assert r.headers["X-RateLimit-Remaining"] == "1"
    assert r.headers["X-RateLimit-Used"] == "1"
    assert r.headers["X-RateLimit-Resource"] == "test"
    reset = int(r.headers["X-RateLimit-Reset"])
    assert expected.timestamp() <= reset <= expected.timestamp() + 5
    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "test"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.headers["X-RateLimit-Limit"] == "2"
    assert r.headers["X-RateLimit-Remaining"] == "0"
    assert r.headers["X-RateLimit-Used"] == "2"
    assert r.headers["X-RateLimit-Resource"] == "test"
    reset = int(r.headers["X-RateLimit-Reset"])
    assert expected.timestamp() <= reset <= expected.timestamp() + 5

    # The third request should be rejected due to rate limiting, with a
    # Retry-After header set to approximately one minute from now.
    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "test"},
        headers=headers,
    )
    assert r.status_code == 403
    retry_after = parsedate_to_datetime(r.headers["Retry-After"])
    assert expected <= retry_after
    assert retry_after <= expected + timedelta(seconds=5)
    body = json.loads(r.headers["X-Error-Body"])
    assert body["detail"][0]["type"] == "rate_limited"
    assert r.headers["X-Error-Status"] == "429"
    assert r.headers["X-RateLimit-Limit"] == "2"
    assert r.headers["X-RateLimit-Remaining"] == "0"
    assert r.headers["X-RateLimit-Used"] == "2"
    assert r.headers["X-RateLimit-Resource"] == "test"
    reset = int(r.headers["X-RateLimit-Reset"])
    assert expected.timestamp() <= reset <= expected.timestamp() + 5

    # A request for a service with no rate limit should be allowed and, since
    # there is no quota set, should not return any of the rate limit headers.
    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "unknown"},
        headers=headers,
    )
    assert r.status_code == 200
    for header in ("Limit", "Remaining", "Used", "Resource", "Reset"):
        assert f"X-RateLimit-{header}" not in r.headers

    # A request for a service with a different rate should get its own rate
    # limit headers and be allowed.
    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "other"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.headers["X-RateLimit-Limit"] == "2"
    assert r.headers["X-RateLimit-Remaining"] == "1"
    assert r.headers["X-RateLimit-Used"] == "1"
    assert r.headers["X-RateLimit-Resource"] == "other"
    reset = int(r.headers["X-RateLimit-Reset"])
    assert expected.timestamp() <= reset <= expected.timestamp() + 5


@pytest.mark.asyncio
async def test_rate_limit_bypass(
    client: AsyncClient, factory: Factory
) -> None:
    await reconfigure("github-quota", factory)
    token_data = await create_session_token(
        factory, group_names=["admin"], scopes={"read:all"}
    )
    headers = {"Authorization": f"bearer {token_data.token}"}

    r = await client.get(
        "/ingress/auth",
        params={"scope": "read:all", "service": "test"},
        headers=headers,
    )
    assert r.status_code == 200

    # There should be no quota set since the user is in the bypass group.
    assert "X-RateLimit-Limit" not in r.headers
    assert "X-RateLimit-Remaining" not in r.headers
    assert "X-RateLimit-Used" not in r.headers
    assert "X-RateLimit-Resource" not in r.headers
    assert "X-RateLimit-Reset" not in r.headers


@pytest.mark.asyncio
async def test_rate_limit_zero(client: AsyncClient, factory: Factory) -> None:
    token_data = await create_session_token(
        factory, group_names=["foo"], scopes={"admin:token"}
    )
    headers = {"Authorization": f"bearer {token_data.token}"}
    r = await client.put(
        "/auth/api/v1/quota-overrides",
        json={"default": {"api": {"blocked": 0}}},
        headers=headers,
    )
    assert r.status_code == 200

    r = await client.get(
        "/ingress/auth",
        params={"scope": "admin:token", "service": "blocked"},
        headers=headers,
    )
    assert r.status_code == 403
    assert r.headers["X-Error-Status"] == "403"
    challenge = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(challenge, AuthErrorChallenge)
    assert challenge.error == AuthError.insufficient_scope
    assert challenge.error_description == (
        f"User {token_data.username} not allowed to access service blocked"
    )
