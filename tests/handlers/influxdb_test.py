"""Tests for the ``/auth/tokens/influxdb`` route."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt
import pytest

from gafaelfawr.auth import AuthErrorChallenge, AuthType
from tests.support.headers import parse_www_authenticate
from tests.support.logging import parse_log

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture

    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_influxdb(setup: SetupTest, caplog: LogCaptureFixture) -> None:
    token_data = await setup.create_session_token()
    assert token_data.expires
    influxdb_secret = setup.config.issuer.influxdb_secret
    assert influxdb_secret

    caplog.clear()
    r = await setup.client.get(
        "/auth/tokens/influxdb/new",
        headers={"Authorization": f"bearer {token_data.token}"},
    )

    assert r.status_code == 200
    data = r.json()
    assert data == {"token": ANY}
    influxdb_token = data["token"]

    header = jwt.get_unverified_header(influxdb_token)
    assert header == {"alg": "HS256", "typ": "JWT"}
    claims = jwt.decode(influxdb_token, influxdb_secret, algorithms=["HS256"])
    assert claims == {
        "username": token_data.username,
        "exp": int(token_data.expires.timestamp()),
        "iat": ANY,
    }

    assert parse_log(caplog) == [
        {
            "event": "Issued InfluxDB token",
            "influxdb_username": token_data.username,
            "level": "info",
            "method": "GET",
            "path": "/auth/tokens/influxdb/new",
            "remote": "127.0.0.1",
            "scope": "user:token",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        }
    ]


@pytest.mark.asyncio
async def test_no_auth(setup: SetupTest) -> None:
    r = await setup.client.get("/auth/tokens/influxdb/new")
    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm


@pytest.mark.asyncio
async def test_not_configured(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    await setup.configure("oidc")
    token_data = await setup.create_session_token()

    caplog.clear()
    r = await setup.client.get(
        "/auth/tokens/influxdb/new",
        headers={"Authorization": f"bearer {token_data.token}"},
    )

    assert r.status_code == 404
    assert r.json()["detail"]["type"] == "not_supported"

    assert parse_log(caplog) == [
        {
            "error": "No InfluxDB issuer configuration",
            "event": "Not configured",
            "level": "warning",
            "method": "GET",
            "path": "/auth/tokens/influxdb/new",
            "remote": "127.0.0.1",
            "scope": "user:token",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        }
    ]


@pytest.mark.asyncio
async def test_influxdb_force_username(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    await setup.configure("influxdb-username")
    token_data = await setup.create_session_token()
    assert token_data.expires
    influxdb_secret = setup.config.issuer.influxdb_secret
    assert influxdb_secret

    caplog.clear()
    r = await setup.client.get(
        "/auth/tokens/influxdb/new",
        headers={"Authorization": f"bearer {token_data.token}"},
    )

    assert r.status_code == 200
    data = r.json()
    claims = jwt.decode(data["token"], influxdb_secret, algorithms=["HS256"])
    assert claims == {
        "username": "influxdb-user",
        "exp": int(token_data.expires.timestamp()),
        "iat": ANY,
    }

    assert parse_log(caplog) == [
        {
            "event": "Issued InfluxDB token",
            "influxdb_username": "influxdb-user",
            "level": "info",
            "method": "GET",
            "path": "/auth/tokens/influxdb/new",
            "remote": "127.0.0.1",
            "scope": "user:token",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        }
    ]
