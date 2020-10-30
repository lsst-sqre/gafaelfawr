"""Tests for the ``/auth/tokens/influxdb`` route."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt
import pytest

from gafaelfawr.auth import AuthErrorChallenge, AuthType
from tests.support.headers import parse_www_authenticate

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture

    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_influxdb(setup: SetupTest, caplog: LogCaptureFixture) -> None:
    token = setup.create_token()
    influxdb_secret = setup.config.issuer.influxdb_secret
    assert influxdb_secret

    caplog.clear()
    r = await setup.client.get(
        "/auth/tokens/influxdb/new",
        headers={"Authorization": f"bearer {token.encoded}"},
    )

    assert r.status_code == 200
    data = r.json()
    assert data == {"token": ANY}
    influxdb_token = data["token"]

    header = jwt.get_unverified_header(influxdb_token)
    assert header == {"alg": "HS256", "typ": "JWT"}
    claims = jwt.decode(influxdb_token, influxdb_secret, algorithms=["HS256"])
    assert claims == {
        "username": token.username,
        "exp": token.claims["exp"],
        "iat": ANY,
    }

    log = json.loads(caplog.record_tuples[0][2])
    assert log == {
        "event": "Issued InfluxDB token",
        "influxdb_username": token.username,
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth/tokens/influxdb/new",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "scope": "",
        "token": token.jti,
        "token_source": "bearer",
        "user": token.username,
        "user_agent": ANY,
    }


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
    setup.configure("oidc")
    token = setup.create_token()

    caplog.clear()
    r = await setup.client.get(
        "/auth/tokens/influxdb/new",
        headers={"Authorization": f"bearer {token.encoded}"},
    )

    assert r.status_code == 404
    assert r.json()["detail"]["type"] == "not_supported"

    log = json.loads(caplog.record_tuples[0][2])
    assert log == {
        "error": "No InfluxDB issuer configuration",
        "event": "Not configured",
        "level": "warning",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth/tokens/influxdb/new",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "scope": "",
        "token": token.jti,
        "token_source": "bearer",
        "user": token.username,
        "user_agent": ANY,
    }


@pytest.mark.asyncio
async def test_influxdb_force_username(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    setup.configure("influxdb-username")
    token = setup.create_token()
    influxdb_secret = setup.config.issuer.influxdb_secret
    assert influxdb_secret

    caplog.clear()
    r = await setup.client.get(
        "/auth/tokens/influxdb/new",
        headers={"Authorization": f"bearer {token.encoded}"},
    )

    assert r.status_code == 200
    data = r.json()
    claims = jwt.decode(data["token"], influxdb_secret, algorithms=["HS256"])
    assert claims == {
        "username": "influxdb-user",
        "exp": token.claims["exp"],
        "iat": ANY,
    }

    log = json.loads(caplog.record_tuples[0][2])
    assert log == {
        "event": "Issued InfluxDB token",
        "influxdb_username": "influxdb-user",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth/tokens/influxdb/new",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "scope": "",
        "token": token.jti,
        "token_source": "bearer",
        "user": token.username,
        "user_agent": ANY,
    }
