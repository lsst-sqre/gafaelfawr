"""Tests for the ``/auth/tokens/influxdb`` route."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt

from gafaelfawr.handlers.util import AuthType
from tests.support.headers import parse_www_authenticate

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture

    from tests.setup import SetupTestCallable


async def test_influxdb(
    create_test_setup: SetupTestCallable, caplog: LogCaptureFixture
) -> None:
    setup = await create_test_setup()
    token = setup.create_token()
    assert setup.config.issuer.influxdb_secret

    caplog.clear()
    r = await setup.client.get(
        "/auth/tokens/influxdb/new",
        headers={"X-Auth-Request-Token": token.encoded},
    )

    assert r.status == 200
    data = await r.json()
    assert data == {"token": ANY}
    influxdb_token = data["token"]

    header = jwt.get_unverified_header(influxdb_token)
    assert header == {"alg": "HS256", "typ": "JWT"}
    claims = jwt.decode(
        influxdb_token, setup.config.issuer.influxdb_secret, algorithm="HS256"
    )
    assert claims == {
        "sub": token.username,
        "exp": token.claims["exp"],
        "iat": ANY,
    }

    log = json.loads(caplog.record_tuples[0][2])
    assert log == {
        "event": "Issued InfluxDB token",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth/tokens/influxdb/new",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "scope": "",
        "token": token.jti,
        "user": token.username,
        "user_agent": ANY,
    }


async def test_no_auth(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    r = await setup.client.get("/auth/tokens/influxdb/new")
    assert r.status == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert not authenticate.error
    assert not authenticate.scope


async def test_not_configured(
    create_test_setup: SetupTestCallable, caplog: LogCaptureFixture
) -> None:
    setup = await create_test_setup("oidc")
    token = setup.create_token()

    caplog.clear()
    r = await setup.client.get(
        "/auth/tokens/influxdb/new",
        headers={"X-Auth-Request-Token": token.encoded},
    )
    assert r.status == 400
    assert await r.json() == {
        "error": "not_supported",
        "error_description": "No InfluxDB issuer configuration",
    }

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
        "user": token.username,
        "user_agent": ANY,
    }
