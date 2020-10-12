"""Tests for the ``/auth/tokens/influxdb`` route."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt

from gafaelfawr.fastapi.dependencies import config
from gafaelfawr.handlers.util import AuthErrorChallenge, AuthType
from tests.support.app import create_fastapi_test_app, create_test_client
from tests.support.headers import parse_www_authenticate
from tests.support.tokens import create_test_token

if TYPE_CHECKING:
    from pathlib import Path

    from _pytest.logging import LogCaptureFixture


async def test_influxdb(tmp_path: Path, caplog: LogCaptureFixture) -> None:
    app = await create_fastapi_test_app(tmp_path)
    token = create_test_token(config())
    influxdb_secret = config().issuer.influxdb_secret
    assert influxdb_secret

    caplog.clear()
    async with create_test_client(app) as client:
        r = await client.get(
            "/auth/tokens/influxdb/new",
            headers={"Authorization": f"bearer {token.encoded}"},
        )

    assert r.status_code == 200
    data = r.json()
    assert data == {"token": ANY}
    influxdb_token = data["token"]

    header = jwt.get_unverified_header(influxdb_token)
    assert header == {"alg": "HS256", "typ": "JWT"}
    claims = jwt.decode(influxdb_token, influxdb_secret, algorithm="HS256")
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


async def test_no_auth(tmp_path: Path) -> None:
    app = await create_fastapi_test_app(tmp_path)

    async with create_test_client(app) as client:
        r = await client.get("/auth/tokens/influxdb/new")

    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config().realm


async def test_not_configured(
    tmp_path: Path, caplog: LogCaptureFixture
) -> None:
    app = await create_fastapi_test_app(tmp_path, environment="oidc")
    token = create_test_token(config())

    caplog.clear()
    async with create_test_client(app) as client:
        r = await client.get(
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


async def test_influxdb_force_username(
    tmp_path: Path, caplog: LogCaptureFixture
) -> None:
    app = await create_fastapi_test_app(
        tmp_path, environment="influxdb-username"
    )
    token = create_test_token(config())
    influxdb_secret = config().issuer.influxdb_secret
    assert influxdb_secret

    caplog.clear()
    async with create_test_client(app) as client:
        r = await client.get(
            "/auth/tokens/influxdb/new",
            headers={"Authorization": f"bearer {token.encoded}"},
        )

    assert r.status_code == 200
    data = r.json()
    claims = jwt.decode(data["token"], influxdb_secret, algorithm="HS256")
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
