"""Tests for the ``/auth/tokens/influxdb`` route."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import ANY

import jwt
import pytest
from _pytest.logging import LogCaptureFixture
from httpx import AsyncClient

from gafaelfawr.config import Config
from gafaelfawr.factory import Factory

from ..support.constants import TEST_HOSTNAME
from ..support.headers import assert_unauthorized_is_correct
from ..support.logging import parse_log
from ..support.settings import reconfigure
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_influxdb(
    client: AsyncClient,
    config: Config,
    factory: Factory,
    caplog: LogCaptureFixture,
) -> None:
    token_data = await create_session_token(factory)
    assert token_data.expires
    assert config.influxdb
    influxdb_secret = config.influxdb.secret

    caplog.clear()
    r = await client.get(
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
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": (
                    f"https://{TEST_HOSTNAME}/auth/tokens/influxdb/new"
                ),
                "remoteIp": "127.0.0.1",
            },
            "scopes": ["user:token"],
            "severity": "info",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        }
    ]


@pytest.mark.asyncio
async def test_no_auth(client: AsyncClient, config: Config) -> None:
    r = await client.get("/auth/tokens/influxdb/new")
    assert_unauthorized_is_correct(r, config)


@pytest.mark.asyncio
async def test_not_configured(
    tmp_path: Path, client: AsyncClient, factory: Factory
) -> None:
    await reconfigure(tmp_path, "oidc", factory)
    token_data = await create_session_token(factory)

    r = await client.get(
        "/auth/tokens/influxdb/new",
        headers={"Authorization": f"bearer {token_data.token}"},
    )

    assert r.status_code == 404
    assert r.json()["detail"][0]["type"] == "not_supported"


@pytest.mark.asyncio
async def test_influxdb_force_username(
    tmp_path: Path,
    client: AsyncClient,
    factory: Factory,
    caplog: LogCaptureFixture,
) -> None:
    config = await reconfigure(tmp_path, "influxdb-username", factory)
    token_data = await create_session_token(factory)
    assert token_data.expires
    assert config.influxdb
    influxdb_secret = config.influxdb.secret

    caplog.clear()
    r = await client.get(
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
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": (
                    f"https://{TEST_HOSTNAME}/auth/tokens/influxdb/new"
                ),
                "remoteIp": "127.0.0.1",
            },
            "scopes": ["user:token"],
            "severity": "info",
            "token": token_data.token.key,
            "token_source": "bearer",
            "user": token_data.username,
        }
    ]
