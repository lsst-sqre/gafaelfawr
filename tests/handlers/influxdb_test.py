"""Tests for the ``/auth/tokens/influxdb`` route."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt
import pytest

from tests.support.headers import assert_unauthorized_is_correct
from tests.support.logging import parse_log
from tests.support.settings import configure
from tests.support.tokens import create_session_token

if TYPE_CHECKING:
    from pathlib import Path

    from _pytest.logging import LogCaptureFixture
    from httpx import AsyncClient

    from gafaelfawr.config import Config
    from gafaelfawr.factory import ComponentFactory


@pytest.mark.asyncio
async def test_influxdb(
    client: AsyncClient,
    config: Config,
    factory: ComponentFactory,
    caplog: LogCaptureFixture,
) -> None:
    token_data = await create_session_token(factory)
    assert token_data.expires
    influxdb_secret = config.issuer.influxdb_secret
    assert influxdb_secret

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
async def test_no_auth(client: AsyncClient, config: Config) -> None:
    r = await client.get("/auth/tokens/influxdb/new")
    assert_unauthorized_is_correct(r, config)


@pytest.mark.asyncio
async def test_not_configured(
    tmp_path: Path,
    client: AsyncClient,
    factory: ComponentFactory,
    caplog: LogCaptureFixture,
) -> None:
    config = await configure(tmp_path, "oidc")
    factory.reconfigure(config)
    token_data = await create_session_token(factory)

    caplog.clear()
    r = await client.get(
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
    tmp_path: Path,
    client: AsyncClient,
    factory: ComponentFactory,
    caplog: LogCaptureFixture,
) -> None:
    config = await configure(tmp_path, "influxdb-username")
    factory.reconfigure(config)
    token_data = await create_session_token(factory)
    assert token_data.expires
    influxdb_secret = config.issuer.influxdb_secret
    assert influxdb_secret

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
