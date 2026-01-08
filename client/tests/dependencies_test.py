"""Tests for Gafaelfawr client FastAPI dependencies."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Annotated

import pytest
from asgi_lifespan import LifespanManager
from fastapi import Depends, FastAPI, Header
from httpx import ASGITransport, AsyncClient
from safir.dependencies.http_client import http_client_dependency

from rubin.gafaelfawr import (
    GafaelfawrClient,
    GafaelfawrUserInfo,
    MockGafaelfawr,
    gafaelfawr_dependency,
)


@pytest.mark.asyncio
async def test_dependency(mock_gafaelfawr: MockGafaelfawr) -> None:
    token = mock_gafaelfawr.create_token("user")
    mock_gafaelfawr.set_user_info("user", GafaelfawrUserInfo(username="user"))
    cached_client = None

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        yield
        await http_client_dependency.aclose()

    app = FastAPI(lifespan=lifespan)

    @app.get("/")
    async def get_root(
        x_auth_request_token: Annotated[str, Header()],
        gafaelfawr: Annotated[
            GafaelfawrClient, Depends(gafaelfawr_dependency)
        ],
    ) -> None:
        nonlocal cached_client
        if cached_client is None:
            cached_client = gafaelfawr
        assert gafaelfawr == cached_client
        user_info = await gafaelfawr.get_user_info(x_auth_request_token)
        assert user_info == GafaelfawrUserInfo(username="user")

    async with LifespanManager(app):
        async with AsyncClient(
            base_url="https://example.com/", transport=ASGITransport(app=app)
        ) as client:
            r = await client.get("/", headers={"X-Auth-Request-Token": token})
            assert r.status_code == 200
            r = await client.get("/", headers={"X-Auth-Request-Token": token})
            assert r.status_code == 200

    # When the HTTPX client dependency is shut down and recreated, this should
    # result in a new Gafaelfawr client. Otherwise, the Gafaelfawr client
    # would try to use the closed HTTPX client.
    old_client = cached_client
    cached_client = None
    async with LifespanManager(app):
        async with AsyncClient(
            base_url="https://example.com/", transport=ASGITransport(app=app)
        ) as client:
            r = await client.get("/", headers={"X-Auth-Request-Token": token})
            assert r.status_code == 200
            assert cached_client != old_client
