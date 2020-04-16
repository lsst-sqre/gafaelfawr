"""Tests for the checkerboard.handlers.internal.index module and routes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.support.app import create_test_app

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient


async def test_get_index(aiohttp_client: TestClient) -> None:
    """Test GET /"""
    app = await create_test_app()
    client = await aiohttp_client(app)

    response = await client.get("/")
    assert response.status == 200
    data = await response.json()
    assert data["name"] == app["safir/config"].name
    assert isinstance(data["version"], str)
    assert isinstance(data["description"], str)
    assert isinstance(data["repository_url"], str)
    assert isinstance(data["documentation_url"], str)
