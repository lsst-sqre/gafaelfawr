"""Tests for the checkerboard.handlers.internal.index module and routes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.setup import SetupTest

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient
    from pathlib import Path


async def test_get_index(tmp_path: Path, aiohttp_client: TestClient) -> None:
    """Test GET /"""
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)

    response = await client.get("/")
    assert response.status == 200
    data = await response.json()
    assert data["name"] == setup.app["safir/config"].name
    assert isinstance(data["version"], str)
    assert isinstance(data["description"], str)
    assert isinstance(data["repository_url"], str)
    assert isinstance(data["documentation_url"], str)
