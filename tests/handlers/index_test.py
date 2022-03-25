"""Tests for the checkerboard.handlers.internal.index module and routes."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from gafaelfawr.config import Config


@pytest.mark.asyncio
async def test_get_index(client: AsyncClient, config: Config) -> None:
    r = await client.get("/")
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "gafaelfawr"
    assert isinstance(data["version"], str)
    assert isinstance(data["description"], str)
    assert isinstance(data["repository_url"], str)
    assert isinstance(data["documentation_url"], str)
