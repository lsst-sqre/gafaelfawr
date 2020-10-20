"""Tests for the checkerboard.handlers.internal.index module and routes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.dependencies import config
from gafaelfawr.main import app

if TYPE_CHECKING:
    from tests.setup import SetupTest


async def test_get_index(setup: SetupTest) -> None:
    async with setup.async_client(app) as client:
        r = await client.get("/")

    assert r.status_code == 200
    data = r.json()
    assert data["name"] == config().safir.name
    assert isinstance(data["version"], str)
    assert isinstance(data["description"], str)
    assert isinstance(data["repository_url"], str)
    assert isinstance(data["documentation_url"], str)
