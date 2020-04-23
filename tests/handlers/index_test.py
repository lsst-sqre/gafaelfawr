"""Tests for the checkerboard.handlers.internal.index module and routes."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tests.setup import SetupTestCallable


async def test_get_index(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    response = await setup.client.get("/")
    assert response.status == 200
    data = await response.json()
    assert data["name"] == setup.app["safir/config"].name
    assert isinstance(data["version"], str)
    assert isinstance(data["description"], str)
    assert isinstance(data["repository_url"], str)
    assert isinstance(data["documentation_url"], str)
