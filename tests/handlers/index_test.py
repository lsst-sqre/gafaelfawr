"""Tests for the checkerboard.handlers.internal.index module and routes."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_get_index(setup: SetupTest) -> None:
    r = await setup.client.get("/")
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == setup.config.safir.name
    assert isinstance(data["version"], str)
    assert isinstance(data["description"], str)
    assert isinstance(data["repository_url"], str)
    assert isinstance(data["documentation_url"], str)
