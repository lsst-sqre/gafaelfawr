"""Tests for the checkerboard.handlers.internal.index module and routes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.fastapi.dependencies import config
from tests.support.app import create_fastapi_test_app, create_test_client

if TYPE_CHECKING:
    from pathlib import Path


async def test_get_index(tmp_path: Path) -> None:
    app = await create_fastapi_test_app(tmp_path)

    async with create_test_client(app) as client:
        r = await client.get("/")

    assert r.status_code == 200
    data = r.json()
    assert data["name"] == config().safir.name
    assert isinstance(data["version"], str)
    assert isinstance(data["description"], str)
    assert isinstance(data["repository_url"], str)
    assert isinstance(data["documentation_url"], str)
