"""Tests for web application startup."""

from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from sqlalchemy.ext.asyncio import AsyncEngine

from gafaelfawr.config import Config
from gafaelfawr.exceptions import DatabaseSchemaError
from gafaelfawr.main import create_app

from .support.database import create_old_database, drop_database


@pytest.mark.asyncio
async def test_out_of_date_schema(config: Config, engine: AsyncEngine) -> None:
    await drop_database(engine)
    await create_old_database(config, engine, "9.6.1")

    app = create_app()
    with pytest.raises(DatabaseSchemaError):
        async with LifespanManager(app):
            pass
