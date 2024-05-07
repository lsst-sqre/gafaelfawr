"""Tests for web application startup."""

from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from safir.database import create_database_engine
from safir.dependencies.db_session import db_session_dependency

from gafaelfawr.config import Config
from gafaelfawr.exceptions import DatabaseSchemaError
from gafaelfawr.main import create_app

from .support.constants import TEST_DATABASE_URL
from .support.database import create_old_database, drop_database


@pytest.mark.asyncio
async def test_out_of_date_schema(config: Config) -> None:
    engine = create_database_engine(TEST_DATABASE_URL, None)
    await drop_database(engine)
    await create_old_database(config, engine, "9.6.1")

    db_session_dependency.override_engine(engine)
    app = create_app()
    with pytest.raises(DatabaseSchemaError):
        async with LifespanManager(app):
            pass
