"""Tests for web application startup."""

from __future__ import annotations

from pathlib import Path

import pytest
from asgi_lifespan import LifespanManager
from safir.database import create_database_engine
from safir.dependencies.db_session import db_session_dependency
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine

from gafaelfawr.config import Config
from gafaelfawr.exceptions import DatabaseSchemaError
from gafaelfawr.factory import Factory
from gafaelfawr.main import create_app
from gafaelfawr.schema import Base

from .support.constants import TEST_DATABASE_URL


# Initialize the database from an old schema. This was the database schema
# before Alembic was introduced, so it should run all migrations.
async def create_old_database(config: Config, engine: AsyncEngine) -> None:
    """Initialize the database from an old schema.

    Used to test whether the application refuses to start if the schema is out
    of date.

    Parameters
    ----------
    config
        Gafaelfawr configuration.
    engine
        Database engine.
    """
    old_schema = Path(__file__).parent / "data" / "schemas" / "9.6.1"

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    async with Factory.standalone(config, engine) as factory:
        async with factory.session.begin():
            try:
                sql = "DROP TABLE alembic_version"
                await factory.session.execute(text(sql))
            except ProgrammingError:
                pass
        async with factory.session.begin():
            with old_schema.open() as f:
                statement = ""
                for line in f:
                    if not line.startswith("--") and line.strip("\n"):
                        statement += line.strip("\n")
                    if statement.endswith(";"):
                        await factory.session.execute(text(statement))
                        statement = ""


@pytest.mark.asyncio
async def test_out_of_date_schema(config: Config) -> None:
    engine = create_database_engine(TEST_DATABASE_URL, None)
    await create_old_database(config, engine)

    db_session_dependency.override_engine(engine)
    app = create_app()
    with pytest.raises(DatabaseSchemaError):
        async with LifespanManager(app):
            pass
