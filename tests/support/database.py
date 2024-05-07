"""Support code for testing database handling."""

from __future__ import annotations

import contextlib
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine

from gafaelfawr.config import Config
from gafaelfawr.factory import Factory
from gafaelfawr.schema import Base

__all__ = [
    "clear_alembic_version",
    "create_old_database",
    "drop_database",
]


async def clear_alembic_version(engine: AsyncEngine) -> None:
    """Clear the Alembic version from the database.

    This is done when clearing the whole database or before stamping the
    database to ensure that the database is in the expected state.

    Parameters
    ----------
    engine
        Engine to use for SQL calls.
    """
    async with engine.begin() as conn:
        with contextlib.suppress(ProgrammingError):
            await conn.execute(text("DROP TABLE alembic_version"))


async def create_old_database(
    config: Config, engine: AsyncEngine, version: str
) -> None:
    """Initialize the database from an old schema.

    Used to test whether the application refuses to start if the schema is out
    of date. This was the database schema # before Alembic was introduced, so
    it should run all migrations.

    Parameters
    ----------
    config
        Gafaelfawr configuration.
    engine
        Database engine.
    version
        Version of schema to load.
    """
    old_schema = Path(__file__).parent.parent / "data" / "schemas" / version
    async with Factory.standalone(config, engine) as factory:
        async with factory.session.begin():
            with old_schema.open() as f:
                statement = ""
                for line in f:
                    if not line.startswith("--") and line.strip("\n"):
                        statement += line.strip("\n")
                    if statement.endswith(";"):
                        await factory.session.execute(text(statement))
                        statement = ""


async def drop_database(engine: AsyncEngine) -> None:
    """Drop all tables from the database.

    Parameters
    ----------
    engine
        Engine to use to issue the SQL commands.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await clear_alembic_version(engine)
