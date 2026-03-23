"""Support code for testing database handling."""

from safir.testing.data import Data
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from gafaelfawr.config import Config
from gafaelfawr.factory import Factory

__all__ = ["create_old_database"]


async def create_old_database(
    config: Config, data: Data, engine: AsyncEngine, *, version: str
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
    old_schema = data.path(f"schemas/{version}")
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
