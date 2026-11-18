"""Database utility functions for Gafaelfawr."""

from typing import Any

from safir.database import engine_manager, initialize_database
from sqlalchemy import create_mock_engine
from sqlalchemy.ext.asyncio import AsyncEngine
from structlog.stdlib import BoundLogger

from .config import Config
from .factory import Factory
from .schema import SchemaBase

__all__ = [
    "generate_schema_sql",
    "initialize_gafaelfawr_database",
]


def generate_schema_sql(config: Config) -> str:
    """Generate SQL for the Gafaelfawr databsae schema.

    Parameters
    ----------
    config
        Gafaelfawr configuration.
    """
    result = ""

    def dump(sql: Any, *args: Any, **kwargs: Any) -> None:
        nonlocal result
        result += str(sql.compile(dialect=engine.dialect)) + ";\n"

    engine = create_mock_engine(config.database.mock_url, dump)
    SchemaBase.metadata.create_all(engine, checkfirst=False)
    return result


async def initialize_gafaelfawr_database(
    config: Config,
    logger: BoundLogger,
    engine: AsyncEngine | None = None,
    *,
    reset: bool = False,
) -> None:
    """Initialize the database.

    This is the internal async implementation details of the ``init`` command,
    except for the Alembic parts. Alembic has to run outside of a running
    asyncio loop, hence this separation. Always stamp the database with
    Alembic after calling this function.

    Parameters
    ----------
    config
        Gafaelfawr configuration.
    logger
        Logger to use for status reporting.
    engine
        If given, database engine to use, which avoids the need to create
        another one.
    reset
        Whether to reset the database.
    """
    schema = SchemaBase.metadata

    async def initialize(engine: AsyncEngine) -> None:
        await initialize_database(engine, logger, schema=schema, reset=reset)
        if config.firestore:
            async with Factory.standalone(config, engine) as factory:
                firestore = factory.create_firestore_storage()
                logger.debug("Initializing Firestore")
                await firestore.initialize()

    if not engine:
        async with engine_manager(config.database) as tmp_engine:
            await initialize(tmp_engine)
    else:
        await initialize(engine)
