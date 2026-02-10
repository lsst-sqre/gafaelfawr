"""Database utility functions for Gafaelfawr."""

import asyncio
from typing import Any

from safir.database import create_database_engine, initialize_database
from sqlalchemy import create_mock_engine, select
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine
from structlog.stdlib import BoundLogger

from .config import Config
from .factory import Factory
from .schema import SchemaBase, Token

__all__ = [
    "initialize_gafaelfawr_database",
    "is_database_initialized",
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

    engine = create_mock_engine(str(config.database_url), dump)
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
    engine_created = False
    if not engine:
        engine = create_database_engine(
            config.database_url, config.database_password
        )
        engine_created = True
    await initialize_database(
        engine, logger, schema=SchemaBase.metadata, reset=reset
    )
    async with Factory.standalone(config, engine) as factory:
        admin_service = factory.create_admin_service()
        logger.debug("Adding initial administrators")
        await admin_service.add_initial_admins(config.initial_admins)
        if config.firestore:
            firestore = factory.create_firestore_storage()
            logger.debug("Initializing Firestore")
            await firestore.initialize()
    if engine_created:
        await engine.dispose()


async def is_database_initialized(
    config: Config, logger: BoundLogger, engine: AsyncEngine | None = None
) -> bool:
    """Check whether the database has been initialized.

    Parameters
    ----------
    config
        Gafaelfawr configuration.
    logger
        Logger to use for status reporting.
    engine
        If given, database engine to use, which avoids the need to create
        another one.

    Returns
    -------
    bool
        `True` if some Gafaelfawr schema (possibly out of date) appears to
        exist, `False` otherwise. This may misdetect partial schemas that
        contain some tables and not others or that are missing indices.
    """
    engine_created = False
    if not engine:
        engine = create_database_engine(
            config.database_url, config.database_password
        )
        engine_created = True
    statement = select(Token).limit(1)
    try:
        for _ in range(5):
            try:
                async with engine.begin() as connection:
                    await connection.execute(statement)
                    return True
            except ConnectionRefusedError, OperationalError, OSError:
                if logger:
                    logger.info("database not ready, waiting two seconds")
                await asyncio.sleep(2)
                continue

        # If we got here, we failed five times. Try one more time to generate
        # a proper exception.
        async with engine.begin() as connection:
            await connection.execute(statement)
            return True
    except ProgrammingError:
        logger.info("Database appears not to be initialized")
        return False
    finally:
        if engine_created:
            await engine.dispose()
