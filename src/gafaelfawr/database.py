"""Database utility functions for Gafaelfawr."""

from __future__ import annotations

import asyncio

from alembic.config import Config as AlembicConfig
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from safir.database import create_database_engine, initialize_database
from sqlalchemy import Connection, select
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine
from structlog.stdlib import BoundLogger

from .config import Config
from .factory import Factory
from .schema import Base, Token

__all__ = [
    "initialize_gafaelfawr_database",
    "is_database_current",
    "is_database_initialized",
]


async def initialize_gafaelfawr_database(
    config: Config, logger: BoundLogger, engine: AsyncEngine | None = None
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
    """
    if not engine:
        engine = create_database_engine(
            config.database_url, config.database_password
        )
    await initialize_database(engine, logger, schema=Base.metadata)
    async with Factory.standalone(config, engine) as factory:
        admin_service = factory.create_admin_service()
        logger.debug("Adding initial administrators")
        async with factory.session.begin():
            await admin_service.add_initial_admins(config.initial_admins)
        if config.firestore:
            firestore = factory.create_firestore_storage()
            logger.debug("Initializing Firestore")
            await firestore.initialize()
    await engine.dispose()


async def is_database_current(
    config: Config, logger: BoundLogger, engine: AsyncEngine | None = None
) -> bool:
    """Check whether the database schema is at the current version.

    This must be called outside of any event loop, since Alembic doesn't work
    well with async event loops. It expects :file:`alembic/versions` to
    contain the migration scripts.

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
        `True` if Alembic reports the database schema is current, false
        otherwise.
    """
    if not engine:
        engine = create_database_engine(
            config.database_url, config.database_password
        )

    def get_current_heads(connection: Connection) -> set[str]:
        context = MigrationContext.configure(connection)
        return set(context.get_current_heads())

    async with engine.begin() as connection:
        current = await connection.run_sync(get_current_heads)
    await engine.dispose()
    alembic_config = AlembicConfig("alembic.ini")
    alembic_scripts = ScriptDirectory.from_config(alembic_config)
    expected = set(alembic_scripts.get_heads())
    if current != expected:
        logger.error(f"Schema mismatch: {current} != {expected}")
        return False
    else:
        return True


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
    if not engine:
        engine = create_database_engine(
            config.database_url, config.database_password
        )
    statement = select(Token).limit(1)
    try:
        for _ in range(5):
            try:
                async with engine.begin() as connection:
                    await connection.execute(statement)
                    return True
            except (ConnectionRefusedError, OperationalError, OSError):
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
