"""Utility functions for database management.

SQLAlchemy, when creating a database schema, can only know about the tables
that have been registered via a metaclass.  This module therefore must import
every schema to ensure that SQLAlchemy has a complete view.
"""

from __future__ import annotations

import time

import structlog
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker
from structlog.stdlib import BoundLogger

from .config import Config
from .models.admin import Admin
from .schema import Admin as SQLAdmin
from .schema import drop_schema, initialize_schema
from .storage.admin import AdminStore

__all__ = ["check_database", "initialize_database"]


def _create_session_factory(engine: AsyncEngine) -> sessionmaker:
    """Create a session factory that generates async sessions."""
    return sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def check_database(url: str, logger: BoundLogger) -> None:
    """Check that the database is accessible.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        The Gafaelfawr configuration.
    logger : `structlog.stdlib.BoundLogger`
        Logger used to report problems
    """
    engine = create_async_engine(url, future=True)
    factory = _create_session_factory(engine)
    for _ in range(5):
        try:
            async with factory() as session:
                async with session.begin():
                    await session.execute(select(SQLAdmin).limit(1))
                    return
        except (ConnectionRefusedError, OperationalError):
            logger.info("database not ready, waiting two seconds")
            time.sleep(2)
            continue

    # If we got here, we failed five times.  Try one last time without
    # catching exceptions so that we raise the appropriate exception to our
    # caller.
    async with factory() as session:
        async with session.begin():
            await session.execute(select(SQLAdmin).limit(1))


async def initialize_database(config: Config, reset: bool = False) -> None:
    """Create and initialize a new database.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        The Gafaelfawr configuration.
    reset : `bool`
        If set to `True`, drop all tables and reprovision the database.
        Useful when running tests with an external database.  Default is
        `False`.
    """
    logger = structlog.get_logger(config.safir.logger_name)

    # Check connectivity to the database and retry if needed.  This uses a
    # pre-ping to ensure the database is available and attempts to connect
    # five times with a two second delay between each attempt.
    success = False
    engine = create_async_engine(config.database_url, future=True)
    for _ in range(5):
        try:
            if reset:
                await drop_schema(engine)
            await initialize_schema(engine)
            success = True
        except (ConnectionRefusedError, OperationalError):
            logger.info("database not ready, waiting two seconds")
            time.sleep(2)
            continue
        if success:
            logger.info("initialized database schema")
            break
    if not success:
        msg = "database schema initialization failed (database not reachable?)"
        logger.error(msg)
        await engine.dispose()
        return

    # Add the initial admins.
    factory = _create_session_factory(engine)
    async with factory() as session:
        admin_store = AdminStore(session)
        async with session.begin():
            if not await admin_store.list():
                for admin in config.initial_admins:
                    logger.info("adding initial admin %s", admin)
                    await admin_store.add(Admin(username=admin))
    await engine.dispose()
