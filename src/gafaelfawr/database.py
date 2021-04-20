"""Utility functions for database management.

SQLAlchemy, when creating a database schema, can only know about the tables
that have been registered via a metaclass.  This module therefore must import
every schema to ensure that SQLAlchemy has a complete view.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import create_engine, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from gafaelfawr.models.admin import Admin
from gafaelfawr.schema import Admin as SQLAdmin
from gafaelfawr.schema import drop_schema, initialize_schema
from gafaelfawr.storage.admin import AdminStore
from gafaelfawr.storage.transaction import TransactionManager

if TYPE_CHECKING:
    from structlog.stdlib import BoundLogger

    from gafaelfawr.config import Config

__all__ = ["create_session", "initialize_database"]


def create_session(config: Config, logger: BoundLogger) -> Session:
    """Create a new database session.

    Checks that the database is available and retries in a loop for 10s if it
    is not.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        The Gafaelfawr configuration.

    Returns
    -------
    session : `sqlalchemy.orm.Session`
        The database session.
    """
    for _ in range(5):
        try:
            engine = create_engine(config.database_url)
            session = Session(bind=engine)
            session.execute(select(SQLAdmin))
            return session
        except OperationalError:
            logger.info("database not ready, waiting two seconds")
            time.sleep(2)
            continue

    # If we got here, we failed five times.  Try one last time without
    # catching exceptions so that we raise the appropriate exception to our
    # caller.
    engine = create_engine(config.database_url)
    session = Session(bind=engine)
    session.execute(select(Admin))
    return session


def initialize_database(config: Config, reset: bool = False) -> None:
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
    for _ in range(5):
        try:
            engine = create_engine(config.database_url, pool_pre_ping=True)
            if reset:
                drop_schema(engine)
            initialize_schema(engine)
            success = True
        except OperationalError:
            logger.info("database not ready, waiting two seconds")
            time.sleep(2)
            continue
        if success:
            logger.info("initialized database schema")
        break
    if not success:
        msg = "database schema initialization failed (database not reachable?)"
        logger.error(msg)

    session = Session(bind=engine)
    with TransactionManager(session).transaction():
        admin_store = AdminStore(session)
        if not admin_store.list():
            for admin in config.initial_admins:
                logger.info("adding initial admin %s", admin)
                admin_store.add(Admin(username=admin))
    session.close()
