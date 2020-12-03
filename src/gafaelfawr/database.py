"""Utility functions for database management.

SQLAlchemy, when creating a database schema, can only know about the tables
that have been registered via a metaclass.  This module therefore must import
every schema to ensure that SQLAlchemy has a complete view.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from gafaelfawr.models.admin import Admin
from gafaelfawr.schema import initialize_schema
from gafaelfawr.storage.admin import AdminStore
from gafaelfawr.storage.transaction import TransactionManager

if TYPE_CHECKING:
    from gafaelfawr.config import Config


def initialize_database(config: Config) -> None:
    """Create and initialize a new database.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        The Gafaelfawr configuration.
    """
    logger = structlog.get_logger(config.safir.logger_name)

    # Check connectivity to the database and retry if needed.  This uses a
    # pre-ping to ensure the database is available and attempts to connect
    # five times with a two second delay between each attempt.
    for _ in range(5):
        try:
            engine = create_engine(config.database_url, pool_pre_ping=True)
            initialize_schema(engine)
        except OperationalError:
            logger.info("database not ready, waiting two seconds")
            time.sleep(2)
            continue
        logger.info("initialized database schema")
        break

    session = Session(bind=engine)
    with TransactionManager(session).transaction():
        admin_store = AdminStore(session)
        if not admin_store.list():
            for admin in config.initial_admins:
                logger.info("adding initial admin %s", admin)
                admin_store.add(Admin(username=admin))
