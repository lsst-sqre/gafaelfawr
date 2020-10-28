"""Utility functions for database management.

SQLAlchemy, when creating a database schema, can only know about the tables
that have been registered via a metaclass.  This module therefore must import
every schema to ensure that SQLAlchemy has a complete view.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from gafaelfawr.models.admin import Admin
from gafaelfawr.schema import initialize_schema
from gafaelfawr.storage.admin import AdminStore

if TYPE_CHECKING:
    from gafaelfawr.config import Config


def initialize_database(config: Config) -> None:
    """Create and initialize a new database.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        The Gafaelfawr configuration.
    """
    engine = create_engine(config.database_url)
    initialize_schema(engine)
    session = Session(bind=engine)
    admin_store = AdminStore(session)
    for admin in config.initial_admins:
        admin_store.add(Admin(username=admin))
