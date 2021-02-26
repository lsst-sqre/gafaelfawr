"""All database schema objects."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.schema.admin import Admin
from gafaelfawr.schema.admin_history import AdminHistory
from gafaelfawr.schema.base import Base
from gafaelfawr.schema.subtoken import Subtoken
from gafaelfawr.schema.token import Token
from gafaelfawr.schema.token_auth_history import TokenAuthHistory
from gafaelfawr.schema.token_change_history import TokenChangeHistory

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

__all__ = [
    "Admin",
    "AdminHistory",
    "Subtoken",
    "Token",
    "TokenAuthHistory",
    "TokenChangeHistory",
    "drop_schema",
    "initialize_schema",
]


def drop_schema(engine: Engine) -> None:
    """Drop all tables to reset the database."""
    Base.metadata.drop_all(engine)


def initialize_schema(engine: Engine) -> None:
    """Initialize the database with all schema."""
    Base.metadata.create_all(engine)
