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
    from sqlalchemy.ext.asyncio import AsyncEngine

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


async def drop_schema(engine: AsyncEngine) -> None:
    """Drop all tables to reset the database."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def initialize_schema(engine: AsyncEngine) -> None:
    """Initialize the database with all schema."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
