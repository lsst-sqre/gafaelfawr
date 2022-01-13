"""All database schema objects."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine

from .admin import Admin
from .admin_history import AdminHistory
from .base import Base
from .subtoken import Subtoken
from .token import Token
from .token_auth_history import TokenAuthHistory
from .token_change_history import TokenChangeHistory

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
