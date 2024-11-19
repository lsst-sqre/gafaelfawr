"""The admin database table.

This is a stopgap representation of admins until we have a group system and a
group-based authorization system up and running.
"""

from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from .base import SchemaBase

__all__ = ["Admin"]


class Admin(SchemaBase):
    """List of users with admin privileges."""

    __tablename__ = "admin"

    username: Mapped[str] = mapped_column(String(64), primary_key=True)
