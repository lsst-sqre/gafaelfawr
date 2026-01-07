"""The admin_history database table.

This is a stopgap representation of changes to the admin table until we have a
group system and a group-based authorization system up and running.
"""

from datetime import datetime

from sqlalchemy import Index, String
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from ..models.enums import AdminChange
from .base import SchemaBase

__all__ = ["AdminHistory"]


class AdminHistory(SchemaBase):
    """History of changes to the list of admins."""

    __tablename__ = "admin_history"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64))
    action: Mapped[AdminChange]
    actor: Mapped[str] = mapped_column(String(64))
    ip_address: Mapped[str] = mapped_column(
        String(64).with_variant(postgresql.INET, "postgresql")
    )
    event_time: Mapped[datetime]

    __table_args__ = (Index("admin_history_by_time", "event_time", "id"),)
