"""The admin_history database table.

This is a stopgap representation of changes to the admin table until we have a
group system and a group-based authorization system up and running.
"""

from __future__ import annotations

from sqlalchemy import Column, DateTime, Enum, Index, Integer, String
from sqlalchemy.dialects import postgresql

from gafaelfawr.models.history import AdminChange
from gafaelfawr.schema.base import Base

__all__ = ["AdminHistory"]


class AdminHistory(Base):
    __tablename__ = "admin_history"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), nullable=False)
    action = Column(Enum(AdminChange), nullable=False)
    actor = Column(String(64), nullable=False)
    ip_address = Column(
        String(64).with_variant(postgresql.INET, "postgresql"), nullable=False
    )
    event_time = Column(DateTime, nullable=False)

    __table_args__ = (Index("admin_history_by_time", "event_time", "id"),)
