"""The admin_history database table.

This is a stopgap representation of changes to the admin table until we have a
group system and a group-based authorization system up and running.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Enum, Index, Integer, String
from sqlalchemy.dialects import postgresql

from ..models.history import AdminChange
from .base import Base

__all__ = ["AdminHistory"]


class AdminHistory(Base):
    __tablename__ = "admin_history"

    id: int = Column(Integer, primary_key=True)
    username: str = Column(String(64), nullable=False)
    action: AdminChange = Column(Enum(AdminChange), nullable=False)
    actor: str = Column(String(64), nullable=False)
    ip_address: str = Column(
        String(64).with_variant(postgresql.INET, "postgresql"), nullable=False
    )
    event_time: datetime = Column(DateTime, nullable=False)

    __table_args__ = (Index("admin_history_by_time", "event_time", "id"),)
