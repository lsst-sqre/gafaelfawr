"""The admin database table.

This is a stopgap representation of admins until we have a group system and a
group-based authorization system up and running.
"""

from __future__ import annotations

from sqlalchemy import Column, String

from gafaelfawr.schema.base import Base

__all__ = ["Admin"]


class Admin(Base):
    __tablename__ = "admin"

    username = Column(String(64), primary_key=True)
