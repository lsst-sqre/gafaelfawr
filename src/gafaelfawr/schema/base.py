"""The base for the table schemas."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase

__all__ = ["SchemaBase"]


class SchemaBase(DeclarativeBase):
    """Declarative base for the Gafaelfawr database schema."""
