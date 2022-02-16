"""The base for the table schemas."""

from __future__ import annotations

from sqlalchemy.orm import declarative_base

__all__ = ["Base"]

Base = declarative_base()
