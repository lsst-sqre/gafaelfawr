"""The subtoken database table."""

from __future__ import annotations

from sqlalchemy import Column, ForeignKey, Index, String

from .base import Base

__all__ = ["Subtoken"]


class Subtoken(Base):
    """Records parent/child relationships for tokens."""

    __tablename__ = "subtoken"

    child: str = Column(
        String(64),
        ForeignKey("token.token", ondelete="CASCADE"),
        primary_key=True,
    )
    parent: str | None = Column(
        String(64), ForeignKey("token.token", ondelete="SET NULL")
    )

    __table_args__ = (Index("subtoken_by_parent", "parent"),)
