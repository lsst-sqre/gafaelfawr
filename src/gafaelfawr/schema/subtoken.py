"""The subtoken databaes table."""

from __future__ import annotations

from sqlalchemy import Column, ForeignKey, Index, Integer, String

from gafaelfawr.schema.base import Base

__all__ = ["Subtoken"]


class Subtoken(Base):
    __tablename__ = "subtoken"

    id = Column(Integer, primary_key=True)
    parent = Column(String(64), ForeignKey("token.token", ondelete="SET NULL"))
    child = Column(
        String(64),
        ForeignKey("token.token", ondelete="CASCADE"),
        nullable=False,
    )

    __table_args__ = (Index("subtoken_by_parent", "parent"),)
