"""The subtoken database table."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Column, ForeignKey, Index, String

from gafaelfawr.schema.base import Base

if TYPE_CHECKING:
    from typing import Optional

__all__ = ["Subtoken"]


class Subtoken(Base):
    __tablename__ = "subtoken"

    child: str = Column(
        String(64),
        ForeignKey("token.token", ondelete="CASCADE"),
        primary_key=True,
    )
    parent: Optional[str] = Column(
        String(64), ForeignKey("token.token", ondelete="SET NULL")
    )

    __table_args__ = (Index("subtoken_by_parent", "parent"),)
