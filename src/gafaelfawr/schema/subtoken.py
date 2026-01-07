"""The subtoken database table."""

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import SchemaBase

__all__ = ["Subtoken"]


class Subtoken(SchemaBase):
    """Records parent/child relationships for tokens."""

    __tablename__ = "subtoken"

    child: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("token.token", ondelete="CASCADE"),
        primary_key=True,
    )
    parent: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("token.token", ondelete="SET NULL")
    )

    __table_args__ = (Index("subtoken_by_parent", "parent"),)
