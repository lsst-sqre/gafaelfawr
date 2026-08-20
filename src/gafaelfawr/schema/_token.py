"""The token database table."""

from datetime import datetime

from sqlalchemy import Index, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..models.enums import TokenType
from ._base import SchemaBase

__all__ = ["Token"]


class Token(SchemaBase):
    """Metadata for a token."""

    __tablename__ = "token"

    token: Mapped[str] = mapped_column(Text(collation="C"), primary_key=True)
    username: Mapped[str]
    token_type: Mapped[TokenType]
    token_name: Mapped[str | None]
    scopes: Mapped[str]
    service: Mapped[str | None]
    created: Mapped[datetime]
    last_used: Mapped[datetime | None]
    expires: Mapped[datetime | None]

    __table_args__ = (
        UniqueConstraint("username", "token_name"),
        Index("token_by_username", "username", "token_type"),
    )
