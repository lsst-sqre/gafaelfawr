"""The token database table."""

from datetime import datetime

from sqlalchemy import Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..models.enums import TokenType
from .base import SchemaBase

__all__ = ["Token"]


class Token(SchemaBase):
    """Metadata for a token."""

    __tablename__ = "token"

    token: Mapped[str] = mapped_column(
        String(64, collation="C"), primary_key=True
    )
    username: Mapped[str] = mapped_column(String(64))
    token_type: Mapped[TokenType]
    token_name: Mapped[str | None] = mapped_column(String(64))
    scopes: Mapped[str] = mapped_column(String(512))
    service: Mapped[str | None] = mapped_column(String(64))
    created: Mapped[datetime]
    last_used: Mapped[datetime | None]
    expires: Mapped[datetime | None]

    __table_args__ = (
        UniqueConstraint("username", "token_name"),
        Index("token_by_username", "username", "token_type"),
    )
