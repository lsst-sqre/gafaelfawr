"""The token database table."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Enum, Index, String, UniqueConstraint

from ..models.token import TokenType
from .base import Base

__all__ = ["Token"]


class Token(Base):
    """Metadata for a token."""

    __tablename__ = "token"

    token: str = Column(String(64, collation="C"), primary_key=True)
    username: str = Column(String(64), nullable=False)
    token_type: TokenType = Column(Enum(TokenType), nullable=False)
    token_name: str | None = Column(String(64))
    scopes: str = Column(String(512), nullable=False)
    service: str | None = Column(String(64))
    created: datetime = Column(DateTime, nullable=False)
    last_used: datetime | None = Column(DateTime)
    expires: datetime | None = Column(DateTime)

    __table_args__ = (
        UniqueConstraint("username", "token_name"),
        Index("token_by_username", "username", "token_type"),
    )
