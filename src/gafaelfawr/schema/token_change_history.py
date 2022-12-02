"""The token_change_history database table."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Enum, Index, Integer, String
from sqlalchemy.dialects import postgresql

from ..models.history import TokenChange
from ..models.token import TokenType
from .base import Base

__all__ = ["TokenChangeHistory"]


class TokenChangeHistory(Base):
    """History of changes to tokens."""

    __tablename__ = "token_change_history"

    id: int = Column(Integer, primary_key=True)
    token: str = Column(String(64), nullable=False)
    username: str = Column(String(64), nullable=False)
    token_type: TokenType = Column(Enum(TokenType), nullable=False)
    token_name: str | None = Column(String(64))
    parent: str = Column(String(64))
    scopes: str = Column(String(512), nullable=False)
    service: str | None = Column(String(64))
    expires: datetime | None = Column(DateTime)
    actor: str | None = Column(String(64))
    action: TokenChange = Column(Enum(TokenChange), nullable=False)
    old_token_name: str | None = Column(String(64))
    old_scopes: str | None = Column(String(512))
    old_expires: datetime | None = Column(DateTime)
    ip_address: str | None = Column(
        String(64).with_variant(postgresql.INET, "postgresql")
    )
    event_time: datetime = Column(DateTime, nullable=False)

    __table_args__ = (
        Index("token_change_history_by_time", "event_time", "id"),
        Index("token_change_history_by_token", "token", "event_time", "id"),
        Index(
            "token_change_history_by_username", "username", "event_time", "id"
        ),
    )
