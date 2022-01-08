"""The token_auth_history database table."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, Enum, Index, Integer, String
from sqlalchemy.dialects import postgresql

from gafaelfawr.models.token import TokenType
from gafaelfawr.schema.base import Base

__all__ = ["TokenAuthHistory"]


class TokenAuthHistory(Base):
    __tablename__ = "token_auth_history"

    id: int = Column(Integer, primary_key=True)
    token: str = Column(String(64), nullable=False)
    username: str = Column(String(64), nullable=False)
    token_type: TokenType = Column(Enum(TokenType), nullable=False)
    token_name: Optional[str] = Column(String(64))
    parent: Optional[str] = Column(String(64))
    scopes: Optional[str] = Column(String(512))
    service: Optional[str] = Column(String(64))
    ip_address: Optional[str] = Column(
        String(64).with_variant(postgresql.INET, "postgresql")
    )
    event_time: datetime = Column(DateTime, nullable=False)

    __table_args__ = (
        Index("token_auth_history_by_time", "event_time", "id"),
        Index("token_auth_history_by_token", "token", "event_time", "id"),
        Index(
            "token_auth_history_by_username", "username", "event_time", "id"
        ),
    )
