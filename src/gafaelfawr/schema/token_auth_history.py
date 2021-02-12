"""The token_auth_history database table."""

from __future__ import annotations

from sqlalchemy import Column, DateTime, Enum, Index, Integer, String
from sqlalchemy.dialects import postgresql

from gafaelfawr.models.token import TokenType
from gafaelfawr.schema.base import Base

__all__ = ["TokenAuthHistory"]


class TokenAuthHistory(Base):
    __tablename__ = "token_auth_history"

    id = Column(Integer, primary_key=True)
    token = Column(String(64), nullable=False)
    username = Column(String(64), nullable=False)
    token_type = Column(Enum(TokenType), nullable=False)
    token_name = Column(String(64))
    parent = Column(String(64))
    scopes = Column(String(512))
    service = Column(String(64))
    ip_address = Column(String(64).with_variant(postgresql.INET, "postgresql"))
    event_time = Column(DateTime, nullable=False)

    __table_args__ = (
        Index("token_auth_history_by_time", "event_time", "id"),
        Index("token_auth_history_by_token", "token", "event_time", "id"),
        Index(
            "token_auth_history_by_username", "username", "event_time", "id"
        ),
    )
