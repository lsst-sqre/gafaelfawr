"""The token_change_history database table."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Column, DateTime, Enum, Index, Integer, String
from sqlalchemy.dialects import postgresql

from gafaelfawr.models.history import TokenChange
from gafaelfawr.models.token import TokenType
from gafaelfawr.schema.base import Base

if TYPE_CHECKING:
    from datetime import datetime
    from typing import Optional

__all__ = ["TokenChangeHistory"]


class TokenChangeHistory(Base):
    __tablename__ = "token_change_history"

    id: int = Column(Integer, primary_key=True)
    token: str = Column(String(64), nullable=False)
    username: str = Column(String(64), nullable=False)
    token_type: TokenType = Column(Enum(TokenType), nullable=False)
    token_name: Optional[str] = Column(String(64))
    parent: str = Column(String(64))
    scopes: str = Column(String(512), nullable=False)
    service: Optional[str] = Column(String(64))
    expires: Optional[datetime] = Column(DateTime)
    actor: Optional[str] = Column(String(64))
    action: TokenChange = Column(Enum(TokenChange), nullable=False)
    old_token_name: Optional[str] = Column(String(64))
    old_scopes: Optional[str] = Column(String(512))
    old_expires: Optional[datetime] = Column(DateTime)
    ip_address: Optional[str] = Column(
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
