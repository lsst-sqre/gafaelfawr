"""The token_auth_history database table."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Index, String
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from ..models.enums import TokenType
from .base import SchemaBase

__all__ = ["TokenAuthHistory"]


class TokenAuthHistory(SchemaBase):
    """Authentication history by token."""

    __tablename__ = "token_auth_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64))
    username: Mapped[str] = mapped_column(String(64))
    token_type: Mapped[TokenType]
    token_name: Mapped[str | None] = mapped_column(String(64))
    parent: Mapped[str | None] = mapped_column(String(64))
    scopes: Mapped[str | None] = mapped_column(String(512))
    service: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(
        String(64).with_variant(postgresql.INET, "postgresql")
    )
    event_time: Mapped[datetime]

    __table_args__ = (
        Index("token_auth_history_by_time", "event_time", "id"),
        Index("token_auth_history_by_token", "token", "event_time", "id"),
        Index(
            "token_auth_history_by_username", "username", "event_time", "id"
        ),
    )
