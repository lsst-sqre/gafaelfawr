"""The token_auth_history database table."""

from datetime import datetime

from sqlalchemy import Index, Text
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from ..models.enums import TokenType
from ._base import SchemaBase

__all__ = ["TokenAuthHistory"]


class TokenAuthHistory(SchemaBase):
    """Authentication history by token."""

    __tablename__ = "token_auth_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str]
    username: Mapped[str]
    token_type: Mapped[TokenType]
    token_name: Mapped[str | None]
    parent: Mapped[str | None]
    scopes: Mapped[str | None]
    service: Mapped[str | None]
    ip_address: Mapped[str | None] = mapped_column(
        Text().with_variant(postgresql.INET, "postgresql")
    )
    event_time: Mapped[datetime]

    __table_args__ = (
        Index("token_auth_history_by_time", "event_time", "id"),
        Index("token_auth_history_by_token", "token", "event_time", "id"),
        Index(
            "token_auth_history_by_username", "username", "event_time", "id"
        ),
    )
