"""The token_change_history database table."""

from datetime import datetime

from sqlalchemy import Index, Text
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from ..models.enums import TokenChange, TokenType
from ._base import SchemaBase

__all__ = ["TokenChangeHistory"]


class TokenChangeHistory(SchemaBase):
    """History of changes to tokens."""

    __tablename__ = "token_change_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str]
    username: Mapped[str]
    token_type: Mapped[TokenType]
    token_name: Mapped[str | None]
    parent: Mapped[str | None]
    scopes: Mapped[str]
    service: Mapped[str | None]
    expires: Mapped[datetime | None]
    actor: Mapped[str | None]
    action: Mapped[TokenChange]
    old_token_name: Mapped[str | None]
    old_scopes: Mapped[str | None]
    old_expires: Mapped[datetime | None]
    ip_address: Mapped[str | None] = mapped_column(
        Text().with_variant(postgresql.INET, "postgresql")
    )
    event_time: Mapped[datetime]

    __table_args__ = (
        Index("token_change_history_by_time", "event_time", "id"),
        Index("token_change_history_by_token", "token", "event_time", "id"),
        Index(
            "token_change_history_by_username", "username", "event_time", "id"
        ),
    )
