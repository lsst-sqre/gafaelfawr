"""The token database table."""

from datetime import datetime

from sqlalchemy import ForeignKey, Index, Text, UniqueConstraint, text
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
    github_project_id: Mapped[int | None] = mapped_column(
        ForeignKey("github_project.id", deferrable=True, initially="DEFERRED")
    )
    """ID of the GitHub project that authorized the token, if any.

    The foreign key ensures that a token can never reference a GitHub project
    that does not exist. It has no ``ON DELETE`` action because the tokens of
    a project must be revoked by the service when the project is deleted:
    tokens are valid as long as they are in Redis, so deleting or unlinking
    their rows in the database would leave them usable. The constraint is
    deferred so that the service can delete the project and then revoke its
    tokens in the same transaction, with the check made at commit.
    """

    __table_args__ = (
        UniqueConstraint("username", "token_name"),
        Index("token_by_username", "username", "token_type"),
        Index(
            "token_by_github_project",
            "github_project_id",
            postgresql_where=text("github_project_id IS NOT NULL"),
        ),
        # Service tokens are a small fraction of a table dominated by
        # session, notebook, and internal tokens, so index them separately
        # to keep listing them cheap. text_pattern_ops lets the index match
        # a username prefix, which a B-tree index cannot do unless the
        # collation of the database is C.
        Index(
            "token_by_service_username",
            "username",
            "created",
            "token",
            postgresql_where=text("token_type = 'service'"),
            postgresql_ops={"username": "text_pattern_ops"},
        ),
    )
