"""The github_project database table."""

from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, func
from sqlalchemy.orm import Mapped, mapped_column

from ._base import SchemaBase

__all__ = ["GitHubProject"]


class GitHubProject(SchemaBase):
    """A GitHub project registered for the GitHub Actions token exchange.

    A project binds a set of constraints on the claims of a GitHub Actions
    OIDC token to a bot username and a token policy. Tokens minted by the
    exchange record the ID of the project that authorized them in the
    ``github_project_id`` column of the token tables, but without a foreign
    key, since revocation is handled by the service rather than by the
    database.
    """

    __tablename__ = "github_project"

    id: Mapped[int] = mapped_column(primary_key=True)
    template: Mapped[str | None] = mapped_column(
        ForeignKey("github_project_template.name")
    )
    description: Mapped[str | None]
    requested_by: Mapped[str | None]
    username: Mapped[str]
    repository: Mapped[str]
    """GitHub repository as ``owner/name``, in the case GitHub reports.

    The exchange matches this column case-insensitively against the
    ``repository`` claim, so lookups must compare ``lower(repository)`` to
    use the ``github_project_by_repository`` index.
    """

    repository_id: Mapped[int]
    repository_owner_id: Mapped[int]
    workflow: Mapped[str | None]
    environment: Mapped[str | None]
    ref: Mapped[str | None]
    scopes: Mapped[str]
    max_lifetime: Mapped[int]
    uid: Mapped[int | None]
    gid: Mapped[int | None]
    groups: Mapped[list[dict[str, Any]] | None]
    enabled: Mapped[bool]
    created: Mapped[datetime]
    created_by: Mapped[str]
    modified: Mapped[datetime]
    modified_by: Mapped[str]

    __table_args__ = (
        Index("github_project_by_requested_by", "requested_by"),
        Index("github_project_by_template", "template"),
        Index("github_project_by_username", "username"),
    )


# Functional index for the case-insensitive repository lookup. This has to be
# declared after the class so that the column can be referenced.
Index("github_project_by_repository", func.lower(GitHubProject.repository))
