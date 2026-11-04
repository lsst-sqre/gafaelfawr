"""The github_project_template database table."""

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Mapped, mapped_column

from ._base import SchemaBase

__all__ = ["GitHubProjectTemplate"]


class GitHubProjectTemplate(SchemaBase):
    """A template from which GitHub projects can be provisioned.

    A template fixes the constraint and token policy fields of a GitHub
    project (``workflow``, ``environment``, ``ref``, ``scopes``,
    ``max_lifetime``, ``uid``, ``gid``, and ``groups``) and restricts the
    repositories that may be provisioned from it to a set of GitHub owners
    and an optional pattern on the repository name. The repository, its
    pinned GitHub IDs, the bot username derived from it, and the description
    and requester come from the provisioning request.
    """

    __tablename__ = "github_project_template"

    name: Mapped[str] = mapped_column(primary_key=True)
    description: Mapped[str | None]
    owners: Mapped[list[dict[str, Any]]]
    repository_pattern: Mapped[str | None]
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
