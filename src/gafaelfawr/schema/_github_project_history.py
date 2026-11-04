"""The github_project_history database table."""

from datetime import datetime
from typing import Any

from sqlalchemy import Index
from sqlalchemy.orm import Mapped, mapped_column

from ..models.enums import GitHubProjectChange
from ._base import INET_TYPE, SchemaBase

__all__ = ["GitHubProjectHistory"]


class GitHubProjectHistory(SchemaBase):
    """History of changes to GitHub projects and project templates.

    Each row records a change to either a project or a project template.
    Rows for projects set ``project_id`` (and ``template`` if the project was
    provisioned from a template); rows for templates set only ``template``.
    The ``old_values`` and ``new_values`` columns hold the serialized
    resource before and after the change, so they are null for creations and
    deletions respectively.
    """

    __tablename__ = "github_project_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int | None]
    template: Mapped[str | None]
    action: Mapped[GitHubProjectChange]
    actor: Mapped[str]
    ip_address: Mapped[str | None] = mapped_column(INET_TYPE)
    event_time: Mapped[datetime]
    old_values: Mapped[dict[str, Any] | None]
    new_values: Mapped[dict[str, Any] | None]

    __table_args__ = (
        Index("github_project_history_by_time", "event_time", "id"),
        Index(
            "github_project_history_by_project",
            "project_id",
            "event_time",
            "id",
        ),
        Index(
            "github_project_history_by_template",
            "template",
            "event_time",
            "id",
        ),
    )
