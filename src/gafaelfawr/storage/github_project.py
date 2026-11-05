"""Storage for the registry of GitHub projects."""

import builtins
from datetime import UTC, datetime
from typing import cast

from safir.database import datetime_to_db
from sqlalchemy import CursorResult, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.github import GitHubRepository
from ..models.github_project import (
    GitHubProject,
    GitHubProjectCreate,
    GitHubProjectHistoryEntry,
)
from ..schema import GitHubProject as SQLGitHubProject
from ..schema import GitHubProjectHistory as SQLGitHubProjectHistory

__all__ = ["GitHubProjectHistoryStore", "GitHubProjectStore"]


class GitHubProjectStore:
    """Stores and retrieves registered GitHub projects.

    The store performs no validation beyond what the database enforces. The
    rules of the registry, such as deriving the bot username, pinning the
    repository IDs, and refusing overlapping projects, are the responsibility
    of the service.

    Parameters
    ----------
    session
        The database session proxy.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(
        self,
        create: GitHubProjectCreate,
        *,
        username: str,
        repository: GitHubRepository,
        created_by: str,
        template: str | None = None,
    ) -> GitHubProject:
        """Store a new GitHub project.

        Parameters
        ----------
        create
            Fields of the new project.
        username
            Bot username of the project, either as given or as derived from
            the repository.
        repository
            Repository metadata from GitHub, used for the canonical name of
            the repository and its pinned IDs.
        created_by
            Username of the person creating the project.
        template
            Name of the project template the project was provisioned from,
            if any.

        Returns
        -------
        GitHubProject
            The stored project, including its assigned ID.
        """
        now = datetime.now(tz=UTC).replace(microsecond=0)
        groups = None
        if create.groups is not None:
            groups = [g.model_dump(mode="json") for g in create.groups]
        new = SQLGitHubProject(
            template=template,
            description=create.description,
            requested_by=create.requested_by,
            username=username,
            repository=repository.full_name,
            repository_id=repository.id,
            repository_owner_id=repository.owner_id,
            workflow=create.workflow,
            environment=create.environment,
            ref=create.ref,
            scopes=",".join(sorted(create.scopes)),
            max_lifetime=int(create.max_lifetime.total_seconds()),
            uid=create.uid,
            gid=create.gid,
            groups=groups,
            enabled=create.enabled,
            created=datetime_to_db(now),
            created_by=created_by,
            modified=datetime_to_db(now),
            modified_by=created_by,
        )
        self._session.add(new)
        await self._session.flush()
        return GitHubProject.model_validate(new, from_attributes=True)

    async def delete(self, project_id: int) -> bool:
        """Delete a GitHub project.

        Parameters
        ----------
        project_id
            ID of the project.

        Returns
        -------
        bool
            `True` if the project was found and deleted, `False` otherwise.
        """
        stmt = delete(SQLGitHubProject).where(
            SQLGitHubProject.id == project_id
        )

        # See https://github.com/sqlalchemy/sqlalchemy/issues/9185
        # and https://github.com/sqlalchemy/sqlalchemy/issues/12813
        result = cast("CursorResult", await self._session.execute(stmt))
        return result.rowcount > 0

    async def get(self, project_id: int) -> GitHubProject | None:
        """Retrieve a GitHub project.

        Parameters
        ----------
        project_id
            ID of the project.

        Returns
        -------
        GitHubProject or None
            The project, or `None` if no project has that ID.
        """
        project = await self._get(project_id)
        if not project:
            return None
        return GitHubProject.model_validate(project, from_attributes=True)

    async def list(
        self,
        *,
        repository: str | None = None,
        username: str | None = None,
        template: str | None = None,
        requested_by: str | None = None,
    ) -> builtins.list[GitHubProject]:
        """List GitHub projects.

        Parameters
        ----------
        repository
            Limit the results to projects for this repository, compared
            case-insensitively.
        username
            Limit the results to projects for this bot username.
        template
            Limit the results to projects provisioned from this template.
        requested_by
            Limit the results to projects requested by this identifier.

        Returns
        -------
        list of GitHubProject
            Matching projects, ordered by ID.
        """
        stmt = select(SQLGitHubProject)
        if repository:
            stmt = stmt.where(
                func.lower(SQLGitHubProject.repository) == repository.lower()
            )
        if username:
            stmt = stmt.where(SQLGitHubProject.username == username)
        if template:
            stmt = stmt.where(SQLGitHubProject.template == template)
        if requested_by:
            stmt = stmt.where(SQLGitHubProject.requested_by == requested_by)
        stmt = stmt.order_by(SQLGitHubProject.id)
        result = await self._session.scalars(stmt)
        return [
            GitHubProject.model_validate(p, from_attributes=True)
            for p in result.all()
        ]

    async def update(self, project: GitHubProject) -> bool:
        """Replace the stored fields of a GitHub project.

        Every field of the project except its ID and template is written to
        the database, including the modification metadata, which the caller
        is responsible for updating.

        Parameters
        ----------
        project
            New contents of the project, identified by its ID.

        Returns
        -------
        bool
            `True` if the project was found and updated, `False` otherwise.
        """
        existing = await self._get(project.id)
        if not existing:
            return False
        groups = None
        if project.groups is not None:
            groups = [g.model_dump(mode="json") for g in project.groups]
        existing.description = project.description
        existing.requested_by = project.requested_by
        existing.username = project.username
        existing.repository = project.repository
        existing.repository_id = project.repository_id
        existing.repository_owner_id = project.repository_owner_id
        existing.workflow = project.workflow
        existing.environment = project.environment
        existing.ref = project.ref
        existing.scopes = ",".join(sorted(project.scopes))
        existing.max_lifetime = int(project.max_lifetime.total_seconds())
        existing.uid = project.uid
        existing.gid = project.gid
        existing.groups = groups
        existing.enabled = project.enabled
        existing.modified = datetime_to_db(project.modified)
        existing.modified_by = project.modified_by
        return True

    async def _get(self, project_id: int) -> SQLGitHubProject | None:
        """Retrieve the database row for a GitHub project."""
        stmt = select(SQLGitHubProject).where(
            SQLGitHubProject.id == project_id
        )
        return await self._session.scalar(stmt)


class GitHubProjectHistoryStore:
    """Stores and retrieves the history of changes to GitHub projects.

    Parameters
    ----------
    session
        The database session proxy.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entry: GitHubProjectHistoryEntry) -> None:
        """Record a change to a GitHub project or project template.

        Parameters
        ----------
        entry
            New entry to add to the database.
        """
        new = SQLGitHubProjectHistory(**entry.model_dump())
        new.event_time = datetime_to_db(entry.event_time)
        self._session.add(new)

    async def list(
        self,
        *,
        project_id: int | None = None,
        template: str | None = None,
    ) -> builtins.list[GitHubProjectHistoryEntry]:
        """List changes to GitHub projects and project templates.

        Parameters
        ----------
        project_id
            Limit the results to changes to this project.
        template
            Limit the results to changes to this template or to projects
            provisioned from it.

        Returns
        -------
        list of GitHubProjectHistoryEntry
            Matching changes in the order they were made.
        """
        stmt = select(SQLGitHubProjectHistory)
        if project_id is not None:
            stmt = stmt.where(SQLGitHubProjectHistory.project_id == project_id)
        if template:
            stmt = stmt.where(SQLGitHubProjectHistory.template == template)
        stmt = stmt.order_by(
            SQLGitHubProjectHistory.event_time, SQLGitHubProjectHistory.id
        )
        result = await self._session.scalars(stmt)
        return [
            GitHubProjectHistoryEntry.model_validate(e, from_attributes=True)
            for e in result.all()
        ]
