"""Storage for the registry of GitHub projects."""

import builtins
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from safir.database import datetime_to_db
from sqlalchemy import CursorResult, delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.github import GitHubRepository
from ..models.github_project import (
    GitHubOwner,
    GitHubProject,
    GitHubProjectCreate,
    GitHubProjectHistoryEntry,
    GitHubProjectTemplate,
    GitHubProjectTemplateCreate,
)
from ..schema import GitHubProject as SQLGitHubProject
from ..schema import GitHubProjectHistory as SQLGitHubProjectHistory
from ..schema import GitHubProjectTemplate as SQLGitHubProjectTemplate

__all__ = [
    "GitHubProjectHistoryStore",
    "GitHubProjectStore",
    "GitHubProjectTemplateStore",
]

_REGISTRY_LOCK_KEY = "gafaelfawr.github_project"
"""Advisory lock key serializing writes to the GitHub project registry."""


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
        max_lifetime: timedelta,
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
        max_lifetime
            Maximum lifetime of tokens minted for the project, either as
            given or as defaulted by the service.
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
        new = SQLGitHubProject(
            **self._to_columns(create),
            template=template,
            username=username,
            repository=repository.full_name,
            repository_id=repository.id,
            repository_owner_id=repository.owner_id,
            max_lifetime=int(max_lifetime.total_seconds()),
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

    async def lock(self) -> None:
        """Take the lock serializing writes to the registry.

        The registry has invariants that span rows, such as at most one
        enabled project matching a given token, a derived username
        belonging to a single repository, and no project naming a deleted
        template, which the service checks by reading the registry before
        writing to it. Holding this lock across the check and the write
        makes those read-then-write sequences atomic: a concurrent writer
        blocks here until this transaction commits or rolls back, and then
        sees its rows. The lock covers project templates as well as
        projects, since provisioning reads a template and writes a project.

        Must be called from inside a transaction. The lock is scoped to
        that transaction and is released automatically when it ends, so
        there is no corresponding unlock.

        Notes
        -----
        This is a single lock for the whole registry rather than one per
        repository or per username. The invariants cross those boundaries
        (a derived username ties together different repositories), so
        finer-grained locks would need to be taken in a fixed order to
        avoid deadlocks. Registry writes are rare administrative actions,
        so serializing all of them costs nothing noticeable and keeps the
        reasoning simple.

        The lock is a PostgreSQL transaction-scoped advisory lock. If there
        is ever a need to support a database without advisory locks,
        fallback code (probably locking a dedicated row) will need to be
        added here.
        """
        stmt = text("SELECT pg_advisory_xact_lock(hashtext(:key))")
        await self._session.execute(stmt, {"key": _REGISTRY_LOCK_KEY})

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
        columns = self._to_columns(project)
        columns["username"] = project.username
        columns["repository"] = project.repository
        columns["repository_id"] = project.repository_id
        columns["repository_owner_id"] = project.repository_owner_id
        columns["max_lifetime"] = int(project.max_lifetime.total_seconds())
        columns["modified"] = datetime_to_db(project.modified)
        columns["modified_by"] = project.modified_by
        for column, value in columns.items():
            setattr(existing, column, value)
        return True

    async def _get(self, project_id: int) -> SQLGitHubProject | None:
        """Retrieve the database row for a GitHub project."""
        stmt = select(SQLGitHubProject).where(
            SQLGitHubProject.id == project_id
        )
        return await self._session.scalar(stmt)

    @staticmethod
    def _to_columns(
        project: GitHubProject | GitHubProjectCreate,
    ) -> dict[str, Any]:
        """Convert the settings of a project to database column values.

        This covers the columns that are stored the same way whether a
        project is being created or updated, so that a new column need only
        be added here. The columns that are derived differently in the two
        cases, such as the repository identifiers, the maximum lifetime,
        which may be left for the service to default when creating a
        project, and the change metadata, are set by the caller.

        Parameters
        ----------
        project
            Project or request to create a project.

        Returns
        -------
        dict of str to Any
            Column values keyed by column name, suitable for passing to the
            constructor of the ORM class or assigning to an existing row.
        """
        groups = None
        if project.groups is not None:
            groups = [g.model_dump(mode="json") for g in project.groups]
        return {
            "description": project.description,
            "requested_by": project.requested_by,
            "workflow": project.workflow,
            "environment": project.environment,
            "ref": project.ref,
            "scopes": ",".join(sorted(project.scopes)),
            "uid": project.uid,
            "gid": project.gid,
            "groups": groups,
            "enabled": project.enabled,
        }


class GitHubProjectTemplateStore:
    """Stores and retrieves GitHub project templates.

    As with `GitHubProjectStore`, the rules of the registry are the
    responsibility of the service. Writes must be made under the registry
    lock taken by `GitHubProjectStore.lock`.

    Parameters
    ----------
    session
        The database session proxy.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(
        self,
        create: GitHubProjectTemplateCreate,
        *,
        owners: list[GitHubOwner],
        max_lifetime: timedelta,
        created_by: str,
    ) -> GitHubProjectTemplate:
        """Store a new GitHub project template.

        Parameters
        ----------
        create
            Fields of the new template.
        owners
            Allowed owners with their pinned IDs, as looked up on GitHub.
        max_lifetime
            Maximum lifetime of tokens minted for provisioned projects,
            either as given or as defaulted by the service.
        created_by
            Username of the person creating the template.

        Returns
        -------
        GitHubProjectTemplate
            The stored template.
        """
        now = datetime.now(tz=UTC).replace(microsecond=0)
        new = SQLGitHubProjectTemplate(
            **self._to_columns(create),
            name=create.name,
            owners=[o.model_dump(mode="json") for o in owners],
            max_lifetime=int(max_lifetime.total_seconds()),
            created=datetime_to_db(now),
            created_by=created_by,
            modified=datetime_to_db(now),
            modified_by=created_by,
        )
        self._session.add(new)
        await self._session.flush()
        return GitHubProjectTemplate.model_validate(new, from_attributes=True)

    async def delete(self, name: str) -> bool:
        """Delete a GitHub project template.

        The caller must first ensure that no project records the template,
        since the database enforces that reference.

        Parameters
        ----------
        name
            Name of the template.

        Returns
        -------
        bool
            `True` if the template was found and deleted, `False` otherwise.
        """
        stmt = delete(SQLGitHubProjectTemplate).where(
            SQLGitHubProjectTemplate.name == name
        )

        # See https://github.com/sqlalchemy/sqlalchemy/issues/9185
        # and https://github.com/sqlalchemy/sqlalchemy/issues/12813
        result = cast("CursorResult", await self._session.execute(stmt))
        return result.rowcount > 0

    async def get(self, name: str) -> GitHubProjectTemplate | None:
        """Retrieve a GitHub project template.

        Parameters
        ----------
        name
            Name of the template.

        Returns
        -------
        GitHubProjectTemplate or None
            The template, or `None` if no template has that name.
        """
        template = await self._get(name)
        if not template:
            return None
        return GitHubProjectTemplate.model_validate(
            template, from_attributes=True
        )

    async def list(self) -> builtins.list[GitHubProjectTemplate]:
        """List GitHub project templates.

        Returns
        -------
        list of GitHubProjectTemplate
            All templates, ordered by name.
        """
        stmt = select(SQLGitHubProjectTemplate).order_by(
            SQLGitHubProjectTemplate.name
        )
        result = await self._session.scalars(stmt)
        return [
            GitHubProjectTemplate.model_validate(t, from_attributes=True)
            for t in result.all()
        ]

    async def update(self, template: GitHubProjectTemplate) -> bool:
        """Replace the stored fields of a GitHub project template.

        Every field of the template except its name is written to the
        database, including the modification metadata, which the caller is
        responsible for updating.

        Parameters
        ----------
        template
            New contents of the template, identified by its name.

        Returns
        -------
        bool
            `True` if the template was found and updated, `False` otherwise.
        """
        existing = await self._get(template.name)
        if not existing:
            return False
        columns = self._to_columns(template)
        columns["owners"] = [
            o.model_dump(mode="json") for o in template.owners
        ]
        columns["max_lifetime"] = int(template.max_lifetime.total_seconds())
        columns["modified"] = datetime_to_db(template.modified)
        columns["modified_by"] = template.modified_by
        for column, value in columns.items():
            setattr(existing, column, value)
        return True

    async def _get(self, name: str) -> SQLGitHubProjectTemplate | None:
        """Retrieve the database row for a GitHub project template."""
        stmt = select(SQLGitHubProjectTemplate).where(
            SQLGitHubProjectTemplate.name == name
        )
        return await self._session.scalar(stmt)

    @staticmethod
    def _to_columns(
        template: GitHubProjectTemplate | GitHubProjectTemplateCreate,
    ) -> dict[str, Any]:
        """Convert the settings of a template to database column values.

        As for `GitHubProjectStore._to_columns`, this covers the columns
        stored the same way on creation and update. The owners, the
        maximum lifetime, and the change metadata are set by the caller.

        Parameters
        ----------
        template
            Template or request to create a template.

        Returns
        -------
        dict of str to Any
            Column values keyed by column name.
        """
        groups = None
        if template.groups is not None:
            groups = [g.model_dump(mode="json") for g in template.groups]
        return {
            "description": template.description,
            "repository_pattern": template.repository_pattern,
            "workflow": template.workflow,
            "environment": template.environment,
            "ref": template.ref,
            "scopes": ",".join(sorted(template.scopes)),
            "uid": template.uid,
            "gid": template.gid,
            "groups": groups,
            "enabled": template.enabled,
        }


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
