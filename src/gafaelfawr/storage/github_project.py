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
    GitHubProjectTemplateUpdate,
    GitHubProjectUpdate,
)
from ..models.userinfo import Group
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


def _groups_to_db(groups: list[Group] | None) -> list[Any] | None:
    """Convert the groups of a project or template to their stored form."""
    if groups is None:
        return None
    return [g.model_dump(mode="json") for g in groups]


def _owners_to_db(owners: list[GitHubOwner]) -> list[Any]:
    """Convert the owners of a template to their stored form."""
    return [o.model_dump(mode="json") for o in owners]


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
            max_lifetime=int(max_lifetime.total_seconds()),
            uid=create.uid,
            gid=create.gid,
            groups=_groups_to_db(create.groups),
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

    async def update(  # noqa: C901, PLR0912
        self,
        project_id: int,
        update: GitHubProjectUpdate,
        *,
        username: str | None,
        repository: GitHubRepository | None,
        modified: datetime,
        modified_by: str,
    ) -> bool:
        """Modify a GitHub project.

        Only the fields set in the update are changed. The username and
        repository are taken from the separate arguments rather than from the
        update, since the service resolves them. Each field is assigned
        explicitly, so a new field of the project must be added here as well
        as to `add`.

        Parameters
        ----------
        project_id
            ID of the project.
        update
            Changes to apply.
        username
            New bot username of the project, either as given or as derived
            from the repository, or `None` to leave it unchanged.
        repository
            Repository metadata from GitHub if the repository is changing,
            used for the canonical name of the repository and its pinned
            IDs, or `None` to leave the repository unchanged.
        modified
            Time of the change.
        modified_by
            Username of the person making the change.

        Returns
        -------
        bool
            `True` if the project was found and updated, `False` otherwise.
        """
        project = await self._get(project_id)
        if not project:
            return False
        fields = update.model_fields_set
        if "description" in fields:
            project.description = update.description
        if "requested_by" in fields:
            project.requested_by = update.requested_by
        if username is not None:
            project.username = username
        if repository is not None:
            project.repository = repository.full_name
            project.repository_id = repository.id
            project.repository_owner_id = repository.owner_id
        if "workflow" in fields:
            project.workflow = update.workflow
        if "environment" in fields:
            project.environment = update.environment
        if "ref" in fields:
            project.ref = update.ref
        if update.scopes is not None:
            project.scopes = ",".join(sorted(update.scopes))
        if update.max_lifetime is not None:
            project.max_lifetime = int(update.max_lifetime.total_seconds())
        if "uid" in fields:
            project.uid = update.uid
        if "gid" in fields:
            project.gid = update.gid
        if "groups" in fields:
            project.groups = _groups_to_db(update.groups)
        if update.enabled is not None:
            project.enabled = update.enabled
        project.modified = datetime_to_db(modified)
        project.modified_by = modified_by
        return True

    async def _get(self, project_id: int) -> SQLGitHubProject | None:
        """Retrieve the database row for a GitHub project."""
        stmt = select(SQLGitHubProject).where(
            SQLGitHubProject.id == project_id
        )
        return await self._session.scalar(stmt)


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
            name=create.name,
            description=create.description,
            owners=_owners_to_db(owners),
            repository_pattern=create.repository_pattern,
            workflow=create.workflow,
            environment=create.environment,
            ref=create.ref,
            scopes=",".join(sorted(create.scopes)),
            max_lifetime=int(max_lifetime.total_seconds()),
            uid=create.uid,
            gid=create.gid,
            groups=_groups_to_db(create.groups),
            enabled=create.enabled,
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

    async def update(  # noqa: C901, PLR0912
        self,
        name: str,
        update: GitHubProjectTemplateUpdate,
        *,
        owners: builtins.list[GitHubOwner] | None,
        modified: datetime,
        modified_by: str,
    ) -> bool:
        """Modify a GitHub project template.

        Only the fields set in the update are changed. The owners are taken
        from the separate argument rather than from the update, since the
        service resolves them. Each field is assigned explicitly, so a new
        field of the template must be added here as well as to `add`.

        Parameters
        ----------
        name
            Name of the template.
        update
            Changes to apply.
        owners
            New allowed owners with their pinned IDs, as resolved by the
            service, or `None` to leave the owners unchanged.
        modified
            Time of the change.
        modified_by
            Username of the person making the change.

        Returns
        -------
        bool
            `True` if the template was found and updated, `False` otherwise.
        """
        template = await self._get(name)
        if not template:
            return False
        fields = update.model_fields_set
        if "description" in fields:
            template.description = update.description
        if owners is not None:
            template.owners = _owners_to_db(owners)
        if "repository_pattern" in fields:
            template.repository_pattern = update.repository_pattern
        if "workflow" in fields:
            template.workflow = update.workflow
        if "environment" in fields:
            template.environment = update.environment
        if "ref" in fields:
            template.ref = update.ref
        if update.scopes is not None:
            template.scopes = ",".join(sorted(update.scopes))
        if update.max_lifetime is not None:
            template.max_lifetime = int(update.max_lifetime.total_seconds())
        if "uid" in fields:
            template.uid = update.uid
        if "gid" in fields:
            template.gid = update.gid
        if "groups" in fields:
            template.groups = _groups_to_db(update.groups)
        if update.enabled is not None:
            template.enabled = update.enabled
        template.modified = datetime_to_db(modified)
        template.modified_by = modified_by
        return True

    async def _get(self, name: str) -> SQLGitHubProjectTemplate | None:
        """Retrieve the database row for a GitHub project template."""
        stmt = select(SQLGitHubProjectTemplate).where(
            SQLGitHubProjectTemplate.name == name
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
