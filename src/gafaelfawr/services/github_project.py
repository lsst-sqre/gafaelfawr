"""Manage the registry of GitHub projects."""

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import BoundLogger

from ..config import GitHubTokenExchangeConfig
from ..constants import (
    GITHUB_BOT_USERNAME_PREFIX,
    GITHUB_BOT_USERNAME_REGEX,
    GITHUB_PROJECT_DEFAULT_LIFETIME,
    MINIMUM_LIFETIME,
)
from ..exceptions import (
    DuplicateGitHubUsernameError,
    GitHubProjectOverlapError,
    InvalidGitHubUsernameError,
    InvalidMaxLifetimeError,
    InvalidScopesError,
    NotFoundError,
    PermissionDeniedError,
)
from ..models.enums import GitHubProjectChange
from ..models.github_project import (
    GitHubProject,
    GitHubProjectCreate,
    GitHubProjectHistoryEntry,
    GitHubProjectUpdate,
)
from ..models.token import TokenData
from ..storage.github import GitHubStorage
from ..storage.github_project import (
    GitHubProjectHistoryStore,
    GitHubProjectStore,
)
from .token import TokenService

__all__ = ["GitHubProjectService"]


class GitHubProjectService:
    """Manage the registry of GitHub projects.

    The registry is the trust configuration of the GitHub Actions token
    exchange: it says which GitHub workflows may obtain Gafaelfawr tokens, as
    whom, with which scopes, and for how long. This service enforces the
    rules of the registry, such as deriving bot usernames, pinning the
    GitHub IDs of repositories, and refusing projects whose constraints
    overlap, and records every change in the project history.

    Parameters
    ----------
    config
        Configuration for the GitHub Actions token exchange.
    known_scopes
        Scopes known to this Gafaelfawr instance.
    project_store
        Backing store for GitHub projects.
    history_store
        Backing store for the history of changes to GitHub projects.
    github_storage
        Client for looking up repository metadata from GitHub.
    token_service
        Token manipulation service, used to revoke the tokens of a project.
    session
        Database session.
    logger
        Logger to use.
    """

    def __init__(
        self,
        *,
        config: GitHubTokenExchangeConfig,
        known_scopes: set[str],
        project_store: GitHubProjectStore,
        history_store: GitHubProjectHistoryStore,
        github_storage: GitHubStorage,
        token_service: TokenService,
        session: AsyncSession,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._known_scopes = known_scopes
        self._project_store = project_store
        self._history_store = history_store
        self._github = github_storage
        self._token_service = token_service
        self._session = session
        self._logger = logger

    async def create_project(
        self,
        create: GitHubProjectCreate,
        auth_data: TokenData,
        *,
        ip_address: str | None,
    ) -> GitHubProject:
        """Create a new GitHub project.

        The repository is looked up on GitHub to pin its numeric IDs. If no
        username was given, one is derived from the repository. If no
        maximum lifetime was given, the default lifetime is used, capped by
        the configured maximum lifetime of the token exchange.

        Parameters
        ----------
        create
            Fields of the new project.
        auth_data
            The data for the authenticated user making the request.
        ip_address
            The IP address from which the request came, or `None` for
            internal requests by Gafaelfawr.

        Returns
        -------
        GitHubProject
            The newly-created project.

        Raises
        ------
        DuplicateGitHubUsernameError
            Raised if the derived username is already used by a project for
            a different repository.
        GitHubError
            Raised if GitHub returned invalid repository data.
        GitHubProjectOverlapError
            Raised if the project is enabled and its constraints overlap
            those of an existing enabled project for the same repository.
        GitHubWebError
            Raised if an HTTP error occurred talking to GitHub.
        InvalidGitHubUsernameError
            Raised if the derived username is not a valid username.
        InvalidMaxLifetimeError
            Raised if the maximum lifetime is out of range.
        InvalidScopesError
            Raised if the scopes are unknown or not permitted.
        PermissionDeniedError
            Raised if the authenticated user is not a token administrator.
        UnknownGitHubRepositoryError
            Raised if the repository does not exist or is not public.
        """
        self._check_authorization(auth_data)
        self._validate_scopes(create.scopes)
        max_lifetime = create.max_lifetime
        if max_lifetime is None:
            max_lifetime = min(
                GITHUB_PROJECT_DEFAULT_LIFETIME, self._config.max_lifetime
            )
        self._validate_max_lifetime(max_lifetime)
        repository = await self._github.get_repository(create.repository)
        actor = auth_data.username

        async with self._session.begin():
            await self._project_store.lock()
            username = await self._resolve_username(
                create.username, repository.full_name
            )
            candidate = create.model_copy(
                update={
                    "username": username,
                    "repository": repository.full_name,
                    "max_lifetime": max_lifetime,
                }
            )
            await self._check_overlap(candidate)
            project = await self._project_store.add(
                create,
                username=username,
                repository=repository,
                max_lifetime=max_lifetime,
                created_by=actor,
            )
            entry = GitHubProjectHistoryEntry(
                project_id=project.id,
                action=GitHubProjectChange.create,
                actor=actor,
                ip_address=ip_address,
                new_values=project.model_dump(mode="json"),
            )
            await self._history_store.add(entry)

        self._logger.info(
            "Created GitHub project",
            github_project_id=project.id,
            repository=project.repository,
            username=project.username,
        )
        return project

    async def delete_project(
        self, project_id: int, auth_data: TokenData, *, ip_address: str | None
    ) -> None:
        """Delete a GitHub project and revoke its outstanding tokens.

        Parameters
        ----------
        project_id
            ID of the project.
        auth_data
            The data for the authenticated user making the request.
        ip_address
            The IP address from which the request came, or `None` for
            internal requests by Gafaelfawr.

        Raises
        ------
        NotFoundError
            Raised if no project has that ID.
        PermissionDeniedError
            Raised if the authenticated user is not a token administrator.
        """
        self._check_authorization(auth_data)
        actor = auth_data.username
        async with self._session.begin():
            # Deleting takes the registry lock too, so that the row cannot
            # vanish between a concurrent writer's checks and its write.
            await self._project_store.lock()
            project = await self._project_store.get(project_id)
            if not project:
                raise NotFoundError(f"GitHub project {project_id} not found")
            await self._project_store.delete(project_id)
            entry = GitHubProjectHistoryEntry(
                project_id=project_id,
                template=project.template,
                action=GitHubProjectChange.delete,
                actor=actor,
                ip_address=ip_address,
                old_values=project.model_dump(mode="json"),
            )
            await self._history_store.add(entry)

            # Revoke the tokens last. Revocation deletes each token from
            # Redis immediately, which is not rolled back with the
            # transaction, so doing it after the database work means a
            # failure there leaves the tokens intact rather than dead in
            # Redis but still listed as live in the database.
            revoked = await self._token_service.revoke_github_project_tokens(
                project_id, auth_data, ip_address=ip_address
            )
        self._logger.info(
            "Deleted GitHub project",
            github_project_id=project_id,
            repository=project.repository,
            username=project.username,
            tokens_revoked=revoked,
        )

    async def get_project(
        self, project_id: int, auth_data: TokenData
    ) -> GitHubProject:
        """Retrieve a GitHub project.

        Parameters
        ----------
        project_id
            ID of the project.
        auth_data
            The data for the authenticated user making the request.

        Returns
        -------
        GitHubProject
            The project.

        Raises
        ------
        NotFoundError
            Raised if no project has that ID.
        PermissionDeniedError
            Raised if the authenticated user is not a token administrator.
        """
        self._check_authorization(auth_data)
        async with self._session.begin():
            project = await self._project_store.get(project_id)
        if not project:
            raise NotFoundError(f"GitHub project {project_id} not found")
        return project

    async def list_projects(
        self,
        auth_data: TokenData,
        *,
        repository: str | None = None,
        username: str | None = None,
        template: str | None = None,
        requested_by: str | None = None,
    ) -> list[GitHubProject]:
        """List GitHub projects.

        Parameters
        ----------
        auth_data
            The data for the authenticated user making the request.
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

        Raises
        ------
        PermissionDeniedError
            Raised if the authenticated user is not a token administrator.
        """
        self._check_authorization(auth_data)
        async with self._session.begin():
            return await self._project_store.list(
                repository=repository,
                username=username,
                template=template,
                requested_by=requested_by,
            )

    async def update_project(
        self,
        project_id: int,
        update: GitHubProjectUpdate,
        auth_data: TokenData,
        *,
        ip_address: str | None,
    ) -> GitHubProject:
        """Modify a GitHub project.

        Only the fields set in the update are changed. Changing the
        repository looks up its numeric IDs again, but keeps the username
        unless it is also changed, since identity should not move when a
        label does. Disabling the project revokes its outstanding tokens.
        Other changes do not affect tokens already minted. An update that
        changes nothing is not recorded in the project history and leaves
        the modification time and actor alone.

        Parameters
        ----------
        project_id
            ID of the project.
        update
            Changes to apply.
        auth_data
            The data for the authenticated user making the request.
        ip_address
            The IP address from which the request came, or `None` for
            internal requests by Gafaelfawr.

        Returns
        -------
        GitHubProject
            The modified project.

        Raises
        ------
        DuplicateGitHubUsernameError
            Raised if the derived username is already used by a project for
            a different repository.
        GitHubError
            Raised if GitHub returned invalid repository data.
        GitHubProjectOverlapError
            Raised if the project is enabled and its constraints overlap
            those of another enabled project for the same repository.
        GitHubWebError
            Raised if an HTTP error occurred talking to GitHub.
        InvalidGitHubUsernameError
            Raised if the derived username is not a valid username.
        InvalidMaxLifetimeError
            Raised if the maximum lifetime is out of range.
        InvalidScopesError
            Raised if the scopes are unknown or not permitted.
        NotFoundError
            Raised if no project has that ID.
        PermissionDeniedError
            Raised if the authenticated user is not a token administrator.
        UnknownGitHubRepositoryError
            Raised if the new repository does not exist or is not public.
        """
        self._check_authorization(auth_data)

        # Take the changed values from the model attributes rather than from
        # model_dump so that nested models such as groups stay as models,
        # since model_copy does not validate its updates.
        changes = {f: getattr(update, f) for f in update.model_fields_set}
        if update.scopes is not None:
            self._validate_scopes(update.scopes)
        if update.max_lifetime is not None:
            self._validate_max_lifetime(update.max_lifetime)
        actor = auth_data.username

        # Changing the repository means looking it up on GitHub, which is a
        # network call and therefore must not happen inside a transaction.
        # Only that case needs a preliminary read of the stored project, to
        # avoid looking up a repository the project already has. Every other
        # update goes straight to the single transaction below.
        stored = None
        if update.repository:
            stored = await self._read_project(project_id)
            if update.repository != stored.repository:
                repository = await self._github.get_repository(
                    update.repository
                )
                changes["repository"] = repository.full_name
                changes["repository_id"] = repository.id
                changes["repository_owner_id"] = repository.owner_id
            else:
                del changes["repository"]

        # An update that sets nothing, or only re-sends the repository the
        # project already has, changes nothing, so return the stored project
        # without taking the registry lock or recording a history entry.
        # Setting the username to null is not a no-op, since it is resolved
        # again below and may differ from the stored username.
        if not changes:
            stored = stored or await self._read_project(project_id)
            self._logger.info(
                "GitHub project unchanged",
                github_project_id=project_id,
                repository=stored.repository,
                username=stored.username,
            )
            return stored

        now = datetime.now(tz=UTC).replace(microsecond=0)
        async with self._session.begin():
            # Read the project inside the transaction that modifies it,
            # under the registry lock. When the repository was looked up
            # above, this also verifies that the project still exists and
            # picks up any changes made underneath us while we were talking
            # to GitHub.
            await self._project_store.lock()
            old = await self._project_store.get(project_id)
            if not old:
                raise NotFoundError(f"GitHub project {project_id} not found")
            if "username" in changes and changes["username"] is None:
                full_name = changes.get("repository", old.repository)
                changes["username"] = await self._resolve_username(
                    None, full_name, exclude_id=project_id
                )
            new = old.model_copy(
                update={**changes, "modified": now, "modified_by": actor}
            )

            # An update that only sets fields to their current values, or
            # whose null username resolves to the current one, also changes
            # nothing. Return the stored project rather than bump its
            # modification time and record a history entry whose old and
            # new values differ only in that time and actor.
            audit = {"modified", "modified_by"}
            if new.model_dump(exclude=audit) == old.model_dump(exclude=audit):
                self._logger.info(
                    "GitHub project unchanged",
                    github_project_id=project_id,
                    repository=old.repository,
                    username=old.username,
                    changes=sorted(changes.keys()),
                )
                return old

            await self._check_overlap(new, exclude_id=project_id)
            await self._project_store.update(new)
            entry = GitHubProjectHistoryEntry(
                project_id=project_id,
                template=new.template,
                action=GitHubProjectChange.modify,
                actor=actor,
                ip_address=ip_address,
                old_values=old.model_dump(mode="json"),
                new_values=new.model_dump(mode="json"),
            )
            await self._history_store.add(entry)

            # Revoke the tokens last, for the same reason as in
            # delete_project: the Redis deletes are immediate and survive a
            # rollback of the database work.
            revoked = 0
            if old.enabled and not new.enabled:
                revoked = (
                    await self._token_service.revoke_github_project_tokens(
                        project_id, auth_data, ip_address=ip_address
                    )
                )

        self._logger.info(
            "Modified GitHub project",
            github_project_id=project_id,
            repository=new.repository,
            username=new.username,
            changes=sorted(changes.keys()),
            tokens_revoked=revoked,
        )
        return new

    def _check_authorization(self, auth_data: TokenData) -> None:
        """Check authorization for manipulating GitHub projects.

        Parameters
        ----------
        auth_data
            Authenticated user performing the action.

        Raises
        ------
        PermissionDeniedError
            Raised if the authenticated user doesn't have permission to
            manipulate GitHub projects.
        """
        if "admin:token" not in auth_data.scopes:
            msg = "Missing required admin:token scope"
            self._logger.warning("Permission denied", error=msg)
            raise PermissionDeniedError(msg)

    async def _check_overlap(
        self,
        project: GitHubProjectCreate | GitHubProject,
        *,
        exclude_id: int | None = None,
    ) -> None:
        """Check that a project does not overlap an existing enabled project.

        Disabled projects never match a token, so they do not participate in
        the overlap check: a disabled project may overlap anything, and an
        existing disabled project does not block a new or changed project.
        Re-enabling a project is therefore refused if it would overlap an
        enabled project, since ``project`` is then the project as it would
        be after the change.

        Must be called from inside a transaction that holds the registry
        lock (see `GitHubProjectStore.lock`). The check reads the registry
        and the caller then writes to it, so without the lock two
        concurrent writers could both see no conflict and both commit. Even
        so, the token exchange should treat several projects matching one
        token as an error rather than rely on this check alone, since the
        invariant is enforced here and not by the database.

        Parameters
        ----------
        project
            Project to check, with its repository in the form GitHub reports
            it and its username resolved.
        exclude_id
            ID of the project itself, when modifying an existing project.

        Raises
        ------
        GitHubProjectOverlapError
            Raised if the project is enabled and its constraints overlap
            those of an existing enabled project for the same repository.
        """
        if not project.enabled:
            return
        existing = await self._project_store.list(
            repository=project.repository
        )
        for other in existing:
            if other.id == exclude_id or not other.enabled:
                continue
            if other.overlaps(project):
                msg = (
                    f"Constraints overlap GitHub project {other.id} for"
                    f" {other.repository}"
                )
                raise GitHubProjectOverlapError(msg, other.id)

    async def _read_project(self, project_id: int) -> GitHubProject:
        """Read a project in a transaction of its own.

        This is for reads outside of the transaction that writes to the
        registry, such as before a network call. The project may change
        between this read and that transaction, which must therefore read
        it again under the registry lock.

        Parameters
        ----------
        project_id
            ID of the project.

        Returns
        -------
        GitHubProject
            The stored project.

        Raises
        ------
        NotFoundError
            Raised if no project has that ID.
        """
        async with self._session.begin():
            project = await self._project_store.get(project_id)
        if not project:
            raise NotFoundError(f"GitHub project {project_id} not found")
        return project

    async def _resolve_username(
        self,
        username: str | None,
        repository: str,
        *,
        exclude_id: int | None = None,
    ) -> str:
        """Determine the bot username for a project.

        An explicit username is used as is. Otherwise, the username is
        derived from the repository as ``bot-gh-<owner>-<repo>``, lowercased,
        with any character that is not a letter or digit replaced with a
        hyphen and runs of hyphens collapsed. Because that derivation is
        ambiguous once hyphens are involved, a derived username that is
        already used by a project for a different repository is refused.

        Must be called from inside a transaction that holds the registry
        lock (see `GitHubProjectStore.lock`), for the same reason as
        `_check_overlap`: the check spans every repository and is only
        meaningful if no other writer can commit between it and the write.

        Parameters
        ----------
        username
            Explicit username, if any.
        repository
            Repository in the form GitHub reports it.
        exclude_id
            ID of the project itself, when modifying an existing project.

        Returns
        -------
        str
            The resolved username.

        Raises
        ------
        DuplicateGitHubUsernameError
            Raised if the derived username is already used by a project for
            a different repository.
        InvalidGitHubUsernameError
            Raised if the derived username is not a valid username.
        """
        if username:
            return username
        derived = re.sub("[^a-z0-9]+", "-", repository.lower())
        derived = GITHUB_BOT_USERNAME_PREFIX + derived.strip("-")
        if len(derived) > 64 or not re.match(
            GITHUB_BOT_USERNAME_REGEX, derived
        ):
            msg = (
                f"Username {derived} derived from {repository} is not a"
                " valid username, provide an explicit username"
            )
            raise InvalidGitHubUsernameError(msg)
        existing = await self._project_store.list(username=derived)
        for other in existing:
            if other.id == exclude_id:
                continue
            if other.repository.lower() != repository.lower():
                msg = (
                    f"Username {derived} derived from {repository} is"
                    f" already used by GitHub project {other.id} for"
                    f" {other.repository}, provide an explicit username"
                )
                raise DuplicateGitHubUsernameError(msg)
        return derived

    def _validate_max_lifetime(self, max_lifetime: timedelta) -> None:
        """Check that a maximum lifetime is within the allowed range.

        Parameters
        ----------
        max_lifetime
            Maximum lifetime to check.

        Raises
        ------
        InvalidMaxLifetimeError
            Raised if the maximum lifetime is out of range.
        """
        if max_lifetime < MINIMUM_LIFETIME:
            seconds = int(MINIMUM_LIFETIME.total_seconds())
            msg = f"max_lifetime must be at least {seconds}s"
            raise InvalidMaxLifetimeError(msg)
        if max_lifetime > self._config.max_lifetime:
            seconds = int(self._config.max_lifetime.total_seconds())
            msg = f"max_lifetime must be at most {seconds}s"
            raise InvalidMaxLifetimeError(msg)

    def _validate_scopes(self, scopes: set[str]) -> None:
        """Check that the scopes of a project are permitted.

        Every scope must be a known scope, and ``admin:`` scopes are
        reserved and may not be granted to a GitHub project.

        Parameters
        ----------
        scopes
            Scopes to check.

        Raises
        ------
        InvalidScopesError
            Raised if the scopes are unknown or not permitted.
        """
        unknown = scopes - self._known_scopes
        if unknown:
            msg = f"Unknown scopes: {', '.join(sorted(unknown))}"
            raise InvalidScopesError(msg)
        reserved = {s for s in scopes if s.startswith("admin:")}
        if reserved:
            msg = f"Reserved scopes not allowed: {', '.join(sorted(reserved))}"
            raise InvalidScopesError(msg)
