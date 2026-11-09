"""Lookups of public repository and owner metadata from the GitHub API."""

from httpx import AsyncClient, HTTPError, HTTPStatusError, Response
from structlog.stdlib import BoundLogger

from ..constants import GITHUB_API_URL
from ..exceptions import (
    GitHubError,
    GitHubWebError,
    UnknownGitHubOwnerError,
    UnknownGitHubRepositoryError,
)
from ..models.github import GitHubRepository
from ..models.github_project import GitHubOwner

__all__ = ["GitHubStorage"]


class GitHubStorage:
    """Retrieve metadata about public repositories and owners from GitHub.

    Used by the GitHub project registry to pin the numeric IDs of a
    repository and its owner when a project is created, and of the owners
    allowed by a project template. Requests are made without credentials,
    so only public repositories can be looked up.

    Parameters
    ----------
    http_client
        HTTP client to use to make requests.
    logger
        Logger for diagnostics.
    """

    def __init__(
        self, *, http_client: AsyncClient, logger: BoundLogger
    ) -> None:
        self._http_client = http_client
        self._logger = logger

    async def get_owner(self, owner: str) -> GitHubOwner:
        """Retrieve metadata about an owner (organization or user).

        Parameters
        ----------
        owner
            Login of the owner.

        Returns
        -------
        GitHubOwner
            Name of the owner as GitHub reports it and its numeric ID.

        Raises
        ------
        GitHubError
            Raised if GitHub returned data that could not be parsed.
        GitHubWebError
            Raised if an HTTP client error occurred trying to talk to GitHub.
        UnknownGitHubOwnerError
            Raised if no organization or user has that login.
        """
        url = f"{GITHUB_API_URL}/users/{owner}"
        self._logger.debug("Fetching owner data from %s", url)
        try:
            r = await self._get(url)
        except HTTPStatusError as e:
            if e.response.status_code == 404:
                msg = f"GitHub owner {owner} not found"
                raise UnknownGitHubOwnerError(msg) from e
            raise GitHubWebError.from_exception(e) from e
        except HTTPError as e:
            raise GitHubWebError.from_exception(e) from e
        try:
            data = r.json()
            return GitHubOwner(name=data["login"], id=int(data["id"]))
        except Exception as e:
            msg = f"GitHub owner data is invalid: {type(e).__name__}: {e}"
            raise GitHubError(msg) from e

    async def get_repository(self, repository: str) -> GitHubRepository:
        """Retrieve metadata about a public repository.

        Parameters
        ----------
        repository
            Repository as ``owner/name``.

        Returns
        -------
        GitHubRepository
            Metadata about the repository, including its numeric IDs.

        Raises
        ------
        GitHubError
            Raised if GitHub returned data that could not be parsed.
        GitHubWebError
            Raised if an HTTP client error occurred trying to talk to GitHub.
        UnknownGitHubRepositoryError
            Raised if the repository does not exist or is not public.
        """
        url = f"{GITHUB_API_URL}/repos/{repository}"
        self._logger.debug("Fetching repository data from %s", url)
        try:
            r = await self._get(url)
        except HTTPStatusError as e:
            if e.response.status_code == 404:
                msg = f"Repository {repository} not found or not public"
                raise UnknownGitHubRepositoryError(msg) from e
            raise GitHubWebError.from_exception(e) from e
        except HTTPError as e:
            raise GitHubWebError.from_exception(e) from e
        try:
            data = r.json()
            return GitHubRepository(
                full_name=data["full_name"],
                id=int(data["id"]),
                owner_id=int(data["owner"]["id"]),
            )
        except Exception as e:
            msg = f"GitHub repository data is invalid: {type(e).__name__}: {e}"
            raise GitHubError(msg) from e

    async def _get(self, url: str) -> Response:
        """Make an unauthenticated GET request to the GitHub API.

        Parameters
        ----------
        url
            URL to request.

        Returns
        -------
        httpx.Response
            Successful response.

        Raises
        ------
        httpx.HTTPError
            Raised if the request failed or returned an error status.
        """
        r = await self._http_client.get(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        r.raise_for_status()
        return r
