"""Lookups of public repository metadata from the GitHub API."""

from httpx import AsyncClient, HTTPError, HTTPStatusError
from structlog.stdlib import BoundLogger

from ..constants import GITHUB_API_URL
from ..exceptions import (
    GitHubError,
    GitHubWebError,
    UnknownGitHubRepositoryError,
)
from ..models.github import GitHubRepository

__all__ = ["GitHubStorage"]


class GitHubStorage:
    """Retrieve metadata about public repositories from the GitHub API.

    Used by the GitHub project registry to pin the numeric IDs of a
    repository and its owner when a project is created. Requests are made
    without credentials, so only public repositories can be looked up.

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
            r = await self._http_client.get(
                url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            r.raise_for_status()
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
