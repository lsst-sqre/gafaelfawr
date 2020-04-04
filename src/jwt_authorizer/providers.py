"""Authentication providers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlencode

if TYPE_CHECKING:
    from aiohttp import ClientResponse, ClientSession
    from jwt_authorizer.config import GitHubConfig
    from logging import Logger
    from typing import Dict, List


@dataclass(frozen=True)
class GitHubTeam:
    """An individual GitHub team."""

    name: str
    """The name of the team."""

    organization: str
    """The organization of which the team is a part."""


@dataclass(frozen=True)
class GitHubUserInfo:
    """Metadata about a user gathered from the GitHub API."""

    username: str
    """The GitHub login of the user."""

    uid: int
    """The GitHub ID of the user, hopefully usable as a UID."""

    email: str
    """The primary email address of the user."""

    teams: List[GitHubTeam]
    """The teams of which the user is a member."""


class GitHubProvider:
    """Authenticate a user with GitHub.

    Parameters
    ----------
    config : `jwt_authorizer.config.GitHubConfig`
        Configuration for the GitHub authentication provider.
    session : `aiohttp.ClientSession`
        Session to use to make HTTP requests.
    """

    _LOGIN_URL = "https://github.com/login/oauth/authorize"
    """URL to which to redirect the user for initial login."""

    _TOKEN_URL = "https://github.com/login/oauth/access_token"
    """URL from which to request an access token."""

    _TEAMS_URL = "https://api.github.com/user/teams"
    """URL from which to request the teams for a user."""

    _USER_URL = "https://api.github.com/user"
    """URL from which to request user metadata."""

    _SCOPES = ["read:org", "read:user", "user:email"]
    """Access scopes to request from GitHub."""

    def __init__(
        self, config: GitHubConfig, session: ClientSession, logger: Logger
    ) -> None:
        self._config = config
        self._session = session
        self._logger = logger

    def get_redirect_url(self, state: str) -> str:
        """Get the login URL to which to redirect the user.

        Parameters
        ----------
        state : `str`
            A random string used for CSRF protection.

        Returns
        -------
        url : `str`
            The encoded URL to which to redirect the user.
        """
        params = {
            "client_id": self._config.client_id,
            "scope": " ".join(self._SCOPES),
            "state": state,
        }
        return f"{self._LOGIN_URL}?{urlencode(params)}"

    async def get_access_token(self, code: str, state: str) -> str:
        """Given the code from a successful authentication, get a token.

        Parameters
        ----------
        code : `str`
            Code returned by a successful authentication.
        state : `str`
            The same random string used for the redirect URL.

        Returns
        -------
        token : `str`
            Access token used for subsequent API calls.
        """
        data = {
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "code": code,
            "state": state,
        }
        r = await self.http_post(
            self._TOKEN_URL,
            data=data,
            headers={"Accept": "application/json"},
            raise_for_status=True,
        )
        result = await r.json()
        return result["access_token"]

    async def get_user_info(self, token: str) -> GitHubUserInfo:
        """Retrieve metadata about a user from GitHub.

        Parameters
        ----------
        token : `str`
            The token for that user.

        Returns
        -------
        info : `GitHubUserInfo`
            Information about that user.
        """
        r = await self.http_get(
            self._USER_URL,
            headers={"Authorization": f"token {token}"},
            raise_for_status=True,
        )
        user_data = await r.json()
        r = await self.http_get(
            self._TEAMS_URL,
            headers={"Authorization": f"token {token}"},
            raise_for_status=True,
        )
        teams_data = await r.json()
        teams = [
            GitHubTeam(name=t["name"], organization=t["organization"]["login"])
            for t in teams_data
        ]
        return GitHubUserInfo(
            username=user_data["login"],
            uid=user_data["id"],
            email=user_data["email"],
            teams=teams,
        )

    async def http_get(
        self, url: str, *, headers: Dict[str, str], raise_for_status: bool
    ) -> ClientResponse:
        """Retrieve a URL.

        Intended for overriding by a test class to avoid actual HTTP requests.

        Parameters
        ----------
        url : `str`
            URL to retrieve.

        Returns
        -------
        response : `aiohttp.ClientResponse`
            The response.
        """
        return await self._session.get(
            url, headers=headers, raise_for_status=raise_for_status
        )

    async def http_post(
        self,
        url: str,
        *,
        data: Dict[str, str],
        headers: Dict[str, str],
        raise_for_status: bool,
    ) -> ClientResponse:
        """POST to a URL.

        Intended for overriding by a test class to avoid actual HTTP requests.

        Parameters
        ----------
        url : `str`
            URL to POST to.
        **args : Any
            Additional `aiohttp.ClientSession` parameters.

        Returns
        -------
        response : `aiohttp.ClientResponse`
            The response.
        """
        return await self._session.post(
            url, data=data, headers=headers, raise_for_status=raise_for_status
        )
