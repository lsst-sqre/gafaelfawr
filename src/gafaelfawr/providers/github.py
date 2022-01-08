"""GitHub authentication provider."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List
from urllib.parse import urlencode

from httpx import AsyncClient, HTTPError
from pydantic import ValidationError
from structlog.stdlib import BoundLogger

from gafaelfawr.config import GitHubConfig
from gafaelfawr.exceptions import GitHubException
from gafaelfawr.models.link import LinkData
from gafaelfawr.models.state import State
from gafaelfawr.models.token import TokenGroup, TokenUserInfo
from gafaelfawr.providers.base import Provider

__all__ = ["GitHubProvider"]


@dataclass(frozen=True)
class GitHubTeam:
    """An individual GitHub team."""

    slug: str
    """The slug of the team, taken from the slug attribute on GitHub."""

    organization: str
    """The organization (its login attribute) of which the team is a part."""

    gid: int
    """The GitHub ID of the team, hopefully usable as a GID."""

    @property
    def group_name(self) -> str:
        """The group name corresponding to this GitHub team.

        Returns
        -------
        group_name : `str`
            The name of the group.

        Notes
        -----
        The default construction is the organization name (from the login
        field), a dash, and the team slug.  If this is over 32 characters, it
        will be truncated to 25 characters and the first six characters of a
        hash of the full name will be appended for uniqueness.
        """
        group_name = f"{self.organization.lower()}-{self.slug}"
        if len(group_name) > 32:
            name_hash = hashlib.sha256(group_name.encode()).digest()
            suffix = base64.urlsafe_b64encode(name_hash).decode()[:6]
            group_name = group_name[:25] + "-" + suffix
        return group_name


@dataclass(frozen=True)
class GitHubUserInfo:
    """Metadata about a user gathered from the GitHub API."""

    name: str
    """Full name of the user."""

    username: str
    """The GitHub login of the user."""

    uid: int
    """The GitHub ID of the user, hopefully usable as a UID."""

    email: str
    """The primary email address of the user."""

    teams: List[GitHubTeam]
    """The teams of which the user is a member."""


class GitHubProvider(Provider):
    """Authenticate a user with GitHub.

    Parameters
    ----------
    config : `gafaelfawr.config.GitHubConfig`
        Configuration for the GitHub authentication provider.
    http_client : ``httpx.AsyncClient``
        Session to use to make HTTP requests.
    logger : ``structlog.stdlib.BoundLogger``
        Logger for any log messages.
    """

    _LOGIN_URL = "https://github.com/login/oauth/authorize"
    """URL to which to redirect the user for initial login."""

    _TOKEN_URL = "https://github.com/login/oauth/access_token"
    """URL from which to request an access token."""

    _GRANT_URL_TMPL = "https://api.github.com/applications/{client_id}/grant"
    """URL template for revoking an OAuth authorization."""

    _EMAILS_URL = "https://api.github.com/user/emails"
    """URL from which to retrieve the user's email addresses."""

    _TEAMS_URL = "https://api.github.com/user/teams"
    """URL from which to request the teams for a user."""

    _USER_URL = "https://api.github.com/user"
    """URL from which to request user metadata."""

    _SCOPES = ["read:org", "read:user", "user:email"]
    """Access scopes to request from GitHub."""

    def __init__(
        self,
        *,
        config: GitHubConfig,
        http_client: AsyncClient,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._http_client = http_client
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
        self._logger.info("Redirecting user to GitHub for authentication")
        return f"{self._LOGIN_URL}?{urlencode(params)}"

    async def create_user_info(
        self, code: str, state: str, session: State
    ) -> TokenUserInfo:
        """Given the code from an authentication, create the user information.

        The GitHub access token is stored in the ``github`` field of the
        ``state`` parameter so that it can be used during logout.

        Parameters
        ----------
        code : `str`
            Code returned by a successful authentication.
        state : `str`
            The same random string used for the redirect URL.
        session : `gafaelfawr.models.state.State`
            The session state, used to store the GitHub access token.

        Returns
        -------
        user_info : `gafaelfawr.models.token.TokenUserInfo`
            The user information corresponding to that authentication.

        Raises
        ------
        gafaelfawr.exceptions.GitHubException
            GitHub responded with an error to a request.
        ``httpx.HTTPError``
            An HTTP client error occurred trying to talk to the authentication
            provider.
        """
        github_token = await self._get_access_token(code, state)
        user_info = await self._get_user_info(github_token)
        self._logger.debug(
            "Got user information from GitHub",
            name=user_info.name,
            username=user_info.username,
            uid=user_info.uid,
            email=user_info.email,
            teams=[
                {"slug": t.slug, "organization": t.organization, "gid": t.gid}
                for t in user_info.teams
            ],
        )

        groups = []
        invalid_groups = {}
        for team in user_info.teams:
            try:
                groups.append(TokenGroup(name=team.group_name, id=team.gid))
            except ValidationError as e:
                invalid_groups[team.group_name] = str(e)
        if invalid_groups:
            self._logger.warning(
                "Ignoring invalid groups", invalid_groups=invalid_groups
            )
        session.github = github_token
        return TokenUserInfo(
            username=user_info.username.lower(),
            name=user_info.name,
            email=user_info.email,
            uid=user_info.uid,
            groups=groups,
        )

    async def logout(self, session: State) -> None:
        """Revoke the OAuth authorization grant for this user.

        During logout, revoke the user's OAuth authorization.  This ensures
        that, after an explicit logout, logging in again forces a
        reauthorization and thus an update of the granted information.

        Parameters
        ----------
        session : `gafaelfawr.models.state.State`
            The session state, which contains the GitHub access token.
        """
        if not session.github:
            return

        client_id = self._config.client_id
        client_secret = self._config.client_secret
        grant_url = GitHubProvider._GRANT_URL_TMPL.format(client_id=client_id)
        data = {"access_token": session.github}
        try:
            r = await self._http_client.request(
                "DELETE",
                grant_url,
                auth=(client_id, client_secret),
                headers={"Accept": "application/json"},
                json=data,
            )
            r.raise_for_status()
            self._logger.info("Revoked GitHub OAuth authorization")
        except HTTPError as e:
            msg = "Unable to revoke GitHub OAuth authorization"
            self._logger.warning(msg, error=str(e))

    async def _get_access_token(self, code: str, state: str) -> str:
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

        Raises
        ------
        gafaelfawr.exceptions.GitHubException
            GitHub responded with an error to the request for the access
            token.
        ``httpx.HTTPError``
            An error occurred trying to talk to GitHub.
        """
        data = {
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "code": code,
            "state": state,
        }
        self._logger.debug("Fetching access token from %s", self._TOKEN_URL)
        r = await self._http_client.post(
            self._TOKEN_URL,
            data=data,
            headers={"Accept": "application/json"},
        )
        r.raise_for_status()
        result = r.json()
        if "error" in result:
            msg = result["error"] + ": " + result["error_description"]
            raise GitHubException(msg)
        return result["access_token"]

    async def _get_user_info(self, token: str) -> GitHubUserInfo:
        """Retrieve metadata about a user from GitHub.

        Parameters
        ----------
        token : `str`
            The token for that user.

        Returns
        -------
        info : `GitHubUserInfo`
            Information about that user.

        Raises
        ------
        gafaelfawr.exceptions.GitHubException
            User has no primary email address.
        ``httpx.HTTPError``
            An error occurred trying to talk to GitHub.
        """
        self._logger.debug("Fetching user data from %s", self._USER_URL)
        r = await self._http_client.get(
            self._USER_URL,
            headers={"Authorization": f"token {token}"},
        )
        r.raise_for_status()
        user_data = r.json()
        self._logger.debug("Fetching user data from %s", self._EMAILS_URL)
        r = await self._http_client.get(
            self._EMAILS_URL,
            headers={"Authorization": f"token {token}"},
        )
        r.raise_for_status()
        emails_data = r.json()
        teams_data = await self._get_user_teams_data(token)

        teams = [
            GitHubTeam(
                slug=team["slug"],
                organization=team["organization"]["login"],
                gid=team["id"],
            )
            for team in teams_data
        ]

        email = None
        for email_data in emails_data:
            if email_data.get("primary"):
                email = email_data["email"]
        if not email:
            msg = f"{user_data['login']} has no primary email address"
            raise GitHubException(msg)

        return GitHubUserInfo(
            name=user_data["name"],
            username=user_data["login"],
            uid=user_data["id"],
            email=email,
            teams=teams,
        )

    async def _get_user_teams_data(self, token: str) -> List[Dict[str, Any]]:
        """Retrieve team membership for a user from GitHub.

        Parameters
        ----------
        token : `str`
            The token for that user.

        Returns
        -------
        team_data : List[Dict[`str`, Any]]
            Team information for that user from GitHub in GitHub's JSON
            format.

        Raises
        ------
        gafaelfawr.exceptions.GitHubException
            The next URL from a Link header didn't point to the teams API URL.
        ``httpx.HTTPError``
            An error occurred trying to talk to GitHub.
        """
        self._logger.debug("Fetching user team data from %s", self._TEAMS_URL)
        r = await self._http_client.get(
            self._TEAMS_URL,
            headers={"Authorization": f"token {token}"},
        )
        r.raise_for_status()
        teams_data = r.json()

        # If the data was paginated, there will be a Link header with a next
        # URL.  Retrieve each page until we run out of Link headers.
        link_data = LinkData.from_header(r.headers.get("Link"))
        while link_data.next_url:
            if not link_data.next_url.startswith(self._TEAMS_URL):
                msg = (
                    "Invalid next URL for team data from GitHub: "
                    + link_data.next_url
                )
                raise GitHubException(msg)
            self._logger.debug(
                "Fetching user team data from %s", link_data.next_url
            )
            r = await self._http_client.get(
                link_data.next_url,
                headers={"Authorization": f"token {token}"},
            )
            r.raise_for_status()
            teams_data.extend(r.json())
            link_data = LinkData.from_header(r.headers.get("Link"))

        return teams_data
