"""GitHub authentication provider."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from jwt_authorizer.providers.base import Provider, ProviderException

if TYPE_CHECKING:
    from aiohttp import ClientSession
    from jwt_authorizer.config import GitHubConfig
    from jwt_authorizer.issuer import TokenIssuer
    from jwt_authorizer.session import Ticket
    from jwt_authorizer.tokens import VerifiedToken
    from logging import Logger
    from typing import List

__all__ = ["GitHubException", "GitHubProvider"]


class GitHubException(ProviderException):
    """GitHub returned an error from an API call."""


@dataclass(frozen=True)
class GitHubTeam:
    """An individual GitHub team."""

    slug: str
    """The slug of the team, taken from the slug attribute on GitHub."""

    organization: str
    """The organization (its login attribute) of which the team is a part."""

    group_name: str
    """A group name constructed from the slug and organization.

    The default construction is the organization name (from the login field),
    a dash, and the team slug.  If this is over 32 characters, it will be
    truncated to 25 characters and the first six characters of a hash of the
    full name will be appended for uniqueness.
    """

    gid: int
    """The GitHub ID of the team, hopefully usable as a GID."""


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
    config : `jwt_authorizer.config.GitHubConfig`
        Configuration for the GitHub authentication provider.
    session : `aiohttp.ClientSession`
        Session to use to make HTTP requests.
    issuer : `jwt_authorizer.issuer.TokenIssuer`
        Issuer to use to generate new tokens.
    logger : `logging.Logger`
        Logger for any log messages.
    """

    _LOGIN_URL = "https://github.com/login/oauth/authorize"
    """URL to which to redirect the user for initial login."""

    _TOKEN_URL = "https://github.com/login/oauth/access_token"
    """URL from which to request an access token."""

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
        config: GitHubConfig,
        session: ClientSession,
        issuer: TokenIssuer,
        logger: Logger,
    ) -> None:
        self._config = config
        super().__init__(session, issuer, logger)

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
        self.logger.info("Redirecting user to GitHub for authentication")
        return f"{self._LOGIN_URL}?{urlencode(params)}"

    async def get_token(
        self, code: str, state: str, ticket: Ticket
    ) -> VerifiedToken:
        """Given the code from a successful authentication, get a token.

        Parameters
        ----------
        code : `str`
            Code returned by a successful authentication.
        state : `str`
            The same random string used for the redirect URL.
        ticket : `jwt_authorizer.session.Ticket`
            The ticket to use for the new token.

        Returns
        -------
        token : `jwt_authorizer.tokens.VerifiedToken`
            Authentication token issued by the local issuer and including the
            user information from the authentication provider.

        Raises
        ------
        aiohttp.ClientResponseError
            An HTTP client error occurred trying to talk to the authentication
            provider.
        GitHubException
            GitHub responded with an error to a request.
        """
        self.logger.info("Getting user information from GitHub")
        github_token = await self._get_access_token(code, state)
        user_info = await self._get_user_info(github_token)

        groups = [{"name": t.group_name, "id": t.gid} for t in user_info.teams]
        payload = {
            "email": user_info.email,
            "isMemberOf": groups,
            "name": user_info.name,
            "sub": user_info.username,
            "uidNumber": str(user_info.uid),
            "uid": user_info.username,
        }

        return await self.issuer.issue_token(payload, ticket)

    @staticmethod
    def _build_group_name(team_slug: str, organization: str) -> str:
        """Construct a group name from the team slug and organization name.

        Parameters
        ----------
        team_slug : `str`
            The slug attribute of the GitHub team.
        organization : `str`
            The name of the organization that owns the team.

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
        group_name = f"{organization}-{team_slug}"
        if len(group_name) > 32:
            name_hash = hashlib.sha256(group_name.encode()).digest()
            suffix = base64.urlsafe_b64encode(name_hash).decode()[:6]
            group_name = group_name[:25] + "-" + suffix
        return group_name

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
        aiohttp.ClientResponseError
            An error occurred trying to talk to GitHub.
        GitHubException
            GitHub responded with an error to the request for the access
            token.
        """
        data = {
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "code": code,
            "state": state,
        }
        self.logger.debug("Fetching access token from %s", self._TOKEN_URL)
        r = await self.http_post(
            self._TOKEN_URL,
            data=data,
            headers={"Accept": "application/json"},
            raise_for_status=True,
        )
        result = await r.json()
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
        aiohttp.ClientResponseError
            An error occurred trying to talk to GitHub.
        GitHubException
            User has no primary email address.
        """
        self.logger.debug("Fetching user data from %s", self._USER_URL)
        r = await self.http_get(
            self._USER_URL,
            headers={"Authorization": f"token {token}"},
            raise_for_status=True,
        )
        user_data = await r.json()
        self.logger.debug("Fetching user data from %s", self._TEAMS_URL)
        r = await self.http_get(
            self._TEAMS_URL,
            headers={"Authorization": f"token {token}"},
            raise_for_status=True,
        )
        teams_data = await r.json()
        self.logger.debug("Fetching user data from %s", self._EMAILS_URL)
        r = await self.http_get(
            self._EMAILS_URL,
            headers={"Authorization": f"token {token}"},
            raise_for_status=True,
        )
        emails_data = await r.json()

        teams = []
        for team in teams_data:
            slug = team["slug"]
            organization = team["organization"]["login"]
            group_name = self._build_group_name(slug, organization)
            teams.append(
                GitHubTeam(
                    slug=slug,
                    organization=organization,
                    group_name=group_name,
                    gid=team["id"],
                )
            )

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
