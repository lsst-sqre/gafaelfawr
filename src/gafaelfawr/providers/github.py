"""GitHub authentication provider."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from gafaelfawr.providers.base import Provider, ProviderException
from gafaelfawr.session import Session, SessionHandle

if TYPE_CHECKING:
    from aiohttp import ClientSession
    from gafaelfawr.config import GitHubConfig
    from gafaelfawr.issuer import TokenIssuer
    from gafaelfawr.session import SessionStore
    from structlog import BoundLogger
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
    http_session : `aiohttp.ClientSession`
        Session to use to make HTTP requests.
    issuer : `gafaelfawr.issuer.TokenIssuer`
        Issuer to use to generate new tokens.
    session_store : `gafaelfawr.session.SessionStore`
        Store for authentication sessions.
    logger : `structlog.BoundLogger`
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
        *,
        config: GitHubConfig,
        http_session: ClientSession,
        issuer: TokenIssuer,
        session_store: SessionStore,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._http_session = http_session
        self._issuer = issuer
        self._session_store = session_store
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

    async def create_session(self, code: str, state: str) -> Session:
        """Given the code from a successful authentication, create a session.

        Parameters
        ----------
        code : `str`
            Code returned by a successful authentication.
        state : `str`
            The same random string used for the redirect URL.

        Returns
        -------
        session : `gafaelfawr.session.Session`
            The new authentication session.

        Raises
        ------
        aiohttp.ClientResponseError
            An HTTP client error occurred trying to talk to the authentication
            provider.
        GitHubException
            GitHub responded with an error to a request.
        """
        self._logger.info("Getting user information from GitHub")
        github_token = await self._get_access_token(code, state)
        user_info = await self._get_user_info(github_token)

        handle = SessionHandle()

        groups = [{"name": t.group_name, "id": t.gid} for t in user_info.teams]
        claims = {
            "email": user_info.email,
            "isMemberOf": groups,
            "jti": handle.key,
            "name": user_info.name,
            "sub": user_info.username.lower(),
            self._config.username_claim: user_info.username.lower(),
            self._config.uid_claim: str(user_info.uid),
        }

        token = self._issuer.issue_token(claims)
        session = Session.create(handle, token)
        await self._session_store.store_session(session)
        return session

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
        self._logger.debug("Fetching access token from %s", self._TOKEN_URL)
        r = await self._http_session.post(
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
        self._logger.debug("Fetching user data from %s", self._USER_URL)
        r = await self._http_session.get(
            self._USER_URL,
            headers={"Authorization": f"token {token}"},
            raise_for_status=True,
        )
        user_data = await r.json()
        self._logger.debug("Fetching user data from %s", self._TEAMS_URL)
        r = await self._http_session.get(
            self._TEAMS_URL,
            headers={"Authorization": f"token {token}"},
            raise_for_status=True,
        )
        teams_data = await r.json()
        self._logger.debug("Fetching user data from %s", self._EMAILS_URL)
        r = await self._http_session.get(
            self._EMAILS_URL,
            headers={"Authorization": f"token {token}"},
            raise_for_status=True,
        )
        emails_data = await r.json()

        teams = []
        for team in teams_data:
            slug = team["slug"]
            organization = team["organization"]["login"]
            teams.append(
                GitHubTeam(
                    slug=slug, organization=organization, gid=team["id"],
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
