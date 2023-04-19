"""GitHub authentication provider."""

from __future__ import annotations

import re
from urllib.parse import urlencode

from httpx import AsyncClient, HTTPError
from pydantic import ValidationError
from structlog.stdlib import BoundLogger

from ..config import GitHubConfig
from ..constants import USERNAME_REGEX
from ..exceptions import GitHubError, GitHubWebError, PermissionDeniedError
from ..models.github import GitHubTeam, GitHubUserInfo
from ..models.link import LinkData
from ..models.state import State
from ..models.token import TokenGroup, TokenUserInfo
from .base import Provider

__all__ = ["GitHubProvider"]


class GitHubProvider(Provider):
    """Authenticate a user with GitHub.

    Parameters
    ----------
    config
        Configuration for the GitHub authentication provider.
    http_client
        Session to use to make HTTP requests.
    logger
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
        state
            A random string used for CSRF protection.

        Returns
        -------
        str
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
        code
            Code returned by a successful authentication.
        state
            The same random string used for the redirect URL.
        session
            The session state, used to store the GitHub access token.

        Returns
        -------
        TokenUserInfo
            The user information corresponding to that authentication.

        Raises
        ------
        GitHubError
            Raised if GitHub responded with an error to a request.
        GitHubWebError
            Raised if an HTTP client error occurred trying to talk to GitHub.
        PermissionDeniedError
            Raised if the GitHub username is not a valid username for
            Gafaelfawr.
        """
        try:
            github_token = await self._get_access_token(code, state)
            user_info = await self._get_user_info(github_token)
        except HTTPError as e:
            raise GitHubWebError.from_exception(e) from e
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
        username = user_info.username.lower()

        # Map GitHub teams to groups.
        groups = []
        invalid_groups = {}
        for team in user_info.teams:
            try:
                groups.append(TokenGroup(name=team.group_name, id=team.gid))
            except ValidationError as e:
                invalid_groups[team.group_name] = str(e)
        if invalid_groups:
            self._logger.warning(
                "Ignoring invalid groups",
                invalid_groups=invalid_groups,
                user=username,
            )

        # Always synthesize a user private group with the same name as the
        # username and a GID matching the UID.  This is not truly a valid
        # approach because GitHub team IDs may clash with GitHub user IDs, but
        # the space of both is large enough that we take the risk.
        if not re.match(USERNAME_REGEX, username):
            raise PermissionDeniedError(f"Invalid username: {username}")
        groups.append(TokenGroup(name=username, id=user_info.uid))

        # Save the token in the session so that we can revoke it later.
        session.github = github_token

        # Return the calculated user information.  For GitHub logins, we store
        # all user information with the token rather than looking it up
        # dynamically.
        return TokenUserInfo(
            username=user_info.username.lower(),
            name=user_info.name,
            email=user_info.email,
            uid=user_info.uid,
            gid=user_info.uid,
            groups=sorted(groups, key=lambda g: g.name),
        )

    async def logout(self, session: State) -> None:
        """Revoke the OAuth authorization grant for this user.

        During logout, revoke the user's OAuth authorization.  This ensures
        that, after an explicit logout, logging in again forces a
        reauthorization and thus an update of the granted information.

        Parameters
        ----------
        session
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
                headers={"Accept": "application/vnd.github+json"},
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
        code
            Code returned by a successful authentication.
        state
            The same random string used for the redirect URL.

        Returns
        -------
        str
            Access token used for subsequent API calls.

        Raises
        ------
        GitHubError
            Raised if GitHub responded with an error to the request for the
            access token.
        httpx.HTTPError
            Raised if an error occurred trying to talk to GitHub.
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
            headers={"Accept": "application/vnd.github+json"},
        )
        r.raise_for_status()
        result = r.json()
        if "error" in result:
            msg = result["error"] + ": " + result["error_description"]
            raise GitHubError(msg)
        return result["access_token"]

    async def _get_user_info(self, token: str) -> GitHubUserInfo:
        """Retrieve metadata about a user from GitHub.

        Parameters
        ----------
        token
            The token for that user.

        Returns
        -------
        info
            Information about that user.

        Raises
        ------
        GitHubError
            Raised if the user's GitHub data is invalid.
        GitHubWebError
            Raised if an error occurred trying to talk to GitHub.
        """
        self._logger.debug("Fetching user data from %s", self._USER_URL)
        username = None
        r = await self._http_client.get(
            self._USER_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"token {token}",
            },
        )
        r.raise_for_status()
        try:
            user_data = r.json()
            username = user_data["login"].lower()
            logger = self._logger.bind(user=username)
            return GitHubUserInfo(
                name=user_data["name"],
                username=user_data["login"],
                uid=user_data["id"],
                email=await self._get_user_email(token, username, logger),
                teams=await self._get_user_teams(token, username, logger),
            )
        except HTTPError as e:
            raise GitHubWebError.from_exception(e, username) from e
        except Exception as e:
            msg = f"GitHub user data is invalid: {type(e).__name__}: {str(e)}"
            raise GitHubError(msg, username)

    async def _get_user_email(
        self, token: str, username: str, logger: BoundLogger
    ) -> str:
        """Retrieve the primary email address for a user from GitHub.

        Parameters
        ----------
        token
            Token for that user.
        username
            Username of user, for error reporting.
        logger
            Logger for debug and error messages.

        Returns
        -------
        str
            User's primary email address.

        Raises
        ------
        GitHubError
            Raised if the user does not have a primary email address.
        httpx.HTTPError
            Raised if an error occurred trying to talk to GitHub.
        """
        logger.debug("Fetching email data from %s", self._EMAILS_URL)
        r = await self._http_client.get(
            self._EMAILS_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"token {token}",
            },
        )
        r.raise_for_status()
        emails_data = r.json()

        # Find the primary email address and return it.
        for email_data in emails_data:
            if email_data.get("primary"):
                return email_data["email"]

        # If we fell through, there is no primary email address.
        msg = f"{username} has no primary email address"
        raise GitHubError(msg, username)

    async def _get_user_teams(
        self, token: str, username: str, logger: BoundLogger
    ) -> list[GitHubTeam]:
        """Retrieve team membership for a user from GitHub.

        Parameters
        ----------
        token
            Token for that user.
        username
            Username of user, for error reporting.
        logger
            Logger for debug and error messages.

        Returns
        -------
        list of GitHubTeam
            Team information for that user from GitHub.

        Raises
        ------
        GitHubError
            Raised if the next URL from a Link header didn't point to the
            teams API URL.
        httpx.HTTPError
            Raised if an error occurred trying to talk to GitHub.
        """
        logger.debug("Fetching user team data from %s", self._TEAMS_URL)
        r = await self._http_client.get(
            self._TEAMS_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"token {token}",
            },
        )
        r.raise_for_status()
        teams_data = r.json()

        # If the data was paginated, there will be a Link header with a next
        # URL.  Retrieve each page until we run out of Link headers.
        link_data = LinkData.from_header(r.headers.get("Link"))
        while link_data.next_url:
            next_url = link_data.next_url
            if not next_url.startswith(self._TEAMS_URL):
                msg = f"Invalid next URL for team data from GitHub: {next_url}"
                raise GitHubError(msg, username)
            self._logger.debug("Fetching user team data from %s", next_url)
            r = await self._http_client.get(
                next_url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"token {token}",
                },
            )
            r.raise_for_status()
            teams_data.extend(r.json())
            link_data = LinkData.from_header(r.headers.get("Link"))

        return [
            GitHubTeam(
                slug=team["slug"],
                organization=team["organization"]["login"],
                gid=team["id"],
            )
            for team in teams_data
        ]
