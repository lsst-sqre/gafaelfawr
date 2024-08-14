"""Representation of Gafaelfawr state stored in a cookie.

This is the Gafaelfawr version of `~gafaelfawr.middleware.state.BaseState`,
used by the `~gafaelfawr.middleware.state.StateMiddleware` middleware.  It
holds the data that Gafaelfawr stores in a session cookie.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Self

from cryptography.fernet import Fernet
from fastapi import Request
from safir.dependencies.logger import logger_dependency

from ..dependencies.config import config_dependency
from ..middleware.state import BaseState
from .token import Token

__all__ = ["State"]


@dataclass
class State(BaseState):
    """State information stored in a cookie."""

    csrf: str | None = None
    """CSRF token for form submissions."""

    token: Token | None = None
    """Token if the user is authenticated."""

    github: str | None = None
    """GitHub OAuth token if user authenticated via GitHub."""

    return_url: str | None = None
    """Destination URL after completion of login."""

    state: str | None = None
    """State token for OAuth 2.0 and OpenID Connect logins."""

    login_start: datetime | None = None
    """Start time of login process if one is in progress."""

    @classmethod
    async def from_cookie(
        cls, cookie: str, request: Request | None = None
    ) -> Self:
        """Reconstruct state from an encrypted cookie.

        Parameters
        ----------
        cookie
            The encrypted cookie value.
        key
            The `~cryptography.fernet.Fernet` key used to decrypt it.
        request
            The request, used for logging.  If not provided (primarily for the
            test suite), invalid state cookies will not be logged.

        Returns
        -------
        State
            The state represented by the cookie.
        """
        config = await config_dependency()
        fernet = Fernet(config.session_secret.get_secret_value().encode())
        try:
            data = json.loads(fernet.decrypt(cookie.encode()).decode())
            token = None
            if "token" in data:
                token = Token.from_str(data["token"])
            login_start = None
            if "login_start" in data:
                timestamp = data["login_start"]
                login_start = datetime.fromtimestamp(timestamp, tz=UTC)
        except Exception as e:
            if request:
                logger = await logger_dependency(request)
                error = type(e).__name__
                if str(e):
                    error += f": {e!s}"
                logger.warning("Discarding invalid state cookie", error=error)
            return cls()

        return cls(
            csrf=data.get("csrf"),
            token=token,
            github=data.get("github"),
            return_url=data.get("return_url"),
            state=data.get("state"),
            login_start=login_start,
        )

    def to_cookie(self) -> str:
        """Build an encrypted cookie representation of the state.

        Returns
        -------
        str
            The encrypted cookie value.
        """
        data: dict[str, str | float] = {}
        if self.csrf:
            data["csrf"] = self.csrf
        if self.token:
            data["token"] = str(self.token)
        if self.github:
            data["github"] = self.github
        if self.return_url:
            data["return_url"] = self.return_url
        if self.state:
            data["state"] = self.state
        if self.login_start:
            data["login_start"] = self.login_start.timestamp()

        config = config_dependency.config()
        fernet = Fernet(config.session_secret.get_secret_value().encode())
        return fernet.encrypt(json.dumps(data).encode()).decode()
