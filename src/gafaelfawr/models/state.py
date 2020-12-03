"""Representation of Gafaelfawr state stored in a cookie.

This is the Gafaelfawr version of `~gafaelfawr.middleware.state.BaseState`,
used by the `~gafaelfawr.middleware.state.StateMiddleware` middleware.  It
holds the data that Gafaelfawr stores in a session cookie.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet

from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.logger import get_logger
from gafaelfawr.middleware.state import BaseState
from gafaelfawr.models.token import Token

if TYPE_CHECKING:
    from typing import Optional

    from fastapi import Request

__all__ = ["State"]


@dataclass
class State(BaseState):
    """State information stored in a cookie."""

    csrf: Optional[str] = None
    """CSRF token for form submissions."""

    token: Optional[Token] = None
    """Token if the user is authenticated."""

    return_url: Optional[str] = None
    """Destination URL after completion of login."""

    state: Optional[str] = None
    """State token for OAuth 2.0 and OpenID Connect logins."""

    @classmethod
    def from_cookie(cls, cookie: str, request: Optional[Request]) -> State:
        """Reconstruct state from an encrypted cookie.

        Parameters
        ----------
        cookie : `str`
            The encrypted cookie value.
        key : `bytes`
            The `~cryptography.fernet.Fernet` key used to decrypt it.
        request : `fastapi.Request` or `None`
            The request, used for logging.  If not provided (primarily for the
            test suite), invalid state cookies will not be logged.

        Returns
        -------
        state : `State`
            The state represented by the cookie.
        """
        key = config_dependency().session_secret.encode()
        fernet = Fernet(key)
        try:
            data = json.loads(fernet.decrypt(cookie.encode()).decode())
            token = None
            if "token" in data:
                token = Token.from_str(data["token"])
        except Exception as e:
            if request:
                logger = get_logger(request)
                logger.warning("Discarding invalid state cookie", error=str(e))
            return cls()

        return cls(
            csrf=data.get("csrf"),
            token=token,
            return_url=data.get("return_url"),
            state=data.get("state"),
        )

    def as_cookie(self) -> str:
        """Build an encrypted cookie representation of the state.

        Returns
        -------
        cookie : `str`
            The encrypted cookie value.
        """
        data = {}
        if self.csrf:
            data["csrf"] = self.csrf
        if self.token:
            data["token"] = str(self.token)
        if self.return_url:
            data["return_url"] = self.return_url
        if self.state:
            data["state"] = self.state

        key = config_dependency().session_secret.encode()
        fernet = Fernet(key)
        return fernet.encrypt(json.dumps(data).encode()).decode()
