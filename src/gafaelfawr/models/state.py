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
from gafaelfawr.session import SessionHandle

if TYPE_CHECKING:
    from typing import Optional

    from fastapi import Request

__all__ = ["State"]


@dataclass
class State(BaseState):
    """State information stored in a cookie."""

    csrf: Optional[str] = None
    """CSRF token for form submissions."""

    handle: Optional[SessionHandle] = None
    """Handle for the session if the user is authenticated."""

    message: Optional[str] = None
    """Status message to display on the next rendered HTML page."""

    return_url: Optional[str] = None
    """Destination URL after completion of login."""

    state: Optional[str] = None
    """State token for OAuth 2.0 and OpenID Connect logins."""

    @classmethod
    def from_cookie(cls, cookie: str, request: Request) -> State:
        """Reconstruct state from an encrypted cookie.

        Parameters
        ----------
        cookie : `str`
            The encrypted cookie value.
        key : `bytes`
            The `~cryptography.fernet.Fernet` key used to decrypt it.
        request : `fastapi.Request`
            The request, used for logging.

        Returns
        -------
        state : `State`
            The state represented by the cookie.
        """
        key = config_dependency().session_secret.encode()
        fernet = Fernet(key)
        try:
            data = json.loads(fernet.decrypt(cookie.encode()).decode())
            handle = None
            if "handle" in data:
                handle = SessionHandle.from_str(data["handle"])
        except Exception as e:
            logger = get_logger(request)
            logger.warning("Discarding invalid state cookie", error=str(e))
            return cls()

        return cls(
            csrf=data.get("csrf"),
            handle=handle,
            message=data.get("message"),
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
        if self.handle:
            data["handle"] = self.handle.encode()
        if self.message:
            data["message"] = self.message
        if self.return_url:
            data["return_url"] = self.return_url
        if self.state:
            data["state"] = self.state

        key = config_dependency().session_secret.encode()
        fernet = Fernet(key)
        return fernet.encrypt(json.dumps(data).encode()).decode()
