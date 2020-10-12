"""State cookie management."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from gafaelfawr.fastapi.dependencies import config, logger
from gafaelfawr.session import SessionHandle

if TYPE_CHECKING:
    from typing import Awaitable, Callable, Optional

    from structlog import BoundLogger

__all__ = ["State", "StateMiddleware"]


@dataclass
class State:
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

    def as_cookie(self, key: bytes) -> str:
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

        fernet = Fernet(key)
        return fernet.encrypt(json.dumps(data).encode()).decode()


class StateMiddleware(BaseHTTPMiddleware):
    """Middleware to read and update an encrypted state cookie."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if "gafaelfawr" in request.cookies:
            state = self._parse_cookie(
                request.cookies["gafaelfawr"], logger(request, config())
            )
        else:
            state = State()

        # Put a copy of the state into the request object.  replace() with no
        # additional parameters makes a copy of a dataclass.  We need to save
        # a copy so that we can determine if the state has changed and
        # therefore whether to replace the cookie after the request handler
        # runs.
        request.state.cookie = replace(state)

        response = await call_next(request)

        if request.state.cookie != state:
            key = config().session_secret.encode()
            cookie = request.state.cookie.as_cookie(key)
            response.set_cookie(
                "gafaelfawr", cookie, secure=True, httponly=True
            )

        return response

    def _parse_cookie(self, cookie: str, logger: BoundLogger) -> State:
        """Parse the state cookie.

        Parameters
        ----------
        cookie : `str`
            The encrypted state cookie.
        config : `gafaelfawr.config.Config`
            The Gafaelfawr configuration, used to get the decryption secret.

        Returns
        -------
        session : `SessionCookie`
            The parsed state cookie information.
        """
        fernet = Fernet(config().session_secret.encode())
        try:
            data = json.loads(fernet.decrypt(cookie.encode()).decode())
        except Exception as e:
            logger.warning("Discarding invalid state cookie", error=str(e))
            return State()

        handle = None
        if "handle" in data:
            handle = SessionHandle.from_str(data["handle"])
        return State(
            csrf=data.get("csrf"),
            handle=handle,
            message=data.get("message"),
            return_url=data.get("return_url"),
            state=data.get("state"),
        )
