"""State cookie management."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import replace
from typing import TYPE_CHECKING

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from typing import Awaitable, Callable, Type

    from fastapi import FastAPI

__all__ = ["BaseState", "StateMiddleware"]


class BaseState(ABC):
    """Base class for state information stored in a cookie.

    Each application must implement this abstract base class and provide the
    class to the `StateMiddleware` constructor.  This allows
    application-specific state while keeping the state middleware handling
    generic.  The derived class must be a dataclass.
    """

    @classmethod
    @abstractmethod
    def from_cookie(cls, cookie: str, request: Request) -> BaseState:
        """Reconstruct state from an encrypted cookie.

        Parameters
        ----------
        cookie : `str`
            The encrypted cookie value.
        request : `fastapi.Request`
            The request, used for logging.

        Returns
        -------
        state : `BaseState`
            The state represented by the cookie.
        """

    @abstractmethod
    def as_cookie(self) -> str:
        """Build an encrypted cookie representation of the state.

        Returns
        -------
        cookie : `str`
            The encrypted cookie value.
        """


class StateMiddleware(BaseHTTPMiddleware):
    """Middleware to read and update an encrypted state cookie.

    If a cookie by the given name exists, it will be parsed by the given class
    and stored as ``request.state.cookie``.  If anything in that object is
    changed as determined by an equality comparison, the state will be
    converted back to a cookie and set in the response after the request is
    complete.

    The cookie will be marked as ``HttpOnly`` and will be marked as ``Secure``
    unless the application is running on localhost and not using TLS.

    This middleware should run after
    `~safir.middleware.x_forwarded.XForwardedMiddleware` since the results of
    that middleware are used to determine if the cookie should be marked as
    secure.

    Parameters
    ----------
    app : `fastapi.FastAPI`
        The ASGI application.
    cookie_name : `str`
        The name of the state cookie.
    state_class : `BaseState`
        The class to use to parse the cookie.  Must be derived from
        `BaseState`.
    """

    def __init__(
        self, app: FastAPI, *, cookie_name: str, state_class: Type[BaseState]
    ) -> None:
        super().__init__(app)
        self.cookie_name = cookie_name
        self.state_class = state_class

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if self.cookie_name in request.cookies:
            cookie = request.cookies[self.cookie_name]
            state = self.state_class.from_cookie(cookie, request)
        else:
            state = self.state_class()

        # Put a copy of the state into the request object.  replace() with no
        # additional parameters makes a copy of a dataclass.  We need to store
        # a copy rather than the original so that we can determine if the
        # state has changed and therefore whether to replace the cookie after
        # the request handler runs.
        request.state.cookie = replace(state)
        response = await call_next(request)

        # If the state has changed, write out the new state.
        if request.state.cookie != state:
            cookie = request.state.cookie.as_cookie()
            secure = self.is_cookie_secure(request)
            response.set_cookie(
                self.cookie_name, cookie, secure=secure, httponly=True
            )

        return response

    @staticmethod
    def is_cookie_secure(request: Request) -> bool:
        """Whether the cookie should be marked as secure.

        Parameters
        ----------
        request : `fastapi.Request`
            The incoming request.

        Returns
        -------
        secure : `bool`
            Whether to mark the cookie as secure.

        Notes
        -----
        Normally, the state cookie is always marked as secure, meaning that it
        won't be sent by the browser to non-HTTPS sites.  However, to allow
        Selenium testing and localhost development, we do not mark it as
        secure if all of the following are true:

        #. The request hostname is localhost
        #. The request proto is http
        #. ``X-Forwarded-Proto``, as determined by the
           `~safir.middleware.x_forwarded.XForwardedMiddleware`, is either not
           set or is http.
        """
        if request.url.hostname != "localhost":
            return True
        if request.url.scheme != "http":
            return True
        if getattr(request.state, "forwarded_proto", None) == "https":
            return True
        return False
