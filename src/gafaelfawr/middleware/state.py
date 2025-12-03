"""State cookie management."""

import copy
from abc import ABCMeta, abstractmethod
from collections.abc import Awaitable, Callable
from typing import Self, override

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ..config import CookieParameters

__all__ = [
    "BaseState",
    "StateMiddleware",
]


class BaseState(metaclass=ABCMeta):
    """Base class for state information stored in a cookie.

    Each application must implement this abstract base class and provide the
    class to the `StateMiddleware` constructor. This allows
    application-specific state while keeping the state middleware handling
    generic. The derived class must be a dataclass.
    """

    @classmethod
    @abstractmethod
    async def from_cookie(cls, cookie: str, request: Request) -> Self:
        """Reconstruct state from an encrypted cookie.

        Parameters
        ----------
        cookie
            The encrypted cookie value.
        request
            The request, used for logging.

        Returns
        -------
        BaseState
            The state represented by the cookie.
        """

    @abstractmethod
    def to_cookie(self) -> str:
        """Build an encrypted cookie representation of the state.

        Returns
        -------
        str
            The encrypted cookie value.
        """


class StateMiddleware[T: BaseState](BaseHTTPMiddleware):
    """Middleware to read and update an encrypted state cookie.

    If a cookie by the given name exists, it will be parsed by the given class
    and stored as ``request.state.cookie``. If anything in that object is
    changed as determined by an equality comparison, the state will be
    converted back to a cookie and set in the response after the request is
    complete.

    This middleware should run after
    `~safir.middleware.x_forwarded.XForwardedMiddleware` since the results of
    that middleware are used to determine if the cookie should be marked as
    secure.

    Parameters
    ----------
    app
        The ASGI application.
    cookie_name
        The name of the state cookie.
    state_class
        The class to use to parse the cookie.
    parameters
        Parameters for the cookie.
    """

    def __init__(
        self,
        app: FastAPI,
        *,
        cookie_name: str,
        state_class: type[T],
        parameters: CookieParameters,
    ) -> None:
        super().__init__(app)
        self._cookie_name = cookie_name
        self._state_class = state_class
        self._parameters = parameters

    @override
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if self._cookie_name in request.cookies:
            cookie = request.cookies[self._cookie_name]
            state = await self._state_class.from_cookie(cookie, request)
        else:
            state = self._state_class()

        # Put a copy of the state into the request object. We need to store a
        # copy rather than the original so that we can determine if the state
        # has changed and therefore whether to replace the cookie after the
        # request handler runs.
        request.state.cookie = copy.copy(state)
        response = await call_next(request)

        # If the state has changed, write out the new state.
        if request.state.cookie != state:
            cookie = request.state.cookie.to_cookie()
            response.set_cookie(self._cookie_name, cookie, **self._parameters)

        return response
