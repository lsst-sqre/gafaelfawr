"""Authentication decorators for route handlers."""

from __future__ import annotations

from functools import wraps
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlparse

from aiohttp import web
from aiohttp_session import get_session

from gafaelfawr.exceptions import InvalidRequestError, InvalidTokenException
from gafaelfawr.handlers.util import (
    AuthChallenge,
    AuthError,
    AuthType,
    RequestContext,
    parse_authorization,
    verify_token,
)
from gafaelfawr.session import SessionHandle

if TYPE_CHECKING:
    from typing import Any, Awaitable, Callable

    from gafaelfawr.session import Session
    from gafaelfawr.tokens import VerifiedToken

    Route = Callable[[web.Request], Awaitable[Any]]
    AuthenticatedRoute = Callable[[web.Request, VerifiedToken], Awaitable[Any]]
    SessionRoute = Callable[[web.Request, Session], Awaitable[Any]]

__all__ = [
    "authenticated_jwt",
    "authenticated_session",
    "authenticated_token",
]


def authenticated_jwt(route: AuthenticatedRoute) -> Route:
    """Deocrator to mark a route as requiring JWT authentication.

    The JWT must be provided as a bearer token in an Authorization header.  If
    the token is missing or invalid, return a 401 error to the caller.  Used
    to protect OpenID Connect routes.

    Parameters
    ----------
    route : `typing.Callable`
        The route that requires authentication.  The token is extracted from
        the incoming request headers, verified, and then passed as a second
        argument of type `gafaelfawr.tokens.VerifiedToken` to the route.

    Returns
    -------
    response : `typing.Callable`
        The decorator generator.

    Raises
    ------
    aiohttp.web.HTTPException
        If no token is present or the token cannot be verified.
    """

    @wraps(route)
    async def authenticated_route(request: web.Request) -> web.Response:
        context = RequestContext.from_request(request)

        try:
            unverified_token = parse_authorization(context)
        except InvalidRequestError as e:
            msg = "Invalid Authorization header"
            context.logger.warning(msg, error=str(e))
            challenge = AuthChallenge(
                auth_type=AuthType.Bearer,
                realm=context.config.realm,
                error=AuthError.invalid_request,
                error_description=str(e),
            )
            headers = {"WWW-Authenticate": challenge.as_header()}
            raise web.HTTPBadRequest(
                headers=headers, reason=str(e), text=str(e)
            )
        if not unverified_token:
            msg = "No authentication token found"
            context.logger.warning(msg)
            challenge = AuthChallenge(AuthType.Bearer, context.config.realm)
            headers = {"WWW-Authenticate": challenge.as_header()}
            raise web.HTTPUnauthorized(headers=headers, reason=msg, text=msg)
        try:
            token = verify_token(context, unverified_token)
        except InvalidTokenException as e:
            context.logger.warning("Invalid token", error=str(e))
            challenge = AuthChallenge(
                auth_type=AuthType.Bearer,
                realm=context.config.realm,
                error=AuthError.invalid_token,
                error_description=str(e),
            )
            headers = {"WWW-Authenticate": challenge.as_header()}
            raise web.HTTPUnauthorized(
                headers=headers, reason=str(e), text=str(e)
            )

        # Add user information to the logger.
        context.rebind_logger(
            token=token.jti,
            user=token.username,
            scope=" ".join(sorted(token.scope)),
        )

        return await route(request, token)

    return authenticated_route


def authenticated_session(route: SessionRoute) -> Route:
    """Decorator to mark a route as requiring authentication with a session.

    The authentication session is passed as an additional parameter to the
    wrapped function.  If there is no session, returns a redirect to the
    ``/login`` route with the current URL as the return URL.

    Parameters
    ----------
    route : `typing.Callable`
        The route that requires authentication.  The session handle is
        extracted from the cookies, converted to a session, and passed as a
        second argument of type `~gafaelfawr.session.Session` to the route.

    Returns
    -------
    response : `typing.Callable`
        The decorator generator.

    Raises
    ------
    aiohttp.web.HTTPException
        The redirect to the ``/login`` route if the user is not authenticated.
    """

    @wraps(route)
    async def authenticated_route(request: web.Request) -> Any:
        context = RequestContext.from_request(request)

        # Retrieve the session.
        session = await get_session(request)
        auth_session = None
        if "handle" in session:
            handle = SessionHandle.from_str(session["handle"])
            session_store = context.factory.create_session_store()
            auth_session = await session_store.get_session(handle)

        # If there is no active session, redirect to /login.
        if not auth_session:
            login_base_url = str(request.app.router["login"].url_for())
            query = urlencode({"rd": str(request.url)})
            login_url = urlparse(login_base_url)._replace(query=query).geturl()
            context.logger.info("Redirecting user for authentication")
            raise web.HTTPFound(login_url)

        # On success, add some context to the logger.
        context.rebind_logger(
            token=auth_session.token.jti,
            user=auth_session.token.username,
            scope=" ".join(sorted(auth_session.token.scope)),
        )

        return await route(request, auth_session)

    return authenticated_route


def authenticated_token(route: AuthenticatedRoute) -> Route:
    """Decorator to mark a route as requiring authentication with a token.

    The authorization token is extracted from the X-Auth-Request-Token header
    and verified, and then passed as an additional parameter to the wrapped
    function.  If the token is missing or invalid, returns a 401 error to the
    user.

    Parameters
    ----------
    route : `typing.Callable`
        The route that requires authentication.  The token is passed as a
        second argument of type `gafaelfawr.tokens.VerifiedToken` to the
        route.

    Returns
    -------
    response : `typing.Callable`
        The decorator generator.

    Raises
    ------
    aiohttp.web.HTTPException
        If no token is present or the token cannot be verified.
    """

    @wraps(route)
    async def authenticated_route(request: web.Request) -> Any:
        context = RequestContext.from_request(request)

        if not request.headers.get("X-Auth-Request-Token"):
            msg = "No authentication token found"
            context.logger.warning(msg)
            challenge = AuthChallenge(AuthType.Bearer, context.config.realm)
            headers = {"WWW-Authenticate": challenge.as_header()}
            raise web.HTTPUnauthorized(headers=headers, reason=msg, text=msg)

        encoded_token = request.headers["X-Auth-Request-Token"]
        try:
            token = verify_token(context, encoded_token)
        except InvalidTokenException as e:
            error = "Failed to authenticate token"
            context.logger.warning(error, error=str(e))
            challenge = AuthChallenge(
                auth_type=AuthType.Bearer,
                realm=context.config.realm,
                error=AuthError.invalid_token,
                error_description=f"{error}: {str(e)}",
            )
            headers = {"WWW-Authenticate": challenge.as_header()}
            raise web.HTTPUnauthorized(
                headers=headers, reason=error, text=challenge.error_description
            )

        # On success, add some context to the logger.
        context.rebind_logger(
            token=token.jti,
            user=token.username,
            scope=" ".join(sorted(token.scope)),
        )

        return await route(request, token)

    return authenticated_route
