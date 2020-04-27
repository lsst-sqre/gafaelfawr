"""Utility functions for external routes."""

from __future__ import annotations

import base64
from functools import wraps
from typing import TYPE_CHECKING

import jwt
from aiohttp import web
from aiohttp_session import get_session

from gafaelfawr.session import SessionHandle
from gafaelfawr.tokens import Token

if TYPE_CHECKING:
    from gafaelfawr.config import Config
    from gafaelfawr.factory import ComponentFactory
    from gafaelfawr.tokens import VerifiedToken
    from logger import Logger
    from typing import Any, Awaitable, Callable, Optional

    Route = Callable[[web.Request], Awaitable[Any]]
    AuthenticatedRoute = Callable[[web.Request, VerifiedToken], Awaitable[Any]]

__all__ = ["authenticated"]


def authenticated(route: AuthenticatedRoute) -> Route:
    """Decorator to mark a route as requiring authentication.

    The authentication token is extracted from the incoming request and
    verified, and then passed as an additional parameter to the wrapped
    function.  If the token is missing or invalid, throws an unauthorized
    exception.

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
    async def authenticated_route(request: web.Request) -> Any:
        logger: Logger = request["safir/logger"]

        try:
            token = await get_token_from_request(request)
            if not token:
                logger.info("No token found, returning unauthorized")
                raise unauthorized(request, "Unable to find token")
        except jwt.PyJWTError as e:
            logger.exception("Failed to authenticate token")
            raise unauthorized(request, "Invalid token", str(e))

        return await route(request, token)

    return authenticated_route


async def get_token_from_request(
    request: web.Request,
) -> Optional[VerifiedToken]:
    """From the request, find the token we need.

    It may be an Authorization header of type ``bearer``, in one of type
    ``basic`` for clients that don't support OAuth 2, or in the session cookie
    for web clients in cases where oauth2_proxy is not in use.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    token : `gafaelfawr.tokens.VerifiedToken`, optional
        The token if found, otherwise None.

    Raises
    ------
    aiohttp.web.HTTPException
        A token was provided but it could not be verified.
    """
    factory: ComponentFactory = request.config_dict["gafaelfawr/factory"]
    logger: Logger = request["safir/logger"]

    # Prefer X-Auth-Request-Token if set.  This is set by the /auth endpoint.
    if request.headers.get("X-Auth-Request-Token"):
        logger.debug("Found token in X-Auth-Request-Token")
        return verify_token(request, request.headers["X-Auth-Request-Token"])

    # Failing that, check the session.  Use it if available.  This needs to
    # happen before checking the Authorization header, since JupyterHub will
    # set its own Authorization header in its JavaScript calls but we won't be
    # able to extract a token from that.
    session = await get_session(request)
    handle_str = session.get("handle")
    if handle_str:
        logger.debug("Found valid handle in session")
        handle = SessionHandle.from_str(handle_str)
        session_store = factory.create_session_store(request)
        auth_session = await session_store.get_session(handle)
        if auth_session:
            return auth_session.token

    # No session or existing authentication header.  Try the Authorization
    # header.  This case is used by API calls from clients.  If we got a
    # session handle, convert it to a token.  Otherwise, if we got a token,
    # verify it.
    handle_or_token = parse_authorization(request)
    if not handle_or_token:
        return None
    elif handle_or_token.startswith("gsh-"):
        handle = SessionHandle.from_str(handle_or_token)
        session_store = factory.create_session_store(request)
        auth_session = await session_store.get_session(handle)
        return auth_session.token if auth_session else None
    else:
        return verify_token(request, handle_or_token)


def parse_authorization(request: web.Request) -> Optional[str]:
    """Find a handle or token in the Authorization header.

    Supports either ``Bearer`` or ``Basic`` authorization types.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    handle_or_token : `str` or `None`
        The handle or token if one was found, otherwise None.

    Notes
    -----
    A Basic Auth authentication string is normally a username and a password
    separated by colon and then base64-encoded.  Support a username of the
    token (or session handle) and a password of ``x-oauth-basic``, or a
    username of ``x-oauth-basic`` and a password of the token (or session
    handle).  If neither is the case, assume the token or session handle is
    the username.
    """
    logger: Logger = request["safir/logger"]

    # Parse the header and handle Bearer.
    header = request.headers.get("Authorization")
    if not header or " " not in header:
        return None
    auth_type, auth_blob = header.split(" ")
    if auth_type.lower() == "bearer":
        return auth_blob
    elif auth_type.lower() != "basic":
        logger.debug("Ignoring unknown Authorization type %s", auth_type)
        return None

    # Basic, the complicated part.
    logger.debug("Using OAuth with Basic")
    try:
        basic_auth = base64.b64decode(auth_blob).decode()
        user, password = basic_auth.strip().split(":")
    except Exception as e:
        logger.warning("Invalid Basic auth string: %s", str(e))
        return None
    if password == "x-oauth-basic":
        return user
    elif user == "x-oauth-basic":
        return password
    else:
        logger.info(
            "Neither username nor password in HTTP Basic is x-oauth-basic,"
            " assuming handle or token is username"
        )
        return user


def unauthorized(
    request: web.Request, error: str, message: str = ""
) -> web.HTTPException:
    """Construct exception for a 401 response (403 for AJAX).

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    error : `str`
        The error message to use as the body of the message and the error
        parameter in the WWW-Authenticate header.
    message : `str`, optional
        The error description for the WWW-Authetnicate header.

    Returns
    -------
    exception : `aiohttp.web.HTTPException`
        Exception to throw.

    Notes
    -----
    If the request contains X-Requested-With: XMLHttpRequest, return 403
    rather than 401.  The presence of this header indicates an AJAX request,
    which in turn means that the request is not under full control of the
    browser window.  The redirect ingress-nginx will send will therefore not
    result in the user going to the authentication provider properly, but may
    result in a spurious request from background AJAX that cannot be
    completed.  That, in turn, can cause unnecessary load on the
    authentication provider and may result in rate limiting.

    Checking for this header does not catch all requests that are pointless to
    redirect (image and CSS requests, for instance), and not all AJAX requests
    will send the header, but every request with this header should be
    pointless to redirect, so at least it cuts down on the noise.
    """
    config: Config = request.config_dict["gafaelfawr/config"]

    requested_with = request.headers.get("X-Requested-With")
    if requested_with and requested_with.lower() == "xmlhttprequest":
        return web.HTTPForbidden(reason=error, text=error)
    else:
        realm = config.realm
        info = f'realm="{realm}",error="{error}",error_description="{message}"'
        headers = {"WWW-Authenticate": f"Bearer {info}"}
        return web.HTTPUnauthorized(headers=headers, reason=error, text=error)


def verify_token(request: web.Request, encoded_token: str) -> VerifiedToken:
    """Verify a token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    encoded_token : `str`
        The encoded token.

    Returns
    -------
    token : `gafaelfawr.tokens.VerifiedToken`
        The verified token.

    Raises
    ------
    aiohttp.web.HTTPException
        If the token could not be verified.
    """
    factory: ComponentFactory = request.config_dict["gafaelfawr/factory"]
    logger: Logger = request["safir/logger"]

    token = Token(encoded=encoded_token)
    token_verifier = factory.create_token_verifier(request)
    try:
        return token_verifier.verify_internal_token(token)
    except Exception as e:
        error = f"Invalid token: {str(e)}"
        logger.warning("%s", error)
        raise web.HTTPForbidden(reason=error, text=error)
