"""Utility functions for external routes."""

from __future__ import annotations

import base64
from functools import wraps
from typing import TYPE_CHECKING

import jwt
from aiohttp import web
from aiohttp_session import get_session

from jwt_authorizer.authnz import scopes_from_token
from jwt_authorizer.session import SessionHandle
from jwt_authorizer.tokens import Token

if TYPE_CHECKING:
    from jwt_authorizer.config import Config
    from jwt_authorizer.factory import ComponentFactory
    from jwt_authorizer.tokens import VerifiedToken
    from logger import Logger
    from typing import Any, Awaitable, Callable, Dict, Optional

__all__ = [
    "forbidden",
    "get_token_from_request",
    "scope_headers",
    "unauthorized",
]


def authenticated(
    route: Callable[[web.Request, VerifiedToken], Awaitable[Any]]
) -> Callable[[web.Request], Awaitable[Any]]:
    """Decorator to mark a route as requiring authentication.

    The authentication token is extracted from the incoming request and
    verified, and then passed as an additional parameter to the wrapped
    function.  If the token is missing or invalid, throws an unauthorized
    exception.

    Paramters
    ---------
    route : `typing.Callable`
        A route handler that takes an `aiohttp.web.Request` and a
        `jwt_authorizer.tokens.VerifiedToken`.  This decorator should be in
        front of (below) the @route decorator.

    Response
    --------
    response : `typing.Callable`
        The wrapped route.
    """

    @wraps(route)
    async def wrapped_route(request: web.Request) -> Any:
        factory: ComponentFactory = request.config_dict[
            "jwt_authorizer/factory"
        ]
        logger: Logger = request["safir/logger"]

        try:
            encoded_token = await get_token_from_request(request)
            if not encoded_token:
                logger.info("No token found, returning unauthorized")
                raise unauthorized(request, "Unable to find token")
            issuer = factory.create_token_issuer()
            token = issuer.verify_token(encoded_token)
        except jwt.PyJWTError as e:
            logger.exception("Failed to authenticate token")
            raise unauthorized(request, "Invalid token", str(e))

        return await route(request, token)

    return wrapped_route


async def get_token_from_request(request: web.Request) -> Optional[Token]:
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
    token : `jwt_authorizer.tokens.Token`, optional
        The token if found, otherwise None.
    """
    factory: ComponentFactory = request.config_dict["jwt_authorizer/factory"]
    logger: Logger = request["safir/logger"]

    # Prefer X-Auth-Request-Token if set.  This is set by the /auth endpoint.
    if request.headers.get("X-Auth-Request-Token"):
        logger.debug("Found token in X-Auth-Request-Token")
        return Token(encoded=request.headers["X-Auth-Request-Token"])

    # Failing that, check the session.  Use it if available.  This needs to
    # happen before checking the Authorization header, since JupyterHub will
    # set its own Authorization header in its JavaScript calls but we won't be
    # able to extract a token from that.
    session = await get_session(request)
    handle_str = session.get("ticket")
    if handle_str:
        logger.debug("Found valid handle in session")
        handle = SessionHandle.from_str(handle_str)
        session_store = factory.create_session_store(request)
        auth_session = await session_store.get_session(handle)
        if auth_session:
            return auth_session.token

    # No session or existing authentication header.  Try the Authorization
    # header.  This case is used by API calls from clients.
    header = request.headers.get("Authorization")
    if not header or " " not in header:
        return None
    auth_type, auth_blob = header.split(" ")
    if auth_type.lower() == "bearer":
        return Token(encoded=auth_blob)
    elif "x-forwarded-access-token" in request.headers:
        return Token(encoded=request.headers["x-forwarded-access-token"])
    elif "x-forwarded-ticket-id-token" in request.headers:
        return Token(encoded=request.headers["x-forwarded-ticket-id-token"])
    elif auth_type.lower() == "basic":
        logger.debug("Using OAuth with Basic")
        return _find_token_in_basic_auth(auth_blob, logger)
    else:
        return None


def _find_token_in_basic_auth(blob: str, logger: Logger) -> Optional[Token]:
    """Find a token in the Basic Auth authentication string.

    A Basic Auth authentication string is normally a username and a password
    separated by colon and then base64-encoded.  Support a username of the
    token and a password of ``x-oauth-basic``, or a username of
    ``x-oauth-basic`` and a password of the token.  If neither is the case,
    assume the token is the username.

    Parameters
    ----------
    blob : `str`
        The encoded portion of the ``Authorization`` header.
    logger : `logging.Logger`
        Logger to use to report issues.

    Returns
    -------
    token : `jwt_authorizer.tokens.Token`, optional
        The token if one was found, otherwise None.
    """
    try:
        basic_auth = base64.b64decode(blob)
        user, password = basic_auth.strip().split(b":")
    except Exception as e:
        logger.warning("Invalid Basic auth string: %s", str(e))
        return None

    if password == b"x-oauth-basic":
        # Recommended default
        return Token(encoded=user.decode())
    elif user == b"x-oauth-basic":
        # ... Could be this though
        return Token(encoded=password.decode())
    else:
        logger.debug("No protocol for token specified, falling back on user")
        return Token(encoded=user.decode())


def scope_headers(
    request: web.Request, token: VerifiedToken
) -> Dict[str, str]:
    """Construct response headers containing capability information.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    token : `jwt_authorizer.tokens.VerifiedToken`
        A verified token containing group and scope information.

    Returns
    -------
    headers : Dict[`str`, `str`]
        The headers to include in the response.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]

    user_scopes = sorted(scopes_from_token(token, config.group_mapping))
    required_scopes = sorted(request.query.getall("scope", []))
    if not required_scopes:
        # Backward compatibility.  Can be removed when all deployments have
        # been updated.
        required_scopes = sorted(request.query.getall("capability", []))
    satisfy = request.query.get("satisfy", "all")

    return {
        "X-Auth-Request-Token-Scopes": " ".join(user_scopes),
        "X-Auth-Request-Scopes-Accepted": " ".join(required_scopes),
        "X-Auth-Request-Scopes-Satisfy": satisfy,
    }


def forbidden(
    request: web.Request, token: VerifiedToken, error: str
) -> web.HTTPException:
    """Construct exception for a 403 response.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    token : VerifiedToken
        A verified token containing group and scope information.
    error : `str`
        The error message.

    Returns
    -------
    exception : `aiohttp.web.HTTPException`
        Exception to throw.
    """
    headers = scope_headers(request, token)
    return web.HTTPForbidden(headers=headers, reason=error, text=error)


def unauthorized(
    request: web.Request, error: str, message: str = ""
) -> web.HTTPException:
    """Construct exception for a 401 response.

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
    """
    config: Config = request.config_dict["jwt_authorizer/config"]

    realm = config.realm
    info = f'realm="{realm}",error="{error}",error_description="{message}"'
    headers = {"WWW-Authenticate": f"Bearer {info}"}
    return web.HTTPUnauthorized(headers=headers, reason=error, text=error)
