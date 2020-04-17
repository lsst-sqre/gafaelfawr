"""Utility functions for external routes."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from aiohttp import web
from aiohttp_session import get_session

from jwt_authorizer.authnz import (
    capabilities_from_groups,
    verify_authorization_strategy,
)
from jwt_authorizer.session import SessionHandle
from jwt_authorizer.tokens import Token

if TYPE_CHECKING:
    from jwt_authorizer.config import Config
    from jwt_authorizer.factory import ComponentFactory
    from jwt_authorizer.tokens import VerifiedToken
    from logger import Logger
    from typing import Dict, Optional

__all__ = [
    "build_capability_headers",
    "forbidden",
    "get_token_from_request",
    "unauthorized",
]


def build_capability_headers(
    request: web.Request, token: VerifiedToken
) -> Dict[str, str]:
    """Construct response headers containing capability information.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    verified_token : `jwt_authorizer.tokens.VerifiedToken`
        A verified token containing group and scope information.

    Returns
    -------
    headers : Dict[`str`, str]
        The headers to include in the response.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]

    capabilities_required, satisfy = verify_authorization_strategy(request)
    group_capabilities_set = capabilities_from_groups(
        token, config.group_mapping
    )
    if "scope" in token.claims:
        scope_capabilities_set = set(token.claims["scope"].split(" "))
        user_capabilities_set = group_capabilities_set.union(
            scope_capabilities_set
        )
    else:
        user_capabilities_set = group_capabilities_set

    return {
        "X-Auth-Request-Token-Capabilities": " ".join(
            sorted(user_capabilities_set)
        ),
        "X-Auth-Request-Capabilities-Accepted": " ".join(
            sorted(capabilities_required)
        ),
        "X-Auth-Request-Capabilities-Satisfy": satisfy,
    }


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
    headers = build_capability_headers(request, token)
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
