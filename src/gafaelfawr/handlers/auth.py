"""Handler for authentication and authorization checking (``/auth``)."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from aiohttp import web
from aiohttp_session import get_session

from gafaelfawr.handlers import routes
from gafaelfawr.handlers.util import (
    AuthChallenge,
    AuthError,
    AuthType,
    InvalidTokenException,
    verify_token,
)
from gafaelfawr.session import SessionHandle

if TYPE_CHECKING:
    from gafaelfawr.config import Config
    from gafaelfawr.factory import ComponentFactory
    from gafaelfawr.tokens import VerifiedToken
    from logging import Logger
    from typing import Dict, Optional

__all__ = ["get_auth"]


class InvalidRequestException(Exception):
    """The provided Authorization header could not be parsed.

    This corresponds to the ``invalid_request`` error in RFC 6750: "The
    request is missing a required parameter, includes an unsupported parameter
    or parameter value, repeats the same parameter, uses more than one method
    for including an access token, or is otherwise malformed."
    """


@routes.get("/auth")
async def get_auth(request: web.Request) -> web.Response:
    """Authenticate and authorize a token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request, normally from NGINX's ``auth_request``
        directive.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.

    Raises
    ------
    aiohttp.web.HTTPException
        Raised on authorization failures or malformed requests.

    Notes
    -----
    Expects the following query parameters to be set:

    scope
        One or more scopes to check (required, may be given multiple times).
    satisfy (optional)
        Require that ``all`` (the default) or ``any`` of the scopes requested
        via the ``scope`` parameter be satisfied.
    auth_type (optional)
        The authentication type to use in challenges.  If given, must be
        either ``bearer`` or ``basic``.  Defaults to ``bearer``.
    audience (optional)
        May be set to the internal audience to request token reissuance.

    Expects the following headers to be set in the request:

    Authorization
        The JWT token. This must always be the full JWT token. The token
        should be in this  header as type ``Bearer``, but it may be type
        ``Basic`` if ``x-oauth-basic`` is the username or password.  This may
        be omitted if the user has a valid session cookie instead.

    The following headers may be set in the response:

    X-Auth-Request-Email
        If enabled and email is available, this will be set based on the
        ``email`` claim.
    X-Auth-Request-User
        If enabled and the field is available, this will be set from token
        based on the ``JWT_USERNAME_KEY`` field.
    X-Auth-Request-Uid
        If enabled and the field is available, this will be set from token
        based on the ``JWT_UID_KEY`` field.
    X-Auth-Request-Groups
        When a token has groups available in the ``isMemberOf`` claim, the
        names of the groups will be returned, comma-separated, in this
        header.
    X-Auth-Request-Token
        If enabled, the encoded token will be set.
    X-Auth-Request-Token-Scopes
        If the token has scopes in the ``scope`` claim or derived from groups
        in the ``isMemberOf`` claim, they will be returned in this header.
    X-Auth-Request-Token-Scopes-Accepted
        A space-separated list of token scopes the reliant resource accepts.
    X-Auth-Request-Token-Scopes-Satisfy
        Whether all requested scopes must be present, or just any one of
        them.  Will be set to either ``any`` or ``all``.
    WWW-Authenticate
        If the request is unauthenticated, this header will be set.
    """
    config: Config = request.config_dict["gafaelfawr/config"]
    logger: Logger = request["safir/logger"]

    # Determine the required scopes, authorization strategy, and desired auth
    # type for challenges from the request.
    required_scopes = request.query.getall("scope", [])
    if not required_scopes:
        msg = "scope parameter not set in the request"
        raise web.HTTPBadRequest(reason=msg, text=msg)
    satisfy = request.query.get("satisfy", "all")
    if satisfy not in ("any", "all"):
        msg = "satisfy parameter must be any or all"
        raise web.HTTPBadRequest(reason=msg, text=msg)
    auth_type_name = request.query.get("auth_type", "bearer")
    if auth_type_name not in ("basic", "bearer"):
        msg = "auth_type parameter must be basic or bearer"
        raise web.HTTPBadRequest(reason=msg, text=msg)
    auth_type = AuthType[auth_type_name.capitalize()]

    # Check authentication and return an appropriate challenge and error
    # status if authentication failed.
    try:
        token = await get_token_from_request(request)
        if not token:
            logger.info("No token found, returning unauthorized")
            challenge = AuthChallenge(auth_type=auth_type, realm=config.realm)
            raise unauthorized(request, challenge, "Authentication required")
    except InvalidRequestException as e:
        logger.warning("Invalid Authorization header: %s", str(e))
        challenge = AuthChallenge(
            auth_type=auth_type,
            realm=config.realm,
            error=AuthError.invalid_request,
            error_description=str(e),
        )
        headers = {"WWW-Authenticate": challenge.as_header()}
        raise web.HTTPBadRequest(headers=headers, reason=str(e), text=str(e))
    except InvalidTokenException as e:
        logger.warning("Invalid token: %s", str(e))
        challenge = AuthChallenge(
            auth_type=auth_type,
            realm=config.realm,
            error=AuthError.invalid_token,
            error_description=str(e),
        )
        raise unauthorized(request, challenge, str(e))

    # Determine whether the request is authorized.
    if satisfy == "any":
        authorized = any([scope in token.scope for scope in required_scopes])
    else:
        authorized = all([scope in token.scope for scope in required_scopes])

    # If not authorized, log and raise the appropriate error.  Here, we always
    # return a 403 and include the desired scope in the resulting challenge,
    # since that may be useful for debugging issues.
    if not authorized:
        logger.error(
            "Token %s (user: %s, scope: %s) not authorized (needed %s of %s)",
            token.jti,
            token.username,
            ", ".join(sorted(token.scope)) if token.scope else "--none--",
            satisfy,
            ", ".join(sorted(required_scopes)),
        )
        error = "Missing required scope"
        challenge = AuthChallenge(
            auth_type=auth_type,
            realm=config.realm,
            error=AuthError.insufficient_scope,
            error_description=error,
            scope=" ".join(sorted(required_scopes)),
        )
        headers = {"WWW-Authenticate": challenge.as_header()}
        raise web.HTTPForbidden(headers=headers, reason=error, text=error)

    # Log and return the results.
    logger.info(
        "Token %s (user: %s, scope: %s) authorized (needed %s of %s)",
        token.jti,
        token.username,
        ", ".join(sorted(token.scope)),
        satisfy,
        ", ".join(sorted(required_scopes)),
    )
    token = maybe_reissue_token(request, token)
    headers = build_success_headers(request, token)
    return web.Response(headers=headers, text="ok")


async def get_token_from_request(
    request: web.Request,
) -> Optional[VerifiedToken]:
    """From the request, find the token we need.

    It may be in the session cookie or in an ``Authorization`` header, and the
    ``Authorization`` header may use type ``Basic`` (of various types) or
    ``Bearer``.

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
    InvalidRequestException
        The Authorization header was malformed.
    gafaelfawr.handlers.util.InvalidTokenException
        A token was provided but it could not be verified.
    """
    factory: ComponentFactory = request.config_dict["gafaelfawr/factory"]
    logger: Logger = request["safir/logger"]

    # Use the session cookie if it is available.  This check has to be before
    # checking the Authorization header, since JupyterHub will set its own
    # Authorization header in its AJAX calls but we won't be able to extract a
    # token from that and will return 400 for them.
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

    Raises
    ------
    InvalidRequestException
        If the Authorization header is malformed.

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
    if not header:
        return None
    if " " not in header:
        raise InvalidRequestException("malformed Authorization header")
    auth_type, auth_blob = header.split(" ")
    if auth_type.lower() == "bearer":
        return auth_blob
    elif auth_type.lower() != "basic":
        msg = f"unkonwn Authorization type {auth_type}"
        raise InvalidRequestException(msg)

    # Basic, the complicated part.
    logger.debug("Using OAuth with Basic")
    try:
        basic_auth = base64.b64decode(auth_blob).decode()
        user, password = basic_auth.strip().split(":")
    except Exception as e:
        msg = f"invalid Basic auth string: {str(e)}"
        raise InvalidRequestException(msg)
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
    request: web.Request, challenge: AuthChallenge, error: str,
) -> web.HTTPException:
    """Construct exception for a 401 response (403 for AJAX).

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    challenge : `AuthChallenge`
        The challenge used to construct the WWW-Authenticate header.
    error : `str`
        The error message to use as the body of the message.

    Returns
    -------
    exception : `aiohttp.web.HTTPException`
        The exception to raise, either HTTPForbidden (for AJAX) or
        HTTPUnauthorized.

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
    This corresponds to the ``invalid_token`` error in RFC 6750: "The access
    token provided is expired, revoked, malformed, or invalid for other
    reasons.  The string form of this exception is suitable for use as the
    ``error_description`` attribute of a ``WWW-Authenticate`` header.
    """
    headers = {"WWW-Authenticate": challenge.as_header()}

    requested_with = request.headers.get("X-Requested-With")
    if requested_with and requested_with.lower() == "xmlhttprequest":
        return web.HTTPForbidden(headers=headers, reason=error, text=error)
    else:
        return web.HTTPUnauthorized(headers=headers, reason=error, text=error)


def maybe_reissue_token(
    request: web.Request, token: VerifiedToken
) -> VerifiedToken:
    """Possibly reissue the token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    token : `gafaelfawr.tokens.VerifiedToken`
        The current token.

    Returns
    -------
    token : `gafaelfawr.tokens.VerifiedToken`
        An encoded token, which may have been reissued.

    Notes
    -----
    The token will be reissued if this is a request to an internal resource,
    as indicated by the ``audience`` parameter being equal to the configured
    internal audience, where the current token's audience is from the default
    audience.  The token will be reissued to the internal audience.  This
    allows passing a more restrictive token to downstream systems that may
    reuse that tokens for their own API calls.
    """
    config: Config = request.config_dict["gafaelfawr/config"]
    factory: ComponentFactory = request.config_dict["gafaelfawr/factory"]

    if not request.query.get("audience") == config.issuer.aud_internal:
        return token
    if not token.claims["aud"] == config.issuer.aud:
        return token

    # Create a new handle just to get a new key for the jti.  The reissued
    # internal token is never stored in a session and cannot be accessed via a
    # session handle, so we don't use the handle to store it.
    issuer = factory.create_token_issuer()
    handle = SessionHandle()
    return issuer.reissue_token(token, jti=handle.key, internal=True)


def build_success_headers(
    request: web.Request, token: VerifiedToken
) -> Dict[str, str]:
    """Construct the headers for successful authorization.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    token : `gafaelfawr.tokens.VerifiedToken`
        The token.

    Returns
    -------
    headers : Dict[`str`, `str`]
        Headers to include in the response.
    """
    required_scopes = sorted(request.query.getall("scope", []))
    satisfy = request.query.get("satisfy", "all")

    headers = {
        "X-Auth-Request-Scopes-Accepted": " ".join(required_scopes),
        "X-Auth-Request-Scopes-Satisfy": satisfy,
        "X-Auth-Request-User": token.username,
        "X-Auth-Request-Uid": token.uid,
    }
    if token.scope:
        headers["X-Auth-Request-Token-Scopes"] = " ".join(sorted(token.scope))
    if token.email:
        headers["X-Auth-Request-Email"] = token.email

    groups_list = token.claims.get("isMemberOf", [])
    if groups_list:
        groups = ",".join([g["name"] for g in groups_list])
        headers["X-Auth-Request-Groups"] = groups

    headers["X-Auth-Request-Token"] = token.encoded

    return headers
