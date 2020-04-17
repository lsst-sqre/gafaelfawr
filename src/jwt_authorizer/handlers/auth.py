"""Handler for authentication and authorization checking (``/auth``)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import jwt
from aiohttp import web

from jwt_authorizer.authnz import authenticate, authorize
from jwt_authorizer.handlers import routes
from jwt_authorizer.handlers.util import (
    build_capability_headers,
    forbidden,
    get_token_from_request,
    unauthorized,
)
from jwt_authorizer.session import SessionHandle

if TYPE_CHECKING:
    from jwt_authorizer.config import Config
    from jwt_authorizer.factory import ComponentFactory
    from jwt_authorizer.tokens import VerifiedToken
    from logging import Logger

__all__ = ["get_auth"]


@routes.get("/auth")
async def get_auth(request: web.Request) -> web.Response:
    """Authenticate and authorize a token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request, normally from nginx's ``auth_request``
        directive.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.

    Notes
    -----
    Expects the following query parameters to be set:

    capability
        One or more capabilities to check (required).
    satisfy
        Require that ``all`` (the default) or ``any`` of the capabilities
        requested via the ``capbility`` parameter be satisfied.

    Expects the following headers to be set in the request:

    Authorization
        The JWT token. This must always be the full JWT token. The token
        should be in this  header as type ``Bearer``, but it may be type
        ``Basic`` if ``x-oauth-basic`` is the username or password.

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
    X-Auth-Request-Token-Capabilities
        If the token has capabilities in the ``scope`` claim, they will be
        returned in this header.
    X-Auth-Request-Token-Capabilities-Accepted
        A space-separated list of token capabilities the reliant resource
        accepts.
    X-Auth-Request-Token-Capabilities-Satisfy
        The strategy the reliant resource uses to accept a capability. Values
        include ``any`` or ``all``.
    WWW-Authenticate
        If the request is unauthenticated, this header will be set.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]
    logger: Logger = request["safir/logger"]

    encoded_token = await get_token_from_request(request)
    if not encoded_token:
        logger.info("No token found, returning unauthorized")
        raise unauthorized(request, "Unable to find token")

    # Authentication
    try:
        token = await authenticate(request, encoded_token)
    except jwt.PyJWTError as e:
        logger.exception("Failed to authenticate token")
        raise unauthorized(request, "Invalid token", message=str(e))

    # Authorization
    okay, message = authorize(request, token)
    jti = token.claims.get("jti", "UNKNOWN")
    if okay:
        user_id = token.claims[config.uid_key]
        logger.info(
            f"Allowed token with Token ID={jti} for user={user_id} "
            f"from issuer={token.claims['iss']}"
        )
        return await success(request, token)
    else:
        logger.error(f"Failed to authorize Token ID {jti} because {message}")
        raise forbidden(request, token, message)


def _check_reissue_token(
    request: web.Request, token: VerifiedToken
) -> VerifiedToken:
    """Possibly reissue the token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    token : `jwt_authorizer.tokens.VerifiedToken`
        The current token.

    Returns
    -------
    token : `jwt_authorizer.tokens.VerifiedToken`
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
    config: Config = request.config_dict["jwt_authorizer/config"]
    factory: ComponentFactory = request.config_dict["jwt_authorizer/factory"]

    if not request.query.get("audience") == config.issuer.aud_internal:
        return token
    if not token.claims["iss"] == config.issuer.iss:
        return token
    if not token.claims["aud"] == config.issuer.aud:
        return token

    # Create a new handle just to get a new key for the jti.  The reissued
    # internal token is never stored in a session and cannot be accessed via a
    # session handle, so we don't use the handle to store it.
    issuer = factory.create_token_issuer()
    handle = SessionHandle()
    return issuer.reissue_token(token, jti=handle.key, internal=True)


async def success(request: web.Request, token: VerifiedToken) -> web.Response:
    """Construct a response for successful authorization.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    token : `jwt_authorizer.tokens.VerifiedToken`
        The token.

    Returns
    -------
    response : `aiohttp.web.Resposne`
        Response to send.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]

    headers = build_capability_headers(request, token)

    email = token.claims.get("email")
    if email:
        headers["X-Auth-Request-Email"] = email

    user = token.claims.get(config.username_key)
    if user:
        headers["X-Auth-Request-User"] = user

    uid = token.claims.get(config.uid_key)
    if uid:
        headers["X-Auth-Request-Uid"] = uid

    groups_list = token.claims.get("isMemberOf", list())
    if groups_list:
        groups = ",".join([g["name"] for g in groups_list])
        headers["X-Auth-Request-Groups"] = groups

    token = _check_reissue_token(request, token)
    headers["X-Auth-Request-Token"] = token.encoded

    return web.Response(headers=headers, text="ok")
