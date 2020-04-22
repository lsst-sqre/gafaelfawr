"""Handler for authentication and authorization checking (``/auth``)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aiohttp import web

from gafaelfawr.handlers import routes
from gafaelfawr.handlers.util import authenticated
from gafaelfawr.session import SessionHandle

if TYPE_CHECKING:
    from gafaelfawr.config import Config
    from gafaelfawr.factory import ComponentFactory
    from gafaelfawr.tokens import VerifiedToken
    from logging import Logger
    from typing import Dict

__all__ = ["get_auth"]


@routes.get("/auth")
@authenticated
async def get_auth(request: web.Request, token: VerifiedToken) -> web.Response:
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
    logger: Logger = request["safir/logger"]

    # Determine the required scopes and authorization strategy from the
    # request.
    required_scopes = request.query.getall("scope", [])
    if not required_scopes:
        msg = "scope parameter not set in the request"
        raise web.HTTPBadRequest(reason=msg, text=msg)
    satisfy = request.query.get("satisfy", "all")
    if satisfy not in ("any", "all"):
        msg = "satisfy parameter must be any or all"
        raise web.HTTPBadRequest(reason=msg, text=msg)

    # Determine whether the request is authorized.
    user_scopes = token.claims.get("scope", "").split()
    if satisfy == "any":
        authorized = any([scope in user_scopes for scope in required_scopes])
    else:
        authorized = all([scope in user_scopes for scope in required_scopes])

    # If not authorized, log and raise the appropriate error.
    if not authorized:
        logger.error(
            "Token %s (user: %s, scope: %s) not authorized (needed %s of %s)",
            token.jti,
            token.username,
            token.scope,
            satisfy,
            ", ".join(sorted(required_scopes)),
        )
        error = "Missing required scope"
        raise web.HTTPForbidden(reason=error, text=error)

    # Log and return the results.
    logger.info(
        "Token %s (user: %s, scope: %s) authorized (needed %s of %s)",
        token.jti,
        token.username,
        token.scope,
        satisfy,
        ", ".join(sorted(required_scopes)),
    )
    token = maybe_reissue_token(request, token)
    headers = build_success_headers(request, token)
    return web.Response(headers=headers, text="ok")


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
    }
    if token.claims.get("scope"):
        headers["X-Auth-Request-Token-Scopes"] = token.claims["scope"]
    if token.email:
        headers["X-Auth-Request-Email"] = token.email
    if token.username:
        headers["X-Auth-Request-User"] = token.username
    if token.uid:
        headers["X-Auth-Request-Uid"] = token.uid

    groups_list = token.claims.get("isMemberOf", [])
    if groups_list:
        groups = ",".join([g["name"] for g in groups_list])
        headers["X-Auth-Request-Groups"] = groups

    headers["X-Auth-Request-Token"] = token.encoded

    return headers
