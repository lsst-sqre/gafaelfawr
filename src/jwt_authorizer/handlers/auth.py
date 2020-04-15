"""Handler for authentication and authorization checking (``/auth``)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import jwt
from aiohttp import web

from jwt_authorizer.authnz import (
    authenticate,
    authorize,
    capabilities_from_groups,
)
from jwt_authorizer.handlers import routes
from jwt_authorizer.handlers.util import (
    build_capability_headers,
    forbidden,
    get_token_from_request,
    unauthorized,
)
from jwt_authorizer.session import Ticket

if TYPE_CHECKING:
    from jwt_authorizer.config import Config
    from jwt_authorizer.factory import ComponentFactory
    from jwt_authorizer.tokens import VerifiedToken
    from logging import Logger
    from typing import Tuple

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
    X-Orig-Authorization
        The Authorization header as it was received before processing by
        ``oauth2_proxy``. This is useful when the original header was an
        ``oauth2_proxy`` ticket, as this gives access to the ticket.

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
    X-Auth-Request-Token-Ticket
        When a ticket is available for the token, we will return it under this
        header.
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


async def _check_reissue_token(
    request: web.Request, token: VerifiedToken
) -> Tuple[VerifiedToken, str]:
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
    oauth2_proxy_ticket_str : `str`
        A ticket for the oauth2_proxy session.

    Notes
    -----
    The token will be reissued under two scenarios.

    The first scenario is a newly logged in session with a cookie, indicated
    by the token being issued from another issuer.  We reissue the token with
    a default audience.

    The second scenario is a request to an internal resource, as indicated by
    the ``audience`` parameter being equal to the configured internal
    audience, where the current token's audience is from the default audience.
    We will reissue the token with an internal audience.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]
    factory: ComponentFactory = request.config_dict["jwt_authorizer/factory"]

    # Only reissue token if it's requested and if it's a different
    # issuer than this application uses to reissue a token
    iss = config.issuer.iss
    default_audience = config.issuer.aud
    internal_audience = config.issuer.aud_internal
    to_internal_audience = request.query.get("audience") == internal_audience
    from_this_issuer = token.claims["iss"] == iss
    from_default_audience = token.claims["aud"] == default_audience
    cookie_name = config.session_store.ticket_prefix
    ticket_str = request.cookies.get(cookie_name, "")
    ticket = None
    issuer = factory.create_token_issuer()

    if not from_this_issuer:
        # If we didn't issue the token, it came from a provider as part of a
        # new session. This only happens once, after initial login, so there
        # should always be a cookie set. If there isn't, or we fail to parse
        # it, something funny is going on and we can abort with an exception.
        ticket = Ticket.from_cookie(cookie_name, ticket_str)
        scope = " ".join(
            sorted(capabilities_from_groups(token, config.group_mapping))
        )
        token = await issuer.reissue_token(token, ticket, scope=scope)
    elif from_this_issuer and from_default_audience and to_internal_audience:
        # In this case, we only reissue tokens from a default audience
        ticket = Ticket()
        token = await issuer.reissue_token(
            token, ticket, internal=to_internal_audience
        )

    return token, ticket.encode(cookie_name) if ticket else ""


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

    if config.set_user_headers:
        email = token.claims.get("email")
        user = token.claims.get(config.username_key)
        uid = token.claims.get(config.uid_key)
        groups_list = token.claims.get("isMemberOf", list())
        if email:
            headers["X-Auth-Request-Email"] = email
        if user:
            headers["X-Auth-Request-User"] = user
        if uid:
            headers["X-Auth-Request-Uid"] = uid
        if groups_list:
            groups = ",".join([g["name"] for g in groups_list])
            headers["X-Auth-Request-Groups"] = groups

    token, oauth2_proxy_ticket = await _check_reissue_token(request, token)
    headers["X-Auth-Request-Token"] = token.encoded
    headers["X-Auth-Request-Token-Ticket"] = oauth2_proxy_ticket
    return web.Response(headers=headers, text="ok")
