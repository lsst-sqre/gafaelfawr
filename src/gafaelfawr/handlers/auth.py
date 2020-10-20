"""Handler for authentication and authorization checking (``/auth``)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set

from fastapi import Depends, Header, HTTPException, Query, Response, status

from gafaelfawr.auth import (
    AuthError,
    AuthErrorChallenge,
    AuthType,
    generate_challenge,
    generate_unauthorized_challenge,
    parse_authorization,
    verify_token,
)
from gafaelfawr.dependencies import RequestContext, context
from gafaelfawr.exceptions import (
    InsufficientScopeError,
    InvalidRequestError,
    InvalidTokenError,
)
from gafaelfawr.handlers import router
from gafaelfawr.session import SessionHandle
from gafaelfawr.tokens import VerifiedToken

__all__ = ["get_auth"]


class Satisfy(Enum):
    """Authorization strategies.

    Controls how to do authorization when there are multiple required scopes.
    A strategy of ANY allows the request if the authentication token has any
    of the required scopes.  A strategy of ALL requires that the
    authentication token have all the required scopes.
    """

    ANY = "any"
    ALL = "all"


@dataclass
class AuthConfig:
    """Configuration for an authorization request."""

    scopes: Set[str]
    """The scopes the authentication token must have."""

    satisfy: Satisfy
    """The authorization strategy if multiple scopes are required."""

    auth_type: AuthType
    """The authentication type to use in challenges."""


def auth_uri(
    x_original_uri: Optional[str] = Header(None),
    x_original_url: Optional[str] = Header(None),
) -> str:
    """Determine URL for which we're validating authentication.

    ``X-Original-URI`` will only be set if the auth-method annotation is set.
    That is recommended, but allow for the case where it isn't set and fall
    back on ``X-Original-URL``, which is set unconditionally.
    """
    return x_original_uri or x_original_url or "NONE"


def auth_config(
    scope: List[str] = Query(...),
    satisfy: Satisfy = Satisfy.ALL,
    auth_type: AuthType = AuthType.Bearer,
    context: RequestContext = Depends(context),
    auth_uri: str = Depends(auth_uri),
) -> AuthConfig:
    context.rebind_logger(
        auth_uri=auth_uri,
        required_scope=" ".join(sorted(scope)),
        satisfy=satisfy.name.lower(),
    )
    return AuthConfig(scopes=set(scope), satisfy=satisfy, auth_type=auth_type)


@router.get("/auth")
async def get_auth(
    response: Response,
    auth_config: AuthConfig = Depends(auth_config),
    audience: Optional[str] = None,
    context: RequestContext = Depends(context),
) -> Dict[str, str]:
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

    X-Auth-Request-Client-Ip
        The IP address of the client, as determined after parsing
        X-Forwarded-For headers.
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
    try:
        token = await get_token_from_request(context)
    except InvalidRequestError as e:
        raise generate_challenge(context, auth_config.auth_type, e)
    except InvalidTokenError as e:
        raise generate_unauthorized_challenge(
            context, auth_config.auth_type, e, ajax_forbidden=True
        )
    if not token:
        raise generate_unauthorized_challenge(
            context, auth_config.auth_type, ajax_forbidden=True
        )

    # Add user information to the logger.
    context.rebind_logger(
        token=token.jti,
        user=token.username,
        scope=" ".join(sorted(token.scope)),
    )

    # Determine whether the request is authorized.
    if auth_config.satisfy == Satisfy.ANY:
        authorized = any([s in token.scope for s in auth_config.scopes])
    else:
        authorized = all([s in token.scope for s in auth_config.scopes])

    # If not authorized, log and raise the appropriate error.
    if not authorized:
        exc = InsufficientScopeError("Token missing required scope")
        raise generate_challenge(
            context, auth_config.auth_type, exc, auth_config.scopes
        )

    # Log and return the results.
    context.logger.info("Token authorized")
    token = maybe_reissue_token(context, audience, token)
    headers = build_success_headers(context, auth_config, token)
    response.headers.update(headers)
    return {"status": "ok"}


@router.get("/auth/forbidden")
async def get_auth_forbidden(
    response: Response,
    auth_config: AuthConfig = Depends(auth_config),
    context: RequestContext = Depends(context),
) -> Response:
    """Error page for HTTP Forbidden (403) errors.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request via NGINX's ``error_page`` directive.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response (never returned because this method raises instead).

    Raises
    ------
    aiohttp.web.HTTPException
        An HTTPForbidden exception with the correct authentication challenge.

    Notes
    -----
    This route exists because we want to set a ``Cache-Control`` header on 403
    errors so that the browser will not cache them.  This doesn't appear to
    easily be possible with ingress-nginx without using a custom error page,
    since headers returned by an ``auth_request`` handler are not passed back
    to the client.

    This route is configured as a custom error page using an annotation like:

    .. code-block:: yaml

       nginx.ingress.kubernetes.io/configuration-snippet: |
         error_page 403 = "/auth/forbidden?scope=<scope>";

    It takes the same parameters as the ``/auth`` route and uses them to
    construct an appropriate challenge, assuming that the 403 is due to
    insufficient token scope.
    """
    error = "Token missing required scope"
    challenge = AuthErrorChallenge(
        auth_type=auth_config.auth_type,
        realm=context.config.realm,
        error=AuthError.insufficient_scope,
        error_description=error,
        scope=" ".join(sorted(auth_config.scopes)),
    )
    headers = {
        "Cache-Control": "no-cache, must-revalidate",
        "WWW-Authenticate": challenge.as_header(),
    }
    context.logger.info("Serving uncached 403 page")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        headers=headers,
        detail={"msg": error, "type": "permission_denied"},
    )


async def get_token_from_request(
    context: RequestContext,
) -> Optional[VerifiedToken]:
    """From the request, find the token we need.

    It may be in the session cookie or in an ``Authorization`` header, and the
    ``Authorization`` header may use type ``Basic`` (of various types) or
    ``Bearer``.  Rebinds the logging context to include the source of the
    token, if one is found.

    Parameters
    ----------
    context : `gafaelfawr.handlers.util.RequestContext`
        The context of the incoming request.

    Returns
    -------
    token : `gafaelfawr.tokens.VerifiedToken`, optional
        The token if found, otherwise None.

    Raises
    ------
    gafaelfawr.exceptions.InvalidRequestError
        The Authorization header was malformed.
    gafaelfawr.handlers.util.InvalidTokenError
        A token was provided but it could not be verified.
    """
    # Use the session cookie if it is available.  This check has to be before
    # checking the Authorization header, since JupyterHub will set its own
    # Authorization header in its AJAX calls but we won't be able to extract a
    # token from that and will return 400 for them.
    if context.request.state.cookie.handle:
        handle = context.request.state.cookie.handle
        context.rebind_logger(token_source="cookie")
        session_store = context.factory.create_session_store()
        session = await session_store.get_session(handle)
        if session:
            return session.token

    # No session or existing authentication header.  Try the Authorization
    # header.  This case is used by API calls from clients.  If we got a
    # session handle, convert it to a token.  Otherwise, if we got a token,
    # verify it.
    handle_or_token = parse_authorization(context, allow_basic=True)
    if not handle_or_token:
        return None
    elif handle_or_token.startswith("gsh-"):
        handle = SessionHandle.from_str(handle_or_token)
        session_store = context.factory.create_session_store()
        session = await session_store.get_session(handle)
        return session.token if session else None
    else:
        return verify_token(context, handle_or_token)


def maybe_reissue_token(
    context: RequestContext, audience: Optional[str], token: VerifiedToken
) -> VerifiedToken:
    """Possibly reissue the token.

    Parameters
    ----------
    context : `gafaelfawr.handlers.util.RequestContext`
        The context of the incoming request.
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
    aud_internal = context.config.issuer.aud_internal
    if not audience == aud_internal:
        return token
    if not token.claims["aud"] == context.config.issuer.aud:
        return token

    # Create a new handle just to get a new key for the jti.  The reissued
    # internal token is never stored in a session and cannot be accessed via a
    # session handle, so we don't use the handle to store it.
    issuer = context.factory.create_token_issuer()
    handle = SessionHandle()
    context.logger.info("Reissuing token to audience %s", aud_internal)
    return issuer.reissue_token(token, jti=handle.key, internal=True)


def build_success_headers(
    context: RequestContext, auth_config: AuthConfig, token: VerifiedToken
) -> Dict[str, str]:
    """Construct the headers for successful authorization.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    auth_config : `AuthConfig`
        Configuration parameters for the authorization.
    token : `gafaelfawr.tokens.VerifiedToken`
        The token.

    Returns
    -------
    headers : Dict[`str`, `str`]
        Headers to include in the response.
    """
    headers = {
        "X-Auth-Request-Client-Ip": context.request.client.host,
        "X-Auth-Request-Scopes-Accepted": " ".join(sorted(auth_config.scopes)),
        "X-Auth-Request-Scopes-Satisfy": auth_config.satisfy.name.lower(),
        "X-Auth-Request-Token-Scopes": " ".join(sorted(token.scope)),
        "X-Auth-Request-User": token.username,
        "X-Auth-Request-Uid": token.uid,
    }
    if token.email:
        headers["X-Auth-Request-Email"] = token.email

    groups_list = token.claims.get("isMemberOf", [])
    if groups_list:
        groups = ",".join([g["name"] for g in groups_list])
        headers["X-Auth-Request-Groups"] = groups

    headers["X-Auth-Request-Token"] = token.encoded

    return headers
