"""Handler for minimalist OpenID Connect (``/auth/openid``)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from functools import wraps
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlparse

from aiohttp import web
from aiohttp_session import get_session

from gafaelfawr.exceptions import (
    InvalidRequestError,
    InvalidTokenException,
    OIDCServerError,
)
from gafaelfawr.handlers import routes
from gafaelfawr.handlers.util import (
    AuthChallenge,
    AuthError,
    AuthType,
    RequestContext,
    validate_return_url,
    verify_token,
)
from gafaelfawr.session import SessionHandle
from gafaelfawr.storage.oidc import OIDCAuthorizationCode

if TYPE_CHECKING:
    from typing import Awaitable, Callable, Optional
    from urllib.parse import ParseResult

    from multidict import MultiDictProxy

    from gafaelfawr.tokens import VerifiedToken

    Route = Callable[[web.Request], Awaitable[web.Response]]
    AuthenticatedRoute = Callable[
        [web.Request, VerifiedToken], Awaitable[web.Response]
    ]

__all__ = ["get_login", "get_userinfo", "post_token"]


@dataclass
class AuthenticationRequest:
    """Represents an authentication request to the login endpoint.

    See `Authentication Request
    <https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest>`__
    in the OpenID Connect specification.
    """

    scope: str
    """The requested scope."""

    response_type: str
    """The requested response type."""

    client_id: str
    """The ID of the client requesting user authentication."""

    redirect_uri: str
    """Redirection URI to which the response will be sent."""

    parsed_redirect_uri: ParseResult
    """The parsed version of redirect_uri."""

    state: Optional[str]
    """An optional opaque value to maintain state across the request."""

    @classmethod
    def from_context(cls, context: RequestContext) -> AuthenticationRequest:
        """Parse query parameters into an authentication request.

        The client_id is not validated by this method, since this needs to
        happen before any error is reported via redirect.  This method assumes
        this has already been done.

        Parameters
        ----------
        context : `gafaelfawr.handlers.util.RequestContext`
            The incoming request context.

        Returns
        -------
        request : `AuthenticationRequest`
            The parsed authentication request.

        Raises
        ------
        aiohttp.web.HTTPException
            The request is invalid in a way that prevents redirecting back to
            the client, so the error should be reported directly to the user.
        gafaelfawr.exceptions.InvalidRequestError
            The request is invalid in a way that can be reported back to the
            caller.
        """
        scope = context.request.query.get("scope")
        response_type = context.request.query.get("response_type")
        client_id = context.request.query["client_id"]
        state = context.request.query.get("state")
        redirect_uri = context.request.query.get("redirect_uri")
        parsed_redirect_uri = validate_return_url(context, redirect_uri)

        # Validate the rest of the request.
        if response_type != "code":
            msg = "code is the only supported response_type"
            raise InvalidRequestError(msg)
        if scope != "openid":
            raise InvalidRequestError("openid is the only supported scope")

        # Create and return the object.
        return cls(
            scope=scope,
            response_type=response_type,
            client_id=client_id,
            redirect_uri=redirect_uri,
            parsed_redirect_uri=parsed_redirect_uri,
            state=state,
        )


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


def parse_authorization(context: RequestContext) -> str:
    """Find a JWT in the Authorization header.

    Requires the ``Bearer`` authorization type.  Rebinds the logging context
    to include the source of the token, if one is found.

    Parameters
    ----------
    context : `gafaelfawr.handlers.util.RequestContext`
        The context of the incoming request.

    Returns
    -------
    handle_or_token : `str` or `None`
        The handle or token if one was found, otherwise None.

    Raises
    ------
    gafaelfawr.exceptions.InvalidRequestError
        If no token is present or the Authorization header cannot be parsed.
    """
    header = context.request.headers.get("Authorization")
    if not header:
        msg = "No authentication token found"
        context.logger.warning(msg)
        challenge = AuthChallenge(AuthType.Bearer, context.config.realm)
        headers = {"WWW-Authenticate": challenge.as_header()}
        raise web.HTTPUnauthorized(headers=headers, reason=msg, text=msg)

    if " " not in header:
        raise InvalidRequestError("malformed Authorization header")
    auth_type, auth_blob = header.split(" ")
    if auth_type.lower() == "bearer":
        context.rebind_logger(token_source="bearer")
        return auth_blob
    else:
        msg = f"unkonwn Authorization type {auth_type}"
        raise InvalidRequestError(msg)


@routes.get("/auth/openid/login")
async def get_login(request: web.Request) -> web.Response:
    """Authenticate the user for an OpenID Connect server flow.

    Authenticates the user and then returns an authorization code to the
    OpenID Connect client via redirect.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response (not used).

    Raises
    ------
    aiohttp.web.HTTPException
        The redirect or exception.
    """
    context = RequestContext.from_request(request)
    oidc_server = context.factory.create_oidc_server()

    # Check the client_id first, since if it is not valid, we cannot continue
    # or send any errors back to the client via redirect.
    client_id = request.query.get("client_id")
    if not client_id:
        msg = "Missing client_id in OpenID Connect request"
        context.logger.warning("Invalid request", error=msg)
        raise web.HTTPBadRequest(reason=msg, text=msg)
    if not oidc_server.is_valid_client(client_id):
        msg = "Unknown client_id {client_id} in OpenID Connect request"
        context.logger.warning("Invalid request", error=msg)
        raise web.HTTPBadRequest(reason=msg, text=msg)

    # Parse the authentication request.
    try:
        auth_request = AuthenticationRequest.from_context(context)
    except OIDCServerError as e:
        e.log_warning(context.logger)
        return_url = build_return_url(auth_request, **e.as_dict())
        raise web.HTTPFound(return_url)

    # Get the user's session.  If they are not already authenticated, send
    # them to the login endpoint.
    session = await get_session(request)
    auth_session = None
    if "handle" in session:
        handle = SessionHandle.from_str(session["handle"])
        session_store = context.factory.create_session_store()
        auth_session = await session_store.get_session(handle)
    if not auth_session:
        login_base_url = str(request.app.router["login"].url_for())
        login_url = urlparse(login_base_url)._replace(
            query=urlencode({"rd": str(request.url)})
        )
        context.logger.info("Redirecting user for authentication")
        raise web.HTTPFound(login_url.geturl())
    context.rebind_logger(
        token=auth_session.token.jti,
        user=auth_session.token.username,
        scope=" ".join(sorted(auth_session.token.scope)),
    )

    # Get an authorization code and return it.
    code = await oidc_server.issue_code(
        auth_request.client_id, auth_request.redirect_uri, handle
    )
    return_url = build_return_url(auth_request, code=code.encode())
    context.logger.info("Returned OpenID Connect authorization code")
    raise web.HTTPFound(return_url)


def build_return_url(
    auth_request: AuthenticationRequest, **params: str
) -> str:
    """Construct a return URL for a redirect.

    Parameters
    ----------
    auth_request : `AuthenticationRequest`
        The authentication request from the client.
    **params : `str`
        Additional parameters to add to that URI to create the return URL.

    Returns
    -------
    return_url : `str`
        The return URL to which the user should be redirected.
    """
    redirect_uri = auth_request.parsed_redirect_uri
    query = parse_qsl(redirect_uri.query) if redirect_uri.query else []
    query.extend(params.items())
    if auth_request.state:
        query.append(("state", auth_request.state))
    return_url = redirect_uri._replace(query=urlencode(query))
    return return_url.geturl()


def get_form_value(data: MultiDictProxy, key: str) -> Optional[str]:
    """Retrieve a string from form data.

    This handles encoding issues and returns `None` if one of the fields is
    unexpectedly a file upload.

    Parameters
    ----------
    data : `multidict.MultiDictProxy`
        The form data.
    key : `str`
        The field to extract.

    Returns
    -------
    value : `str` or `None`
        The value, or `None` if this field wasn't present or if it was a file
        upload.
    """
    value = data.get(key)
    if not value:
        return None
    elif isinstance(value, str):
        return value
    elif isinstance(value, bytes):
        return value.decode()
    else:
        return None


@routes.post("/auth/openid/token")
async def post_token(request: web.Request) -> web.Response:
    """Redeem an authorization code for a token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    context = RequestContext.from_request(request)
    data = await request.post()
    grant_type = get_form_value(data, "grant_type")
    client_id = get_form_value(data, "client_id")
    client_secret = get_form_value(data, "client_secret")
    code = get_form_value(data, "code")
    redirect_uri = get_form_value(data, "redirect_uri")

    # Check the request parameters.
    if not grant_type or not client_id or not code or not redirect_uri:
        msg = "Invalid token request"
        context.logger.warning("Invalid request", error=msg)
        error = {
            "error": "invalid_request",
            "error_description": msg,
        }
        return web.json_response(error, status=400)
    if grant_type != "authorization_code":
        msg = f"Invalid grant type {grant_type}"
        context.logger.warning("Invalid request", error=msg)
        error = {
            "error": "unsupported_grant_type",
            "error_description": msg,
        }
        return web.json_response(error, status=400)

    # Redeem the provided code for a token.
    oidc_server = context.factory.create_oidc_server()
    try:
        authorization_code = OIDCAuthorizationCode.from_str(code)
        token = await oidc_server.redeem_code(
            client_id, client_secret, redirect_uri, authorization_code,
        )
    except OIDCServerError as e:
        e.log_warning(context.logger)
        return web.json_response(e.as_dict, status=400)

    # Log the token redemption.
    context.logger.info(
        "Retrieved token for user %s via OpenID Connect",
        token.username,
        user=token.username,
        token=token.jti,
        scope=" ".join(sorted(token.scope)),
    )

    # Return the token to the caller.
    response = {
        "access_token": token.encoded,
        "token_type": "Bearer",
        "expires_in": token.claims["exp"] - time.time(),
        "id_token": token.encoded,
    }
    return web.json_response(response)


@routes.get("/auth/openid/userinfo")
@authenticated_jwt
async def get_userinfo(
    request: web.Request, token: VerifiedToken
) -> web.Response:
    """Return information about the holder of a JWT.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    token : `gafaelfawr.tokens.VerifiedToken`
        The token of the authenticated user.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    context = RequestContext.from_request(request)
    context.logger.info("Returned user information")
    return web.json_response(token.claims)
