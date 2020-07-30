"""Handler for minimalist OpenID Connect (``/auth/openid``)."""

from __future__ import annotations

import time
from functools import wraps
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlparse

from aiohttp import web
from aiohttp_session import get_session

from gafaelfawr.exceptions import (
    InvalidRequestException,
    InvalidTokenException,
    OIDCServerError,
    UnauthorizedClientException,
)
from gafaelfawr.handlers import routes
from gafaelfawr.handlers.util import (
    AuthChallenge,
    AuthError,
    AuthType,
    RequestContext,
    verify_token,
)
from gafaelfawr.session import SessionHandle
from gafaelfawr.storage.oidc import OIDCAuthorizationCode

if TYPE_CHECKING:
    from typing import Awaitable, Callable, Optional

    from multidict import MultiDictProxy

    from gafaelfawr.tokens import VerifiedToken

    Route = Callable[[web.Request], Awaitable[web.Response]]
    AuthenticatedRoute = Callable[
        [web.Request, VerifiedToken], Awaitable[web.Response]
    ]

__all__ = ["get_login", "get_userinfo", "post_token"]


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
        except InvalidRequestException as e:
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
        context.logger = context.logger.bind(
            token=token.jti,
            user=token.username,
            scope=" ".join(sorted(token.scope)),
        )
        request["safir/logger"] = context.logger

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
    gafaelfawr.exceptions.InvalidRequestException
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
        raise InvalidRequestException("malformed Authorization header")
    auth_type, auth_blob = header.split(" ")
    if auth_type.lower() == "bearer":
        context.logger = context.logger.bind(token_source="bearer")
        return auth_blob
    else:
        msg = f"unkonwn Authorization type {auth_type}"
        raise InvalidRequestException(msg)


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

    # Get the parameters from the login request.
    response_type = request.query.get("response_type")
    scope = request.query.get("scope")
    client_id = request.query.get("client_id")
    state = request.query.get("state")
    return_url = request.query.get("redirect_uri")
    if response_type != "code" or not client_id or not scope:
        msg = "Malformed OpenID Connect login request"
        context.logger.warning("Invalid request", error=msg)
        raise web.HTTPBadRequest(reason=msg, text=msg)
    if scope != "openid":
        msg = "Scope of login request must be openid"
        context.logger.warning("Invalid request", error=msg)
        raise web.HTTPBadRequest(reason=msg, text=msg)

    # Parse and validate the return URL, including that it's at the same host
    # as this request.
    if not return_url:
        msg = "No destination URL specified"
        context.logger.warning("Invalid request", error=msg)
        raise web.HTTPBadRequest(reason=msg, text=msg)
    context.logger = context.logger.bind(return_url=return_url)
    parsed_return_url = urlparse(return_url)
    if parsed_return_url.hostname != request.url.raw_host:
        msg = f"Redirect URL not at {request.host}"
        context.logger.warning("Invalid request", error=msg)
        raise web.HTTPBadRequest(reason=msg, text=msg)
    if parsed_return_url.query:
        return_query = parse_qsl(parsed_return_url.query)
    else:
        return_query = []

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

    # Get an authorization code, returning an error via redirect if needed.
    oidc_server = context.factory.create_oidc_server()
    try:
        code = await oidc_server.issue_code(client_id, return_url, handle)
    except UnauthorizedClientException as e:
        query = [
            ("error", "unauthorized_client"),
            ("error_description", str(e)),
        ]
        if state:
            query.append(("state", state))
        return_query.extend(query)
        error_url = parsed_return_url._replace(query=urlencode(return_query))
        context.logger.warning(
            "Unauthorized OpenID Connect client", error=str(e)
        )
        raise web.HTTPFound(error_url.geturl())

    # Return the authorization code to the client via redirect.
    query = [("code", code.encode())]
    if state:
        query.append(("state", state))
    return_query.extend(query)
    redirect_url = parsed_return_url._replace(query=urlencode(return_query))
    context.logger.info("Returned OpenID Connect authorization code")
    raise web.HTTPFound(redirect_url.geturl())


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
