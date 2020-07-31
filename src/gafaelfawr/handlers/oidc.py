"""Handler for minimalist OpenID Connect (``/auth/openid``)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode

from aiohttp import web

from gafaelfawr.exceptions import InvalidRequestError, OAuthError
from gafaelfawr.handlers import routes
from gafaelfawr.handlers.decorators import authenticated_session
from gafaelfawr.handlers.util import RequestContext, validate_return_url
from gafaelfawr.storage.oidc import OIDCAuthorizationCode

if TYPE_CHECKING:
    from typing import Optional
    from urllib.parse import ParseResult

    from multidict import MultiDictProxy

    from gafaelfawr.session import Session

__all__ = ["get_login", "post_token"]


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


@routes.get("/auth/openid/login")
@authenticated_session
async def get_login(request: web.Request, session: Session) -> web.Response:
    """Authenticate the user for an OpenID Connect server flow.

    Authenticates the user and then returns an authorization code to the
    OpenID Connect client via redirect.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    session : `gafaelfawr.session.Session`
        The authentication session.

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
    except OAuthError as e:
        e.log_warning(context.logger)
        return_url = build_return_url(auth_request, **e.as_dict())
        raise web.HTTPFound(return_url)

    # Get an authorization code and return it.
    code = await oidc_server.issue_code(
        auth_request.client_id, auth_request.redirect_uri, session.handle
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
    except OAuthError as e:
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
