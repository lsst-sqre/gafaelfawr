"""Handler for minimalist OpenID Connect (``/auth/openid``)."""

from __future__ import annotations

import time
from typing import Optional, Union
from urllib.parse import ParseResult, parse_qsl, urlencode

from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
    Query,
    Response,
    status,
)
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from gafaelfawr.dependencies.auth import authenticate_session
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.dependencies.return_url import parsed_redirect_uri
from gafaelfawr.exceptions import (
    InvalidRequestError,
    OAuthError,
    UnsupportedGrantTypeError,
)
from gafaelfawr.models.oidc import OIDCAuthorizationCode
from gafaelfawr.models.token import TokenData

router = APIRouter()

__all__ = ["get_login", "post_token"]


@router.get("/auth/openid/login")
async def get_login(
    client_id: str,
    parsed_redirect_uri: ParseResult = Depends(parsed_redirect_uri),
    response_type: Optional[str] = Query(None),
    scope: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    token_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> RedirectResponse:
    """Authenticate the user for an OpenID Connect server flow.

    Authenticates the user and then returns an authorization code to the
    OpenID Connect client via redirect.
    """
    oidc_server = context.factory.create_oidc_server()

    # Check the client_id first, since if it's not valid, we cannot continue
    # or send any errors back to the client via redirect.
    if not oidc_server.is_valid_client(client_id):
        msg = f"Unknown client_id {client_id} in OpenID Connect request"
        context.logger.warning("Invalid request", error=msg)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"type": "invalid_client", "msg": msg},
        )

    # Parse the authentication request.
    error = None
    if not response_type:
        error = "Missing response_type parameter"
    elif response_type != "code":
        error = "code is the only supported response_type"
    elif not scope:
        error = "Missing scope parameter"
    elif scope != "openid":
        error = "openid is the only supported scope"
    if error:
        e = InvalidRequestError(error)
        context.logger.warning("%s", e.message, error=str(e))
        return_url = build_return_url(
            parsed_redirect_uri,
            state=state,
            error=e.error,
            error_description=str(e),
        )
        return RedirectResponse(return_url)

    # Get an authorization code and return it.
    code = await oidc_server.issue_code(
        client_id, parsed_redirect_uri.geturl(), token_data.token
    )
    return_url = build_return_url(
        parsed_redirect_uri, state=state, code=str(code)
    )
    context.logger.info("Returned OpenID Connect authorization code")
    return RedirectResponse(return_url)


def build_return_url(
    redirect_uri: ParseResult, **params: Optional[str]
) -> str:
    """Construct a return URL for a redirect.

    Parameters
    ----------
    redirect_uri : `urllib.parse.ParseResult`
        The parsed return URI from the client.
    **params : `str` or `None`
        Additional parameters to add to that URI to create the return URL.
        Any parameters set to `None` will be ignored.

    Returns
    -------
    return_url : `str`
        The return URL to which the user should be redirected.
    """
    query = parse_qsl(redirect_uri.query) if redirect_uri.query else []
    query.extend(((k, v) for (k, v) in params.items() if v is not None))
    return_url = redirect_uri._replace(query=urlencode(query))
    return return_url.geturl()


class TokenReply(BaseModel):
    access_token: str
    id_token: str
    expires_in: int
    token_type: str = "Bearer"


class ErrorReply(BaseModel):
    error: str
    error_description: str


@router.post(
    "/auth/openid/token",
    response_model=TokenReply,
    responses={status.HTTP_400_BAD_REQUEST: {"model": ErrorReply}},
)
async def post_token(
    response: Response,
    grant_type: str = Form(None),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    context: RequestContext = Depends(context_dependency),
) -> Union[TokenReply, JSONResponse]:
    """Redeem an authorization code for a token."""
    # Redeem the provided code for a token.
    oidc_server = context.factory.create_oidc_server()
    try:
        if not grant_type or not client_id or not code or not redirect_uri:
            raise InvalidRequestError("Invalid token request")
        if grant_type != "authorization_code":
            raise UnsupportedGrantTypeError(f"Invalid grant type {grant_type}")
        authorization_code = OIDCAuthorizationCode.from_str(code)
        token = await oidc_server.redeem_code(
            client_id, client_secret, redirect_uri, authorization_code
        )
    except OAuthError as e:
        context.logger.warning("%s", e.message, error=str(e))
        content = {
            "error": e.error,
            "error_description": e.message if e.hide_error else str(e),
        }
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST, content=content
        )

    # Log the token redemption.
    context.logger.info(
        "Retrieved token for user %s via OpenID Connect",
        token.username,
        user=token.username,
        token=token.jti,
    )

    # Return the token to the caller.  The headers are mandated by RFC 6749.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return TokenReply(
        access_token=token.encoded,
        id_token=token.encoded,
        expires_in=int(token.claims["exp"] - time.time()),
    )
