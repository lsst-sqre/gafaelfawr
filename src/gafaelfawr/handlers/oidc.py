"""Handler for minimalist OpenID Connect (``/auth/openid``)."""

from __future__ import annotations

import time
from typing import Any, Mapping, Optional, Union
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
from safir.models import ErrorModel

from ..dependencies.auth import AuthenticateRead, verified_oidc_token
from ..dependencies.context import RequestContext, context_dependency
from ..dependencies.return_url import parsed_redirect_uri
from ..exceptions import (
    InvalidRequestError,
    OAuthError,
    UnsupportedGrantTypeError,
)
from ..models.oidc import (
    JWKS,
    OIDCAuthorizationCode,
    OIDCConfig,
    OIDCErrorReply,
    OIDCTokenReply,
    OIDCVerifiedToken,
)
from ..models.token import TokenData

router = APIRouter(
    responses={
        404: {
            "description": "OpenID Connect server not configured",
            "model": ErrorModel,
        },
    }
)
authenticate = AuthenticateRead(
    require_session=True, redirect_if_unauthenticated=True
)

__all__ = ["get_login", "get_userinfo", "post_token"]


@router.get(
    "/auth/openid/login",
    description=(
        "Authenticates the user and then returns an authorization code to the"
        " OpenID Connect client via redirect. All errors except those from an"
        " invalid OpenID client ID are reported via a redirect back to the"
        " OpenID client application with error and error_description set."
    ),
    responses={
        307: {"description": "Redirect for authentication or back to client"},
        400: {"description": "Invalid OpenID client ID", "model": ErrorModel},
    },
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    summary="Start OIDC authentication",
    tags=["oidc"],
)
async def get_login(
    client_id: str,
    parsed_redirect_uri: ParseResult = Depends(parsed_redirect_uri),
    response_type: Optional[str] = Query(
        None,
        title="Requested response type",
        description="code is the only supported response type",
        example="code",
    ),
    scope: Optional[str] = Query(
        None,
        title="Requested token scope",
        description="openid is the only supported scope",
        example="openid",
    ),
    state: Optional[str] = Query(
        None,
        title="Opaque state cookie",
        description=(
            "Set by the client to prevent session fixation attacks. Will be"
            " returned verbatim in the response. The client should verify"
            " that it matches the code sent in the request by, for example"
            " comparing it to a code set in a cookie."
        ),
        example="omeKJ7MNv_9dKSKnVNjxMQ",
    ),
    token_data: TokenData = Depends(authenticate),
    context: RequestContext = Depends(context_dependency),
) -> RedirectResponse:
    oidc_service = context.factory.create_oidc_service()

    # Check the client_id first, since if it's not valid, we cannot continue
    # or send any errors back to the client via redirect.
    if not oidc_service.is_valid_client(client_id):
        msg = f"Unknown client_id {client_id} in OpenID Connect request"
        context.logger.warning("Invalid request", error=msg)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=[{"type": "invalid_client", "msg": msg}],
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
    code = await oidc_service.issue_code(
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


@router.post(
    "/auth/openid/token",
    description="Redeem an authorization code for a token.",
    response_model=OIDCTokenReply,
    responses={
        400: {"description": "Request was invalid", "model": OIDCErrorReply}
    },
    summary="Request OIDC token",
    tags=["oidc"],
)
async def post_token(
    response: Response,
    grant_type: str = Form(
        None,
        title="Request type",
        description="authorization_code is the only supported grant type",
        example="authorization_code",
    ),
    client_id: str = Form(
        None,
        title="ID of client",
        example="oidc-client-name",
    ),
    client_secret: str = Form(
        None,
        title="Client secret",
        example="rYTfX6h9-ilGwADfgn7KRQ",
    ),
    code: str = Form(
        None,
        title="Authorization code",
        description="The code returned from the /auth/openid/login endpoint",
        example="gc-W74I5HltJZRc0fOUAapgVQ.3T1xQQgeD063KgmNinw-tA",
    ),
    redirect_uri: str = Form(
        None,
        title="URL of client",
        description="Must match the redirect_uri in the client registration",
        example="https://example.com/",
    ),
    context: RequestContext = Depends(context_dependency),
) -> Union[OIDCTokenReply, JSONResponse]:
    oidc_service = context.factory.create_oidc_service()
    try:
        if not grant_type or not client_id or not code or not redirect_uri:
            raise InvalidRequestError("Invalid token request")
        if grant_type != "authorization_code":
            raise UnsupportedGrantTypeError(f"Invalid grant type {grant_type}")
        authorization_code = OIDCAuthorizationCode.from_str(code)
        token = await oidc_service.redeem_code(
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
    return OIDCTokenReply(
        access_token=token.encoded,
        id_token=token.encoded,
        expires_in=int(token.claims["exp"] - time.time()),
    )


@router.get(
    "/auth/oidc/userinfo",
    description="Return information about the holder of a JWT.",
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "exp": 1616993932,
                        "iat": 1614993932,
                        "isMemberOf": [
                            {"name": "g_special_users", "id": 139131}
                        ],
                        "name": "Alice Example",
                        "scope": "read:all user:token",
                        "sub": "someuser",
                        "uid": "someuser",
                        "uidNumber": 4151,
                    }
                }
            }
        },
        401: {"description": "Unauthenticated"},
        403: {"description": "Permission denied", "model": ErrorModel},
    },
    summary="Get OIDC token metadata",
    tags=["oidc"],
)
@router.get("/auth/userinfo", include_in_schema=False, tags=["oidc"])
async def get_userinfo(
    token: OIDCVerifiedToken = Depends(verified_oidc_token),
    context: RequestContext = Depends(context_dependency),
) -> Mapping[str, Any]:
    """Return information about the holder of a JWT."""
    return token.claims


@router.get(
    "/.well-known/jwks.json",
    description=(
        "Returns the key set used for JWT signatures in the format"
        " specified in RFC 7517 and RFC 7518."
    ),
    response_model=JWKS,
    response_model_exclude_none=True,
    summary="OIDC key set",
    tags=["oidc"],
)
async def get_well_known_jwks(
    context: RequestContext = Depends(context_dependency),
) -> JWKS:
    kid = context.config.issuer.kid
    return context.config.issuer.keypair.public_key_as_jwks(kid=kid)


@router.get(
    "/.well-known/openid-configuration",
    description=(
        "Returns OpenID Connect configuration information in the format"
        " specified in the OpenID Connect Discovery 1.0 specification."
    ),
    response_model=OIDCConfig,
    summary="OIDC configuration",
    tags=["oidc"],
)
async def get_well_known_openid(
    context: RequestContext = Depends(context_dependency),
) -> OIDCConfig:
    base_url = context.config.issuer.iss
    return OIDCConfig(
        issuer=context.config.issuer.iss,
        authorization_endpoint=base_url + "/auth/openid/login",
        token_endpoint=base_url + "/auth/openid/token",
        userinfo_endpoint=base_url + "/auth/openid/userinfo",
        jwks_uri=base_url + "/.well-known/jwks.json",
    )
