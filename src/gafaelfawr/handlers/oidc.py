"""Handler for minimalist OpenID Connect (``/auth/openid``)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any
from urllib.parse import parse_qsl, urlencode, urlparse

from fastapi import APIRouter, Depends, Form, Query, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from safir.models import ErrorModel
from safir.slack.webhook import SlackRouteErrorHandler

from ..auth import generate_challenge
from ..dependencies.auth import AuthenticateRead
from ..dependencies.context import RequestContext, context_dependency
from ..exceptions import InvalidRequestError, InvalidTokenError, OAuthError
from ..models.auth import AuthType
from ..models.oidc import (
    JWKS,
    OIDCConfig,
    OIDCErrorReply,
    OIDCScope,
    OIDCTokenReply,
)
from ..models.token import TokenData, TokenType

__all__ = ["router"]

router = APIRouter(
    responses={
        404: {
            "description": "OpenID Connect server not configured",
            "model": ErrorModel,
        },
    },
    route_class=SlackRouteErrorHandler,
)
authenticate = AuthenticateRead(
    require_session=True, redirect_if_unauthenticated=True
)
authenticate_token = AuthenticateRead(require_bearer_token=True)


@router.get(
    "/auth/openid/login",
    description=(
        "Authenticates the user and then returns an authorization code to the"
        " OpenID Connect client via redirect. All errors except those from an"
        " invalid OpenID client ID are reported via a redirect back to the"
        " protected service with error and error_description set."
    ),
    response_class=RedirectResponse,
    responses={
        307: {"description": "Redirect for authentication or back to client"},
        400: {"description": "Invalid OpenID client ID", "model": ErrorModel},
    },
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    summary="Start OIDC authentication",
    tags=["oidc"],
)
async def get_login(
    *,
    client_id: Annotated[
        str,
        Query(
            title="Client ID",
            description="Identifier of the registered OpenID Client",
            examples=["https://example.org/chronograf"],
        ),
    ],
    redirect_uri: Annotated[
        str,
        Query(
            title="URL to return to",
            description=(
                "User is sent here after successful or failed authentication"
            ),
            examples=["https://example.com/"],
        ),
    ],
    response_type: Annotated[
        str | None,
        Query(
            title="Requested response type",
            description="code is the only supported response type",
            examples=["code"],
        ),
    ] = None,
    scope: Annotated[
        str | None,
        Query(
            title="Requested token scopes",
            description=(
                "Token scopes separated by spaces. The openid scope is"
                " required, and profile and email scopes are supported. All"
                " other scopes are ignored."
            ),
            examples=["openid", "openid profile email"],
        ),
    ] = None,
    state: Annotated[
        str | None,
        Query(
            title="Opaque state cookie",
            description=(
                "Set by the client to prevent session fixation attacks. Will"
                " be returned verbatim in the response. The client should"
                " verify that it matches the code sent in the request by, for"
                " example comparing it to a code set in a cookie."
            ),
            examples=["omeKJ7MNv_9dKSKnVNjxMQ"],
        ),
    ] = None,
    nonce: Annotated[
        str | None,
        Query(
            title="ID token nonce",
            description=(
                "Nonce to include in ID tokens to mitigate replay attacks or"
                " associate an ID token with a client session"
            ),
            examples=["5Ndm2AFSZ6dN6Gt-Iu6lng"],
        ),
    ] = None,
    token_data: Annotated[TokenData, Depends(authenticate)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> str:
    context.rebind_logger(return_uri=redirect_uri)
    oidc_service = context.factory.create_oidc_service()

    # Check the client_id and redirect_uri first, since if either of them are
    # not valid, we cannot continue or send any errors back to the client via
    # redirect.
    oidc_service.validate_client(client_id, redirect_uri)

    # Parse the authentication request.
    error = None
    if not response_type:
        error = "Missing response_type parameter"
    elif response_type != "code":
        error = "code is the only supported response_type"
    elif not scope:
        error = "Missing scope parameter"
    else:
        scopes = OIDCScope.parse_scopes(scope)
        if OIDCScope.openid not in scopes:
            error = "Only OpenID Connect supported (openid not in scope)"
    if error:
        e = InvalidRequestError(error)
        context.logger.warning("%s", e.message, error=str(e))
        return build_return_url(
            redirect_uri,
            state=state,
            error=e.error,
            error_description=str(e),
        )

    # Get an authorization code and return it.
    code = await oidc_service.issue_code(
        client_id=client_id,
        redirect_uri=redirect_uri,
        token=token_data.token,
        scopes=scopes,
        nonce=nonce,
    )
    return_url = build_return_url(redirect_uri, state=state, code=str(code))
    context.logger.info("Returned OpenID Connect authorization code")
    return return_url


def build_return_url(redirect_uri: str, **params: str | None) -> str:
    """Construct a return URL for a redirect.

    Parameters
    ----------
    redirect_uri
        Return URI from the client.
    **params
        Additional parameters to add to that URI to create the return URL.
        Any parameters set to `None` will be ignored.

    Returns
    -------
    str
        The return URL to which the user should be redirected.
    """
    parsed_uri = urlparse(redirect_uri)
    query = parse_qsl(parsed_uri.query) if parsed_uri.query else []
    query.extend((k, v) for (k, v) in params.items() if v is not None)
    return_url = parsed_uri._replace(query=urlencode(query))
    return return_url.geturl()


@router.post(
    "/auth/openid/token",
    description="Redeem an authorization code for a token",
    response_model=OIDCTokenReply,
    responses={
        400: {"description": "Request was invalid", "model": OIDCErrorReply}
    },
    summary="Request OIDC token",
    tags=["oidc"],
)
async def post_token(
    *,
    grant_type: Annotated[
        str | None,
        Form(
            title="Request type",
            description=(
                "`authorization_code` is the only supported grant type"
            ),
            examples=["authorization_code"],
        ),
    ] = None,
    client_id: Annotated[
        str | None,
        Form(
            title="ID of client",
            examples=["https://data.lsst.cloud/oidc-client"],
        ),
    ] = None,
    client_secret: Annotated[
        str | None,
        Form(
            title="Client secret",
            examples=["rYTfX6h9-ilGwADfgn7KRQ"],
        ),
    ] = None,
    code: Annotated[
        str | None,
        Form(
            title="Authorization code",
            description="Code returned from the `/auth/openid/login` endpoint",
            examples=["gc-W74I5HltJZRc0fOUAapgVQ.3T1xQQgeD063KgmNinw-tA"],
        ),
    ] = None,
    redirect_uri: Annotated[
        str | None,
        Form(
            title="URL of client",
            description="Must match `redirect_uri` in the client registration",
            examples=["https://example.com/"],
        ),
    ] = None,
    context: Annotated[RequestContext, Depends(context_dependency)],
    response: Response,
) -> OIDCTokenReply | JSONResponse:
    oidc_service = context.factory.create_oidc_service()
    async with context.session.begin():
        try:
            reply = await oidc_service.redeem_code(
                grant_type=grant_type,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                code=code,
                ip_address=context.ip_address,
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

    # Return the token to the caller.  The headers are mandated by RFC 6749.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return reply


@router.get(
    "/auth/openid/userinfo",
    description="Return information about the holder of a JWT",
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "email": "someone@example.com",
                        "name": "Alice Example",
                        "preferred_username": "someuser",
                        "sub": "someuser",
                    }
                }
            }
        },
        401: {"description": "Unauthenticated"},
        403: {"description": "Permission denied", "model": ErrorModel},
    },
    summary="Get user metadata from OIDC token",
    tags=["oidc"],
)
async def get_userinfo(
    *,
    token_data: Annotated[TokenData, Depends(authenticate_token)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> Mapping[str, Any]:
    if token_data.token_type != TokenType.oidc:
        msg = f"Token of type {token_data.token_type.value} not allowed"
        exc = InvalidTokenError(msg)
        raise generate_challenge(context, AuthType.Bearer, exc)
    oidc_service = context.factory.create_oidc_service()
    return await oidc_service.token_to_userinfo_claims(token_data)


@router.get(
    "/.well-known/jwks.json",
    description=(
        "Returns the key set used for JWT signatures in the format"
        " specified in"
        " [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) and"
        " [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)"
    ),
    response_model=JWKS,
    response_model_exclude_none=True,
    summary="OIDC key set",
    tags=["oidc"],
)
async def get_well_known_jwks(
    *,
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> JWKS:
    oidc_server = context.factory.create_oidc_service()
    return oidc_server.get_jwks()


@router.get(
    "/.well-known/openid-configuration",
    description=(
        "Returns OpenID Connect configuration information in the format"
        " specified in the"
        " [OpenID Connect Discovery 1.0]"
        "(https://openid.net/specs/openid-connect-discovery-1_0.html)"
        " specification."
    ),
    response_model=OIDCConfig,
    summary="OIDC configuration",
    tags=["oidc"],
)
async def get_well_known_openid(
    *,
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> OIDCConfig:
    oidc_server = context.factory.create_oidc_service()
    return oidc_server.get_openid_configuration()
