"""Handler for authentication and authorization checking (``/auth``)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Response,
    status,
)
from fastapi.responses import HTMLResponse

from ..auth import AuthError, AuthErrorChallenge, AuthType, generate_challenge
from ..dependencies.auth import AuthenticateRead
from ..dependencies.context import RequestContext, context_dependency
from ..exceptions import InsufficientScopeError, InvalidDelegateToError
from ..models.token import TokenData

router = APIRouter()

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

    notebook: bool
    """Whether to generate a notebook token."""

    delegate_to: Optional[str]
    """Internal service for which to create an internal token."""

    delegate_scopes: List[str]
    """List of scopes the delegated token should have."""


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
    scope: List[str] = Query(
        ...,
        title="Required scopes",
        description=(
            "If given more than once, meaning is determined by the satisfy"
            " parameter"
        ),
        example="read:all",
    ),
    satisfy: Satisfy = Query(
        Satisfy.ALL,
        title="Scope matching policy",
        description=(
            "Set to all to require all listed scopes, set to any to require"
            " any of the listed scopes"
        ),
        example="any",
    ),
    auth_type: AuthType = Query(
        AuthType.Bearer,
        title="Challenge type",
        description="Control the type of WWW-Authenticate challenge returned",
        example="basic",
    ),
    notebook: bool = Query(
        False,
        title="Request notebook token",
        description="Cannot be used with delegate_to or delegate_scope.",
        example=True,
    ),
    delegate_to: Optional[str] = Query(
        None,
        title="Service name",
        description="Create an internal token for the named service",
        example="some-service",
    ),
    delegate_scope: Optional[str] = Query(
        None,
        title="Scope of delegated token",
        description=(
            "Comma-separated list of scopes to add to the delegated token."
            " All listed scopes are implicitly added to the scope"
            " requirements for authorization."
        ),
        example="read:all,write:all",
    ),
    auth_uri: str = Depends(auth_uri),
    context: RequestContext = Depends(context_dependency),
) -> AuthConfig:
    """Construct the configuration for an authorization request.

    A shared dependency that reads various GET parameters and headers and
    converts them into an `AuthConfig` class.

    Raises
    ------
    fastapi.HTTPException
        If ``notebook`` and ``delegate_to`` are both set.
    """
    context.rebind_logger(
        auth_uri=auth_uri,
        required_scopes=sorted(scope),
        satisfy=satisfy.name.lower(),
    )
    if notebook and delegate_to:
        msg = "delegate_to cannot be set for notebook tokens"
        raise InvalidDelegateToError(msg)
    if delegate_scope:
        delegate_scopes = [s.strip() for s in delegate_scope.split(",")]
    else:
        delegate_scopes = []
    return AuthConfig(
        scopes=set(scope) | set(delegate_scopes),
        satisfy=satisfy,
        auth_type=auth_type,
        notebook=notebook,
        delegate_to=delegate_to,
        delegate_scopes=delegate_scopes,
    )


async def authenticate_with_type(
    auth_type: AuthType = Query(
        AuthType.Bearer,
        title="Challenge type",
        description="Control the type of WWW-Authenticate challenge returned",
        example="basic",
    ),
    context: RequestContext = Depends(context_dependency),
) -> TokenData:
    """Set authentication challenge based on auth_type parameter."""
    authenticate = AuthenticateRead(auth_type=auth_type, ajax_forbidden=True)
    return await authenticate(context=context)


@router.get(
    "/auth",
    description="Meant to be used as an NGINX auth_request handler",
    responses={
        401: {"description": "Unauthenticated"},
        403: {"description": "Permission denied"},
    },
    summary="Authenticate user",
    tags=["internal"],
)
async def get_auth(
    response: Response,
    auth_config: AuthConfig = Depends(auth_config),
    token_data: TokenData = Depends(authenticate_with_type),
    context: RequestContext = Depends(context_dependency),
) -> Dict[str, str]:
    """Authenticate and authorize a token.

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

    Expects the following headers to be set in the request:

    Authorization
        The JWT token. This must always be the full JWT token. The token
        should be in this  header as type ``Bearer``, but it may be type
        ``Basic`` if ``x-oauth-basic`` is the username or password.  This may
        be omitted if the user has a valid session cookie instead.

    The following headers may be set in the response:

    X-Auth-Request-Client-Ip
        The IP address of the client, as determined after parsing
        ``X-Forwarded-For`` headers.
    X-Auth-Request-Email
        The email address of the authenticated user, if known.
    X-Auth-Request-User
        The username of the authenticated user.
    X-Auth-Request-Uid
        The numeric UID of the authenticated user.
    X-Auth-Request-Groups
        The names of the groups of the authenticated user, comma-separated, if
        any.
    X-Auth-Request-Token
        If requested by ``notebook`` or ``delegate_to``, will be set to the
        delegated token.
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
    # Determine whether the request is authorized.
    if auth_config.satisfy == Satisfy.ANY:
        authorized = any([s in token_data.scopes for s in auth_config.scopes])
    else:
        authorized = all([s in token_data.scopes for s in auth_config.scopes])

    # If not authorized, log and raise the appropriate error.
    if not authorized:
        exc = InsufficientScopeError("Token missing required scope")
        raise generate_challenge(
            context, auth_config.auth_type, exc, auth_config.scopes
        )

    # Log and return the results.
    context.logger.info("Token authorized")
    headers = await build_success_headers(context, auth_config, token_data)
    response.headers.update(headers)
    return {"status": "ok"}


@router.get(
    "/auth/forbidden",
    description=(
        "This route exists to set a Cache-Control header on 403 errors so"
        " that the browser will not cache them. This route is configured as"
        " a custom error page in the ingress configuration. It takes the"
        " same parameters as the /auth route and uses them to construct an"
        " appropriate challenge. The response will set the WWW-Authenticate"
        " header."
    ),
    response_class=HTMLResponse,
    responses={403: {"description": "Permission denied"}},
    status_code=status.HTTP_403_FORBIDDEN,
    summary="Generate 403 error",
    tags=["internal"],
)
async def get_auth_forbidden(
    response: Response,
    auth_config: AuthConfig = Depends(auth_config),
    context: RequestContext = Depends(context_dependency),
) -> Response:
    """Error page for HTTP Forbidden (403) errors.

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
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        headers=headers,
        detail={"msg": error, "type": "permission_denied"},
    )


async def build_success_headers(
    context: RequestContext, auth_config: AuthConfig, token_data: TokenData
) -> Dict[str, str]:
    """Construct the headers for successful authorization.

    Parameters
    ----------
    context : `gafaelfawr.dependencies.context.RequestContext`
        The context of the incoming request.
    auth_config : `AuthConfig`
        Configuration parameters for the authorization.
    token_data : `gafaelfawr.models.token.TokenData`
        The data from the authentication token.

    Returns
    -------
    headers : Dict[`str`, `str`]
        Headers to include in the response.
    """
    headers = {
        "X-Auth-Request-Client-Ip": context.request.client.host,
        "X-Auth-Request-Scopes-Accepted": " ".join(sorted(auth_config.scopes)),
        "X-Auth-Request-Scopes-Satisfy": auth_config.satisfy.name.lower(),
        "X-Auth-Request-Token-Scopes": " ".join(sorted(token_data.scopes)),
        "X-Auth-Request-User": token_data.username,
    }
    if token_data.email:
        headers["X-Auth-Request-Email"] = token_data.email
    if token_data.uid:
        headers["X-Auth-Request-Uid"] = str(token_data.uid)
    if token_data.groups:
        groups = ",".join([g.name for g in token_data.groups])
        headers["X-Auth-Request-Groups"] = groups

    if auth_config.notebook:
        token_service = context.factory.create_token_service()
        async with context.session.begin():
            token = await token_service.get_notebook_token(
                token_data, ip_address=context.request.client.host
            )
        headers["X-Auth-Request-Token"] = str(token)
    elif auth_config.delegate_to:
        token_service = context.factory.create_token_service()
        async with context.session.begin():
            token = await token_service.get_internal_token(
                token_data,
                service=auth_config.delegate_to,
                scopes=auth_config.delegate_scopes,
                ip_address=context.request.client.host,
            )
        headers["X-Auth-Request-Token"] = str(token)

    return headers
