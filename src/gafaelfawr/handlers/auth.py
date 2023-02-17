"""Handler for authentication and authorization checking (``/auth``)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Header, Query, Response
from safir.models import ErrorModel

from ..auth import (
    clean_authorization,
    clean_cookies,
    generate_challenge,
    generate_unauthorized_challenge,
)
from ..constants import MINIMUM_LIFETIME
from ..dependencies.auth import AuthenticateRead
from ..dependencies.context import RequestContext, context_dependency
from ..exceptions import (
    InsufficientScopeError,
    InvalidDelegateToError,
    InvalidMinimumLifetimeError,
    InvalidTokenError,
)
from ..models.auth import AuthType, Satisfy
from ..models.token import TokenData
from ..slack import SlackRouteErrorHandler
from ..util import current_datetime

router = APIRouter(route_class=SlackRouteErrorHandler)

__all__ = ["get_auth"]


@dataclass
class AuthConfig:
    """Configuration for an authorization request."""

    scopes: set[str]
    """The scopes the authentication token must have."""

    satisfy: Satisfy
    """The authorization strategy if multiple scopes are required."""

    auth_type: AuthType
    """The authentication type to use in challenges."""

    notebook: bool
    """Whether to generate a notebook token."""

    delegate_to: str | None
    """Internal service for which to create an internal token."""

    delegate_scopes: set[str]
    """List of scopes the delegated token should have."""

    minimum_lifetime: timedelta | None
    """Required minimum lifetime of the token."""

    use_authorization: bool
    """Whether to put any delegated token in the ``Authorization`` header."""


def auth_uri(
    x_original_uri: Optional[str] = Header(
        None, description="URL for which authorization is being checked"
    ),
    x_original_url: Optional[str] = Header(
        None,
        description=(
            "URL for which authorization is being checked. `X-Original-URI`"
            " takes precedence if both are set."
        ),
    ),
) -> str:
    """Determine URL for which we're validating authentication.

    ``X-Original-URI`` will only be set if the auth-method annotation is set.
    That is recommended, but allow for the case where it isn't set and fall
    back on ``X-Original-URL``, which is set unconditionally.
    """
    return x_original_uri or x_original_url or "NONE"


def auth_config(
    scope: list[str] = Query(
        ...,
        title="Required scopes",
        description=(
            "If given more than once, meaning is determined by the `satisfy`"
            " parameter"
        ),
        example="read:all",
    ),
    satisfy: Satisfy = Query(
        Satisfy.ALL,
        title="Scope matching policy",
        description=(
            "Set to `all` to require all listed scopes, set to `any` to"
            " require any of the listed scopes"
        ),
        example="any",
    ),
    auth_type: AuthType = Query(
        AuthType.Bearer,
        title="Challenge type",
        description="Type of `WWW-Authenticate` challenge to return",
        example="basic",
    ),
    notebook: bool = Query(
        False,
        title="Request notebook token",
        description="Cannot be used with `delegate_to` or `delegate_scope`",
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
    minimum_lifetime: Optional[int] = Query(
        None,
        title="Required minimum lifetime",
        description=(
            "Force reauthentication if the delegated token (internal or"
            " notebook) would have a shorter lifetime, in seconds, than this"
            " parameter."
        ),
        ge=MINIMUM_LIFETIME.total_seconds(),
        example=86400,
    ),
    use_authorization: bool = Query(
        False,
        title="Put delegated token in Authorization",
        description=(
            "If true, also replace the Authorization header with any"
            " delegated token, passed as a bearer token."
        ),
        example=True,
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
    if notebook and delegate_to:
        msg = "delegate_to cannot be set for notebook tokens"
        raise InvalidDelegateToError(msg)
    scopes = set(scope)
    context.rebind_logger(
        auth_uri=auth_uri,
        required_scopes=sorted(scopes),
        satisfy=satisfy.name.lower(),
    )

    if delegate_scope:
        delegate_scopes = set(s.strip() for s in delegate_scope.split(","))
    else:
        delegate_scopes = set()
    lifetime = None
    if minimum_lifetime:
        lifetime = timedelta(seconds=minimum_lifetime)
    elif not minimum_lifetime and (notebook or delegate_to):
        lifetime = MINIMUM_LIFETIME
    return AuthConfig(
        scopes=scopes,
        satisfy=satisfy,
        auth_type=auth_type,
        notebook=notebook,
        delegate_to=delegate_to,
        delegate_scopes=delegate_scopes,
        minimum_lifetime=lifetime,
        use_authorization=use_authorization,
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
        400: {"description": "Bad request", "model": ErrorModel},
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
) -> dict[str, str]:
    """Authenticate and authorize a token.

    Notes
    -----
    The following headers may be set in the response:

    X-Auth-Request-Email
        The email address of the authenticated user, if known.
    X-Auth-Request-User
        The username of the authenticated user.
    X-Auth-Request-Token
        If requested by ``notebook`` or ``delegate_to``, will be set to the
        delegated token.
    X-Error-Status
        The real status of the error, since NGINX can only handle 401 and 403
        replies from an ``auth_request`` subhandler.
    X-Error-Body
        The real body of the error, which NGINX otherwise discards.
    WWW-Authenticate
        If the request is unauthenticated, this header will be set.
    """
    # Check if the token lifetime is long enough.
    #
    # It's awkward to do this check here, since what we have access to is the
    # lifetime of the user's authentication token, but what we need is the
    # lifetime of any delegated internal or notebook token we will pass along.
    # However, getting the latter is more expensive: we would have to do all
    # the work of creating the token, then retrieve it from Redis, and then
    # check its lifetime.
    #
    # Thankfully, we can know in advance whether the token we will create will
    # have a long enough lifetime, since we can request tokens up to the
    # lifetime of the parent token and therefore can check the required
    # lifetime against the lifetime of the parent token as long as we require
    # the child token have the required lifetime (which we do, in
    # build_success_headers).
    #
    # The only special case we need to handle is where the required lifetime
    # is too close to the maximum lifetime for new tokens, since the lifetime
    # of delegated tokens will be capped at that.  In this case, we can never
    # satisfy this request and need to raise a 422 error instead of a 401 or
    # 403 error.  We don't allow required lifetimes within MINIMUM_LIFETIME of
    # the maximum lifetime to avoid the risk of a slow infinite redirect loop
    # when the login process takes a while.
    if auth_config.minimum_lifetime:
        max_lifetime = context.config.token_lifetime - MINIMUM_LIFETIME
        if auth_config.minimum_lifetime > max_lifetime:
            minimum_lifetime_seconds = int(
                auth_config.minimum_lifetime.total_seconds()
            )
            max_lifetime_seconds = int(max_lifetime.total_seconds())
            msg = (
                f"Requested lifetime {minimum_lifetime_seconds}s longer"
                f" than maximum lifetime {max_lifetime_seconds}s"
            )
            raise InvalidMinimumLifetimeError(msg)
        if token_data.expires:
            lifetime = token_data.expires - current_datetime()
            if auth_config.minimum_lifetime > lifetime:
                raise generate_unauthorized_challenge(
                    context,
                    auth_config.auth_type,
                    InvalidTokenError("Remaining token lifetime too short"),
                    ajax_forbidden=True,
                )

    # Determine whether the request is authorized.
    if auth_config.satisfy == Satisfy.ANY:
        authorized = any([s in token_data.scopes for s in auth_config.scopes])
    else:
        authorized = all([s in token_data.scopes for s in auth_config.scopes])

    # If not authorized, log and raise the appropriate error.
    if not authorized:
        raise generate_challenge(
            context,
            auth_config.auth_type,
            InsufficientScopeError("Token missing required scope"),
            auth_config.scopes,
        )

    # Log and return the results.
    context.logger.info("Token authorized")
    headers = await build_success_headers(context, auth_config, token_data)
    for key, value in headers:
        response.headers.append(key, value)
    return {"status": "ok"}


@router.get(
    "/auth/anonymous",
    description=(
        "Intended for use as an auth-url handler for anonymous routes. No"
        " authentication is done and no authorization checks are performed,"
        " but the `Authorization` and `Cookie` headers are still reflected"
        " in the response with Gafaelfawr tokens and cookies stripped."
    ),
    summary="Filter headers for anonymous routes",
    tags=["internal"],
)
async def get_anonymous(
    response: Response,
    context: RequestContext = Depends(context_dependency),
) -> dict[str, str]:
    if "Authorization" in context.request.headers:
        raw_authorizations = context.request.headers.getlist("Authorization")
        authorizations = clean_authorization(raw_authorizations)
        for authorization in authorizations:
            response.headers.append("Authorization", authorization)
    if "Cookie" in context.request.headers:
        raw_cookies = context.request.headers.getlist("Cookie")
        cookies = clean_cookies(raw_cookies)
        for cookie in cookies:
            response.headers.append("Cookie", cookie)
    return {"status": "ok"}


async def build_success_headers(
    context: RequestContext, auth_config: AuthConfig, token_data: TokenData
) -> list[tuple[str, str]]:
    """Construct the headers for successful authorization.

    Parameters
    ----------
    context
        The context of the incoming request.
    auth_config
        Configuration parameters for the authorization.
    token_data
        The data from the authentication token.

    Returns
    -------
    headers
        Headers to include in the response.
    """
    headers = [("X-Auth-Request-User", token_data.username)]
    user_info_service = context.factory.create_user_info_service()
    user_info = await user_info_service.get_user_info_from_token(token_data)
    if user_info.email:
        headers.append(("X-Auth-Request-Email", user_info.email))

    delegated_token = None
    if auth_config.notebook:
        token_service = context.factory.create_token_service()
        async with context.session.begin():
            token = await token_service.get_notebook_token(
                token_data,
                ip_address=context.ip_address,
                minimum_lifetime=auth_config.minimum_lifetime,
            )
        delegated_token = str(token)
        headers.append(("X-Auth-Request-Token", delegated_token))
    elif auth_config.delegate_to:
        # Delegated scopes are optional; if the authenticating token doesn't
        # have the scope, it's omitted from the delegated token.  (To make it
        # mandatory, require that scope via the scope parameter as well, and
        # then the authenticating token will always have it.)  Therefore,
        # reduce the scopes of the internal token to the intersection between
        # the requested delegated scopes and the scopes of the authenticating
        # token.
        delegate_scopes = auth_config.delegate_scopes & set(token_data.scopes)
        token_service = context.factory.create_token_service()
        async with context.session.begin():
            token = await token_service.get_internal_token(
                token_data,
                service=auth_config.delegate_to,
                scopes=sorted(delegate_scopes),
                ip_address=context.ip_address,
                minimum_lifetime=auth_config.minimum_lifetime,
            )
        delegated_token = str(token)
        headers.append(("X-Auth-Request-Token", delegated_token))

    # If told to put the delegated token in the Authorization header, do that.
    # Otherwise, strip authentication tokens from the Authorization headers of
    # the incoming request and reflect the remainder back in the response.
    # Always do this with the Cookie header.  ingress-nginx can then be
    # configured to lift those headers up into the proxy request, preventing
    # the user's cookie from being passed down to the protected application.
    if auth_config.use_authorization:
        if delegated_token:
            headers.append(("Authorization", f"Bearer {delegated_token}"))
    elif "Authorization" in context.request.headers:
        raw_authorizations = context.request.headers.getlist("Authorization")
        authorizations = clean_authorization(raw_authorizations)
        if authorizations:
            headers.extend(("Authorization", v) for v in authorizations)
    if "Cookie" in context.request.headers:
        raw_cookies = context.request.headers.getlist("Cookie")
        cookies = clean_cookies(raw_cookies)
        if cookies:
            headers.extend(("Cookie", v) for v in cookies)

    return headers
