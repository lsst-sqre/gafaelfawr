"""Handlers for routes intended for use only by the ingress.

These routes implement the NGINX ``auth_request`` API and should only be
accessed by the NGINX ingress. They should not be expoed to users via a
Kubernetes ``Ingress`` and instead should be accessed using cluster-internal
URLs.
"""

from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import Annotated
from urllib.parse import urlparse

import sentry_sdk
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from limits import RateLimitItemPerMinute
from safir.datetime import current_datetime, format_datetime_for_logging
from safir.models import ErrorModel
from safir.pydantic import SecondsTimedelta
from safir.slack.webhook import SlackRouteErrorHandler

from ..auth import (
    clean_authorization,
    clean_cookies,
    generate_challenge,
    generate_unauthorized_challenge,
)
from ..constants import MINIMUM_LIFETIME
from ..dependencies.auth import AuthenticateRead
from ..dependencies.context import RequestContext, context_dependency
from ..events import AuthBotEvent, AuthUserEvent, RateLimitEvent
from ..exceptions import (
    DisallowedCORSRequestError,
    ExternalUserInfoError,
    InsufficientScopeError,
    InvalidDelegateToError,
    InvalidMinimumLifetimeError,
    InvalidServiceError,
    InvalidTokenError,
    OptionsNotSupportedError,
)
from ..models.auth import AuthType, Satisfy
from ..models.token import TokenData
from ..models.userinfo import RateLimitStatus, UserInfo
from ..util import is_bot_user

router = APIRouter(route_class=SlackRouteErrorHandler)

__all__ = ["router"]


@dataclass
class AuthConfig:
    """Configuration for an authorization request."""

    allow_options: bool
    """Whether to allow non-CORS ``OPTIONS`` requests."""

    auth_type: AuthType
    """The authentication type to use in challenges."""

    auth_uri: str
    """URL for which Gafaelfawr is processing an authorization request."""

    delegate_scopes: set[str]
    """List of scopes the delegated token should have."""

    delegate_to: str | None
    """Internal service for which to create an internal token."""

    minimum_lifetime: timedelta | None
    """Required minimum lifetime of the token."""

    notebook: bool
    """Whether to generate a notebook token."""

    only_services: set[str] | None
    """Restrict access to tokens issued to one of the listed services."""

    satisfy: Satisfy
    """The authorization strategy if multiple scopes are required."""

    scopes: set[str]
    """The scopes the authentication token must have."""

    service: str | None
    """Name of the service for which authorization is being checked."""

    use_authorization: bool
    """Whether to put any delegated token in the ``Authorization`` header."""

    user_domain: bool
    """Restrict access to the username matching the last hostname component."""

    username: str | None
    """Restrict access to the ingress to only this username."""


def auth_config(
    *,
    allow_options: Annotated[
        bool,
        Query(
            title="Allow OPTIONS",
            description="Whether to allow non-CORS OPTIONS requests",
            examples=["true"],
        ),
    ] = False,
    auth_type: Annotated[
        AuthType,
        Query(
            title="Challenge type",
            description="Type of `WWW-Authenticate` challenge to return",
            examples=["basic"],
        ),
    ] = AuthType.Bearer,
    delegate_to: Annotated[
        str | None,
        Query(
            title="Service name",
            description="Create an internal token for the named service",
            examples=["some-service"],
        ),
    ] = None,
    delegate_scope: Annotated[
        list[str] | None,
        Query(
            title="Scope of delegated token",
            description=(
                "Scopes to add to the delegated token if present in the"
                " token used for authentication"
            ),
            examples=[["read:all", "write:all"]],
        ),
    ] = None,
    minimum_lifetime: Annotated[
        SecondsTimedelta | None,
        Query(
            title="Required minimum lifetime",
            description=(
                "Force reauthentication if the delegated token (internal or"
                " notebook) would have a shorter lifetime, in seconds, than"
                " this parameter."
            ),
            ge=MINIMUM_LIFETIME,
            examples=[86400],
        ),
    ] = None,
    notebook: Annotated[
        bool,
        Query(
            title="Request notebook token",
            description=(
                "Cannot be used with `delegate_to` or `delegate_scope`"
            ),
            examples=[True],
        ),
    ] = False,
    only_service: Annotated[
        list[str] | None,
        Query(
            title="Restrict to service",
            description=(
                "Restrict access to only tokens issued to the named service,"
                " in addition to any other constraints. This will prevent"
                " users from accessing the service directly, but allow the"
                " named service to access it on their behalf. May be given"
                " multiple times to allow multiple services."
            ),
            examples=["portal", "vo-cutouts"],
        ),
    ] = None,
    satisfy: Annotated[
        Satisfy,
        Query(
            title="Scope matching policy",
            description=(
                "Set to `all` to require all listed scopes, set to `any` to"
                " require any of the listed scopes"
            ),
            examples=["any"],
        ),
    ] = Satisfy.ALL,
    scope: Annotated[
        list[str] | None,
        Query(
            title="Required scopes",
            description=(
                "If given more than once, meaning is determined by the"
                " `satisfy` parameter"
            ),
            examples=[["read:all"]],
        ),
    ] = None,
    service: Annotated[
        str | None,
        Query(
            title="Service",
            description="Name of the underlying service",
            examples=["tap"],
        ),
    ] = None,
    use_authorization: Annotated[
        bool,
        Query(
            title="Put delegated token in Authorization",
            description=(
                "If true, also replace the Authorization header with any"
                " delegated token, passed as a bearer token."
            ),
            examples=[True],
        ),
    ] = False,
    user_domain: Annotated[
        bool,
        Query(
            title="Enforce per-user hostnames",
            description=(
                "Restrict access to only the user whose username matches the"
                " last component of the request hostname."
            ),
            examples=[True],
        ),
    ] = False,
    username: Annotated[
        str | None,
        Query(
            title="Restrict to username",
            description=(
                "Only allow access to this ingress by the user with the given"
                " username. All other users, regardless of scopes, will"
                " receive 403 errors. The user must still meet the scope"
                " requirements for the ingress."
            ),
            examples=["rra"],
        ),
    ] = None,
    x_original_url: Annotated[str, Header()],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> AuthConfig:
    """Construct the configuration for an authorization request.

    A shared dependency that reads various GET parameters and headers and
    converts them into an `AuthConfig` class.

    Raises
    ------
    InvalidDelegateToError
        Raised if ``notebook`` and ``delegate_to`` are both set.
    InvalidServiceError
        Raised if ``service`` is set to something different than
        ``delegate_to``.
    """
    if notebook and delegate_to:
        msg = "delegate_to cannot be set for notebook tokens"
        raise InvalidDelegateToError(msg)
    if service and delegate_to and service != delegate_to:
        msg = "service must be the same as delegate_to"
        raise InvalidServiceError(msg)
    scopes = set(scope) if scope else set()
    context.rebind_logger(
        auth_uri=x_original_url,
        required_scopes=sorted(scopes),
        satisfy=satisfy.name.lower(),
        service=service,
    )
    if only_service:
        context.rebind_logger(only_services=only_service)
    if username:
        context.rebind_logger(required_user=username)

    if not minimum_lifetime and (notebook or delegate_to):
        minimum_lifetime = MINIMUM_LIFETIME
    return AuthConfig(
        allow_options=allow_options,
        auth_type=auth_type,
        auth_uri=x_original_url,
        delegate_scopes=set(delegate_scope) if delegate_scope else set(),
        delegate_to=delegate_to,
        minimum_lifetime=minimum_lifetime,
        only_services=set(only_service) if only_service else None,
        notebook=notebook,
        satisfy=satisfy,
        scopes=scopes,
        service=service,
        use_authorization=use_authorization,
        user_domain=user_domain,
        username=username,
    )


async def authenticate_with_type(
    *,
    allow_cookies: Annotated[
        bool,
        Query(
            title="Whether to allow cookies",
            description="Set to false to disallow cookie authentication",
            examples=[False],
        ),
    ] = True,
    auth_type: Annotated[
        AuthType,
        Query(
            title="Challenge type",
            description=(
                "Control the type of WWW-Authenticate challenge returned"
            ),
            examples=["basic"],
        ),
    ] = AuthType.Bearer,
    x_original_method: Annotated[str, Header(description="Request method")],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> TokenData | None:
    """Handle ``OPTIONS`` and user authentication.

    If the request method is a CORS preflight ``OPTIONS`` request, no
    authentication information will be included. For other ``OPTIONS``
    requests, authentication is optional. Return `None` for any ``OPTIONS``
    request. Otherwise, authenticate the user or, if they are not
    authenticated, send an authentication challenge based on the ``auth_type``
    parameter.
    """
    if x_original_method == "OPTIONS":
        return None
    authenticate = AuthenticateRead(
        allow_cookies=allow_cookies, auth_type=auth_type, ajax_forbidden=True
    )
    return await authenticate(context=context)


@router.get(
    "/ingress/auth",
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
    *,
    access_control_request_method: Annotated[
        str | None, Header(description="Method for CORS preflight")
    ] = None,
    origin: Annotated[
        str | None, Header(description="Origin header of original request")
    ] = None,
    x_original_method: Annotated[
        str, Header(description="Method of original request")
    ],
    auth_config: Annotated[AuthConfig, Depends(auth_config)],
    token_data: Annotated[TokenData | None, Depends(authenticate_with_type)],
    context: Annotated[RequestContext, Depends(context_dependency)],
    response: Response,
) -> dict[str, str]:
    if x_original_method == "OPTIONS":
        return handle_options(
            context,
            auth_config,
            response,
            access_control_request_method=access_control_request_method,
            origin=origin,
        )

    # token_data should only be None for OPTIONS requests, handled above.
    if not token_data:
        raise RuntimeError("Unauthenticated request to /ingress/auth")

    # Do some basic checks and analysis of the authentication data.
    check_lifetime(context, auth_config, token_data)
    token_scopes = set(token_data.scopes)

    # Determine whether the request is authorized.
    if auth_config.satisfy == Satisfy.ANY:
        authorized = not token_scopes.isdisjoint(auth_config.scopes)
    else:
        authorized = token_scopes.issuperset(auth_config.scopes)
    if not authorized:
        raise generate_challenge(
            context,
            auth_config.auth_type,
            InsufficientScopeError("Token missing required scope"),
            auth_config.scopes,
        )

    # Check a user or service constraint. InsufficientScopeError is not really
    # correct, but none of the RFC 6750 error codes are correct and it's the
    # closest.
    if not user_allowed(context, auth_config, token_data):
        raise generate_challenge(
            context,
            auth_config.auth_type,
            InsufficientScopeError("Access not allowed for this user"),
        )

    # Get user information and check rate limits.
    user_info = await get_user_info(context, token_data)
    rate_status = await check_rate_limit(context, auth_config, user_info)
    if rate_status:
        response.headers.update(rate_status.to_http_headers())

    # Construct the response headers.
    headers = await build_success_headers(
        context, auth_config, token_data, user_info
    )
    for key, value in headers:
        response.headers.append(key, value)

    # Send a metric event for the authentication.
    with sentry_sdk.start_span(name="events.publish"):
        if is_bot_user(token_data.username):
            bot_event = AuthBotEvent(
                username=token_data.username,
                service=auth_config.service,
                quota=rate_status.limit if rate_status else None,
                quota_used=rate_status.used if rate_status else None,
            )
            await context.events.auth_bot.publish(bot_event)
        else:
            user_event = AuthUserEvent(
                username=token_data.username,
                service=auth_config.service,
                quota=rate_status.limit if rate_status else None,
                quota_used=rate_status.used if rate_status else None,
            )
            await context.events.auth_user.publish(user_event)

    # Log and return the results.
    context.logger.info("Token authorized")
    return {"status": "ok"}


@router.get(
    "/ingress/anonymous",
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
    *,
    context: Annotated[RequestContext, Depends(context_dependency)],
    response: Response,
) -> dict[str, str]:
    for header, value in build_anonymous_headers(context):
        response.headers.append(header, value)
    return {"status": "ok"}


def handle_options(
    context: RequestContext,
    auth_config: AuthConfig,
    response: Response,
    *,
    access_control_request_method: str | None,
    origin: str | None,
) -> dict[str, str]:
    """Handle an ``OPTIONS`` request.

    ``OPTIONS`` is a special case, since the standard for CORS preflight
    checks says that they do not contain authentication information and
    therefore we cannot do normal authentication and authorization.
    ``OPTIONS`` is also used for WebDAV, and in that case sending
    authentication with the ``OPTIONS`` request is optional.

    The current policy is that CORS preflight requests are passed to the
    backend service (and hence Gafaelfawr returns 200) if the ``Origin`` of
    the request is within the Gafaelfawr-protected domain. Otherwise, they are
    rejected with a 403 error. ``OPTIONS`` requests that are not CORS
    preflight requests (ones without an ``Origin`` header) are passed to the
    backend if and only if the ingress is configured to allow ``OPTIONS``
    requests.

    It shouldn't be necessary to clean the ``Authorization`` and ``Cookie``
    headers, since they shouldn't be sent in ``OPTIONS`` requests, but do it
    anyway out of paranoia.

    Parameters
    ----------
    context
        Request context.
    auth_config
        Configuration for the ingress.
    response
        Response, used to add stripped headers on success.
    access_control_request_method
        ``Access-Control-Request-Method`` header of the request.
    origin
        ``Origin`` header of the request.

    Returns
    -------
    dict of str
        JSON to return for success.

    Raises
    ------
    fastapi.HTTPException
        Raised for non-CORS ``OPTIONS`` requests or if the ``OPTIONS`` request
        is rejected.
    """
    if not origin or not access_control_request_method:
        if auth_config.allow_options:
            if not (origin or access_control_request_method):
                return {"status": "ok"}
            else:
                raise generate_challenge(
                    context=context,
                    auth_type=None,
                    exc=OptionsNotSupportedError("Malformed CORS request"),
                )
        else:
            msg = "Non-CORS OPTIONS requests not supported"
            raise generate_challenge(
                context=context,
                auth_type=None,
                exc=OptionsNotSupportedError(msg),
            )
    okay = False
    with suppress(Exception):
        hostname = urlparse(origin).hostname
        if hostname and context.config.is_hostname_allowed(hostname):
            okay = True
    if not okay:
        raise generate_challenge(
            context=context,
            auth_type=None,
            exc=DisallowedCORSRequestError("Cross-origin request not allowed"),
        )
    for header, value in build_anonymous_headers(context):
        response.headers.append(header, value)
    return {"status": "ok"}


def build_anonymous_headers(context: RequestContext) -> list[tuple[str, str]]:
    """Construct the headers returned in an anonymous ingress response.

    This will contain only the stripped ``Authorization`` and ``Cookie``
    headers from the request.

    Parameters
    ----------
    context
        Request context.

    Returns
    -------
    list of tuple
        Headers to add to the response.
    """
    headers: list[tuple[str, str]] = []
    if "Authorization" in context.request.headers:
        raw_authorizations = context.request.headers.getlist("Authorization")
        authorizations = clean_authorization(raw_authorizations)
        headers.extend(("Authorization", a) for a in authorizations)
    if "Cookie" in context.request.headers:
        raw_cookies = context.request.headers.getlist("Cookie")
        headers.extend(("Cookie", c) for c in clean_cookies(raw_cookies))
    return headers


def check_lifetime(
    context: RequestContext, auth_config: AuthConfig, token_data: TokenData
) -> None:
    """Check if the token lifetime is long enough.

    This check is done prior to getting the delegated token during the initial
    authentication check. The timing of the check is a bit awkward, since the
    semantic request is a minimum lifetime of any delegated internal or
    notebook token we will pass along.  However, getting the latter is more
    expensive: we would have to do all the work of creating the token, then
    retrieve it from Redis, and then check its lifetime.

    Thankfully, we can know in advance whether the token we will create will
    have a long enough lifetime. We can request tokens up to the lifetime of
    the parent token and therefore can check the required lifetime against the
    lifetime of the parent token as long as we require the child token have
    the required lifetime (which we do, in `build_success_headers`).

    The only special case we need to handle is where the required lifetime is
    too close to the maximum lifetime for new tokens, since the lifetime of
    delegated tokens will be capped at that. In this case, we can never
    satisfy this request and need to raise a 422 error instead of a 401 or 403
    error. We don't allow required lifetimes within ``MINIMUM_LIFETIME`` of
    the maximum lifetime to avoid the risk of a slow infinite redirect loop
    when the login process takes a while.

    Parameters
    ----------
    context
        The context of the incoming request.
    auth_config
        Configuration parameters for the authorization.
    token_data
        The data from the authentication token.

    Raises
    ------
    fastapi.HTTPException
        Raised if the minimum lifetime is not satisfied. This will be a 401 or
        403 HTTP error as appropriate.
    InvalidMinimumLifetime
        Raised if the specified minimum lifetime is longer than the maximum
        lifetime of a token minus the minimum remaining lifetime and therefore
        cannot be satisfied.
    """
    if not auth_config.minimum_lifetime:
        return
    max_lifetime = context.config.token_lifetime - MINIMUM_LIFETIME
    if auth_config.minimum_lifetime > max_lifetime:
        min_seconds = int(auth_config.minimum_lifetime.total_seconds())
        max_seconds = int(max_lifetime.total_seconds())
        msg = (
            f"Requested lifetime {min_seconds}s longer than maximum lifetime"
            f" {max_seconds}s"
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


async def check_rate_limit(
    context: RequestContext, auth_config: AuthConfig, user_info: UserInfo
) -> RateLimitStatus | None:
    """Check whether this request is allowed by rate limits.

    Any failure inside the rate limiting library, such as a failure to contact
    Redis, causes the request to succeed. (In other words, rate limiting fails
    open.)

    Parameters
    ----------
    context
        Context of the incoming request.
    auth_config
        Configuration parameters for the authorization.
    user_info
        Information about the user, including their quotas.

    Returns
    -------
    RateLimitStatus or None
        Current status of rate limit, or `None` if no rate limit applies.

    Raises
    ------
    fastapi.HTTPException
        Raised if the requet was rejected by rate limiting. This error
        will use a 429 response code.
    """
    if not user_info.quota or not auth_config.service:
        return None
    quota = user_info.quota.api.get(auth_config.service)
    if quota is None:
        return None

    # If the quota is zero, treat this as an administrative block and return a
    # 403 error.
    if quota == 0:
        msg = (
            f"User {user_info.username} not allowed to access service"
            f" {auth_config.service}"
        )
        raise generate_challenge(
            context, auth_config.auth_type, exc=InsufficientScopeError(msg)
        )

    # Check the usage against Redis.
    key = ("api", user_info.username, auth_config.service)
    limit = RateLimitItemPerMinute(quota, 1)
    try:
        allowed = await context.rate_limiter.hit(limit, *key)
        stats = await context.rate_limiter.get_window_stats(limit, *key)
    except Exception as e:
        # Ideally the failure would be reported to Slack, but if the Redis pool
        # in which rate limiting information is stored is unavailable, every
        # request with quotas would produce an error and we would hammer the
        # Slack API into the ground. Settle for reporting exceptions to the
        # application logs and continuing as if no rate limiting were
        # configured.
        error = f"{type(e).__name__}: {e!s}"
        context.logger.exception("Rate limiting failed", error=error)
        return None

    # Handle the results of the rate limiting, either returning statistics for
    # inclusion in HTTP response headers or raising an exception.
    retry_after = datetime.fromtimestamp(stats.reset_time, tz=UTC)
    status = RateLimitStatus(
        limit=quota,
        used=quota - stats.remaining,
        remaining=stats.remaining,
        reset=retry_after,
        resource=auth_config.service,
    )
    context.rebind_logger(
        quota={
            "limit": quota,
            "used": status.used,
            "reset": format_datetime_for_logging(retry_after),
        }
    )
    if allowed:
        return status

    # The user ran out of API quota. Log the relevant metric and the error.
    with sentry_sdk.start_span(name="events.publish"):
        event = RateLimitEvent(
            username=user_info.username,
            is_bot=is_bot_user(user_info.username),
            service=auth_config.service,
            quota=quota,
        )
        await context.events.rate_limit.publish(event)

    # Return a 403 error with the actual status code and body in the
    # headers, where they will be parsed by the ingress-nginx integration.
    msg = f"Rate limit ({quota}/minute) exceeded"
    context.logger.info("Request rejected due to rate limits", error=msg)
    detail = [{"msg": msg, "type": "rate_limited"}]
    raise HTTPException(
        detail=detail,
        status_code=403,
        headers={
            "Cache-Control": "no-cache, no-store",
            "X-Error-Body": json.dumps({"detail": detail}),
            "X-Error-Status": "429",
            "Retry-After": format_datetime(retry_after, usegmt=True),
            **status.to_http_headers(),
        },
    )


async def get_user_info(
    context: RequestContext, token_data: TokenData
) -> UserInfo:
    """Get user information for the user authenticated by a token.

    Parameters
    ----------
    context
        Request context.
    token_data
        Data for authenticated and verified token.

    Returns
    -------
    UserInfo
        User information corresponding to that authenticated user.

    Raises
    ------
    fastapi.HTTPException
        Raised if an error occurred while retrieving the user information for
        the user.
    """
    info_service = context.factory.create_user_info_service()
    try:
        return await info_service.get_user_info_from_token(token_data)
    except ExternalUserInfoError as e:
        # Catch these exceptions rather than raising an uncaught exception or
        # reporting the exception to Slack. This route is called on every user
        # request and may be called multiple times per second, so if we
        # reported every exception during an LDAP outage to Slack, we would
        # get rate-limited or destroy the Slack channel. Instead, log the
        # exception and return 403 and rely on failures during login (which
        # are reported to Slack) and external testing to detect these
        # problems.
        msg = "Unable to get user information"
        context.logger.exception(msg, user=token_data.username, error=str(e))
        raise HTTPException(
            headers={"Cache-Control": "no-cache, no-store"},
            status_code=500,
            detail=[{"msg": msg, "type": "user_info_failed"}],
        ) from e


def user_allowed(
    context: RequestContext, auth_config: AuthConfig, token_data: TokenData
) -> bool:
    """Check for special authorization rules for this user.

    Verify that the request passes service restrictions, username
    restrictions, and per-user hostname restrictions.

    Returns
    -------
    bool
        `True` if the user is allowed, `False` otherwise.
    """
    if auth_config.only_services:
        if token_data.service not in auth_config.only_services:
            return False
    if auth_config.username and token_data.username != auth_config.username:
        return False
    if auth_config.user_domain:
        try:
            hostname = urlparse(auth_config.auth_uri).hostname
            if not hostname:
                return False
            if not context.config.is_hostname_allowed(hostname):
                return False
            hostname, _ = hostname.split(".", 1)
            if hostname != token_data.username:
                return False
        except Exception:
            return False
    return True


async def build_success_headers(
    context: RequestContext,
    auth_config: AuthConfig,
    token_data: TokenData,
    user_info: UserInfo,
) -> list[tuple[str, str]]:
    """Construct the headers for successful authorization.

    The following headers may be included:

    Authorization
        The input ``Authorization`` headers with any headers containing
        Gafaelfawr tokens stripped.
    Cookie
        The input ``Cookie`` headers with any cookie values containing
        Gafaelfawr tokens stripped.
    X-Auth-Request-Email
        The email address of the authenticated user, if known.
    X-Auth-Request-Service
        The service associated with the token if one was present.
    X-Auth-Request-User
        The username of the authenticated user.
    X-Auth-Request-Token
        If requested by ``notebook`` or ``delegate_to``, will be set to the
        delegated token.

    Parameters
    ----------
    context
        Context of the incoming request.
    auth_config
        Configuration parameters for the authorization.
    token_data
        Data from the authentication token.
    user_info
        User information for the authenticated user.

    Returns
    -------
    headers
        Headers to include in the response.

    Raises
    ------
    fastapi.HTTPException
        Raised if user information could not be retrieved from external
        systems.
    """
    headers = [("X-Auth-Request-User", token_data.username)]
    if user_info.email:
        headers.append(("X-Auth-Request-Email", user_info.email))

    # Add the service of the token if the token is associated with a service.
    if token_data.service:
        headers.append(("X-Auth-Request-Service", token_data.service))

    # Add the delegated token, if there should be one.
    delegated = await build_delegated_token(context, auth_config, token_data)
    if delegated:
        headers.append(("X-Auth-Request-Token", delegated))

    # If told to put the delegated token in the Authorization header, do that.
    # Otherwise, strip authentication tokens from the Authorization headers of
    # the incoming request and reflect the remainder back in the response.
    # Always do this with the Cookie header. ingress-nginx can then be
    # configured to lift those headers up into the proxy request, preventing
    # the user's cookie from being passed down to the protected application.
    if auth_config.use_authorization:
        if delegated:
            headers.append(("Authorization", f"Bearer {delegated}"))
    elif "Authorization" in context.request.headers:
        raw_authorizations = context.request.headers.getlist("Authorization")
        authorizations = clean_authorization(raw_authorizations)
        headers.extend(("Authorization", v) for v in authorizations)
    if "Cookie" in context.request.headers:
        raw_cookies = context.request.headers.getlist("Cookie")
        cookies = clean_cookies(raw_cookies)
        headers.extend(("Cookie", v) for v in cookies)

    return headers


async def build_delegated_token(
    context: RequestContext, auth_config: AuthConfig, token_data: TokenData
) -> str | None:
    """Construct the delegated token for this request.

    Parameters
    ----------
    context
        Context of the incoming request.
    auth_config
        Configuration parameters for the authorization.
    token_data
        Data from the authentication token.

    Returns
    -------
    str or None
        Delegated token to include in the request, or `None` if none should be
        included.
    """
    if auth_config.notebook:
        token_service = context.factory.create_token_service()
        token = await token_service.get_notebook_token(
            token_data,
            ip_address=context.ip_address,
            minimum_lifetime=auth_config.minimum_lifetime,
        )
        return str(token)
    elif auth_config.delegate_to:
        # Delegated scopes are optional; if the authenticating token doesn't
        # have the scope, it's omitted from the delegated token. (To make it
        # mandatory, require that scope via the scope parameter as well, and
        # then the authenticating token will always have it.) Therefore,
        # reduce the scopes of the internal token to the intersection between
        # the requested delegated scopes and the scopes of the authenticating
        # token.
        delegate_scopes = auth_config.delegate_scopes & token_data.scopes
        token_service = context.factory.create_token_service()
        token = await token_service.get_internal_token(
            token_data,
            service=auth_config.delegate_to,
            scopes=delegate_scopes,
            ip_address=context.ip_address,
            minimum_lifetime=auth_config.minimum_lifetime,
        )
        return str(token)
    else:
        return None
