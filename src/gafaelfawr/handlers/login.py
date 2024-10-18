"""Initial authentication handlers (``/login``)."""

import base64
import os
from datetime import UTC, datetime
from enum import Enum
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import RedirectResponse, Response
from safir.slack.blockkit import SlackException
from safir.slack.webhook import SlackRouteErrorHandler

from ..dependencies.context import RequestContext, context_dependency
from ..dependencies.return_url import return_url_with_header
from ..events import (
    LoginAttemptEvent,
    LoginEnrollmentEvent,
    LoginFailureEvent,
    LoginSuccessEvent,
)
from ..exceptions import (
    FirestoreError,
    InvalidReturnURLError,
    LDAPError,
    NoScopesError,
    OIDCNotEnrolledError,
    PermissionDeniedError,
    ProviderError,
    ProviderWebError,
)
from ..models.token import Token, TokenUserInfo
from ..templates import templates

router = APIRouter(route_class=SlackRouteErrorHandler)

__all__ = ["router"]


class LoginError(Enum):
    """Possible login failure conditions and their error messages."""

    GROUPS_MISSING = "User unauthorized"
    INVALID_USERNAME = "Cannot authenticate"
    NOT_ENROLLED = "User is not enrolled"
    FIRESTORE_FAILED = "Retrieving UID/GID from Firestore failed"
    LDAP_FAILED = "Retrieving data from LDAP failed"
    PROVIDER_FAILED = "Authentication provider failed"
    PROVIDER_NETWORK = "Cannot contact authentication provider"
    RETURN_URL_MISSING = "Invalid state: return_url not present in cookie"
    STATE_INVALID = "Authentication state mismatch, please start over"
    STATE_MISSING = "No authentication state, please start over"


@router.get(
    "/login",
    description=(
        "Protected services redirect to this URL when the user is not"
        " authenticated to start the authentication process. The user will"
        " then be sent to an authentication provider, back to this URL with"
        " additional parameters to complete the process, and then back to the"
        " protected site."
    ),
    responses={
        307: {
            "description": "Redirect to provider or destination",
            "headers": {
                "Location": {
                    "description": (
                        "URL of authentication provider or protected site"
                    ),
                    "schema": {"type": "string"},
                }
            },
        },
        403: {
            "content": {"text/html": {}},
            "description": "Error authenticating the user",
        },
    },
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    summary="Authenticate browser",
    tags=["browser"],
)
async def get_login(
    *,
    code: Annotated[
        str | None,
        Query(
            title="Provider code",
            description=(
                "Set by the authentication provider after authentication"
            ),
            examples=["V2hrNqgM_eiIjXvV41RlMw"],
        ),
    ] = None,
    state: Annotated[
        str | None,
        Query(
            title="Authentication state",
            description=(
                "Set by the authentication provider after authentication to"
                " protect against session fixation"
            ),
            examples=["wkC2bAP5VFpDioKc3JfaDA"],
        ),
    ] = None,
    return_url: Annotated[str | None, Depends(return_url_with_header)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> Response:
    """Handle an initial login or the return from a login provider.

    Notes
    -----
    Also export the login handler at ``/oauth2/callback``, the route used by
    oauth2_proxy, for compatibility with older oauth2_proxy installations.
    This avoids needing to change the redirect_uri registered with an OpenID
    Connect provider.  It can be removed once all registrations have been
    updated with the ``/login`` route.
    """
    if code:
        if not state:
            return await _error_user(context, LoginError.STATE_MISSING)
        return await handle_provider_return(code, state, context)
    else:
        return await redirect_to_provider(return_url, context)


async def redirect_to_provider(
    return_url: str | None, context: RequestContext
) -> RedirectResponse:
    """Redirect the user to an external authentication provider.

    Handles the initial processing and redirect to an external provider,
    storing necessary state in the user's session cookie.

    Parameters
    ----------
    return_url
        The return URL to which to send the user after authentication.
    context
        The context of the incoming request.

    Returns
    -------
    fastapi.RedirectResponse
        A redirect to the authentication provider.

    Raises
    ------
    fastapi.HTTPException
        The authentication request is invalid.
    """
    if not return_url:
        raise InvalidReturnURLError("No return URL given", "rd")
    context.state.return_url = return_url

    # Reuse the existing state if one already exists in the session cookie.
    #
    # This is subtle and requires some explanation. Most modern webapps
    # involve a lot of background JavaScript. If the user has a tab open when
    # their session expires, those background JavaScript requests will start
    # turning into redirects to Gafaelfawr and thus to this code. Since there
    # isn't a good way to see whether a request is a background JavaScript
    # request versus a browser loading a page, we will generate an
    # authentication redirect for each one.
    #
    # This means that if we generate new random state for each request, there
    # is a race condition. The user may go to a page with an expired session
    # and get redirected to log in. While they are logging in at the external
    # provider, another open tab may kick off one of these JavaScript
    # requests, which generates a new redirect and replaces the state stored
    # in their session cookie. Then, when they return from authentication, the
    # state will have changed, and the authentication attempt will fail.
    #
    # Work around this by reusing the same random state until the user
    # completes an authentication. This does not entirely close the window for
    # the race condition because it's possible that two requests will both see
    # sessions without state, both generate state, and then both set cookies,
    # and only one of them will win. However, that race condition window is
    # much smaller and is unlikely to persist across authentication requests.
    #
    # For this same reason, only count a redirect where we have to create
    # authentication state as an attempted login so that we don't count any
    # subsequent redirects for other resources.
    state = context.state.state
    if not state:
        state = base64.urlsafe_b64encode(os.urandom(16)).decode()
        context.state.state = state
        context.state.login_start = datetime.now(tz=UTC)
        await context.events.login_attempt.publish(LoginAttemptEvent())

    # Get the authentication provider URL send the user there.
    provider = context.factory.create_provider()
    redirect_url = provider.get_redirect_url(state)
    return RedirectResponse(redirect_url)


async def handle_provider_return(
    code: str, state: str, context: RequestContext
) -> Response:
    """Handle the return from an external authentication provider.

    Handles the target of the redirect back from an external authentication
    provider with new authentication state information.

    Parameters
    ----------
    code
        Authentication code from the provider.
    state
        Opaque state used to verify that this user initiated the
        authentication.
    context
        Context of the incoming request.

    Returns
    -------
    fastapi.Response
        Either a redirect to the resource the user was trying to reach before
        authentication, to the login URL, or an HTML page with an error
        message if the authentication failed.

    Raises
    ------
    fastapi.HTTPException
        The authentication request is invalid or retrieving authentication
        information from the provider failed.
    """
    try:
        return await _construct_login_response(code, state, context)
    except OIDCNotEnrolledError as e:
        if context.config.oidc and context.config.oidc.enrollment_url:
            url = str(context.config.oidc.enrollment_url)
            context.logger.info("Redirecting user to enrollment URL", url=url)
            await context.events.login_enrollment.publish(
                LoginEnrollmentEvent()
            )
            headers = {"Cache-Control": "no-cache, no-store"}
            return RedirectResponse(url, headers=headers)
        else:
            return await _error_user(context, LoginError.NOT_ENROLLED, str(e))
    except FirestoreError as e:
        return await _error_system(context, LoginError.FIRESTORE_FAILED, e)
    except ProviderWebError as e:
        return await _error_system(context, LoginError.PROVIDER_NETWORK, e)
    except LDAPError as e:
        return await _error_system(context, LoginError.LDAP_FAILED, e)
    except NoScopesError as e:
        provider = context.factory.create_provider()
        await provider.logout(context.state)
        return await _error_user(context, LoginError.GROUPS_MISSING, str(e))
    except ProviderError as e:
        return await _error_system(context, LoginError.PROVIDER_FAILED, e)
    except PermissionDeniedError as e:
        provider = context.factory.create_provider()
        await provider.logout(context.state)
        return await _error_user(context, LoginError.INVALID_USERNAME, str(e))


async def _construct_token(
    context: RequestContext, user_info: TokenUserInfo
) -> Token:
    """Construct a token for the authenticated user.

    Parameters
    ----------
    context
        Context of the incoming request.
    user_info
        User information for the user.

    Returns
    -------
    Token
        Newly-minted token for the user.

    Raises
    ------
    NoScopesError
        Raised if the user's group memberships do not entitle them to any
        scopes, and therefore they cannot log in.
    PermissionDeniedError
        Raised if the user's username is invalid.
    """
    user_info_service = context.factory.create_user_info_service()
    admin_service = context.factory.create_admin_service()
    token_service = context.factory.create_token_service()

    # Get the user's scopes.
    scopes = await user_info_service.get_scopes(user_info)
    if scopes is None:
        await user_info_service.invalidate_cache(user_info.username)
        msg = f"{user_info.username} is not a member of any authorized groups"
        raise NoScopesError(msg)

    # Construct a token.
    async with context.session.begin():
        if await admin_service.is_admin(user_info.username):
            scopes = sorted([*scopes, "admin:token"])
        return await token_service.create_session_token(
            user_info, scopes=scopes, ip_address=context.ip_address
        )


async def _error_system(
    context: RequestContext, error: LoginError, exc: SlackException
) -> Response:
    """Generate an error page for a system login failure.

    Report errors back to the user in a somewhat more human-readable form than
    a JSON error message. This function is for errors on the Gafaelfawr side
    that should also be reported to Slack. Use `_error_user` for errors caused
    by the user.

    Parameters
    ----------
    context
        Context of the incoming request.
    error
        Type of error.
    exc
        Exception representing the error.

    Returns
    -------
    fastapi.Response
        Response to send back to the user.
    """
    context.logger.error(error.value, error=str(exc))
    slack_client = context.factory.create_slack_client()
    if slack_client:
        await slack_client.post_exception(exc)
    context.state.state = None
    context.state.return_url = None
    context.state.login_start = None
    await context.events.login_failure.publish(LoginFailureEvent())
    return templates.TemplateResponse(
        context.request,
        "login-error.html",
        context={
            "error": error,
            "message": error.value,
            "details": str(exc),
            "error_footer": context.config.error_footer,
        },
        headers={"Cache-Control": "no-cache, no-store"},
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


async def _error_user(
    context: RequestContext, error: LoginError, details: str | None = None
) -> Response:
    """Generate an error page for a user login failure.

    Report errors back to the user in a somewhat more human-readable form than
    a JSON error message. This function is for errors on the user's side. Use
    `_error_system` for errors internal to Gafaelfawr.

    Parameters
    ----------
    context
        Context of the incoming request.
    error
        Type of error.
    details
        Additional error details, if provided.

    Returns
    -------
    fastapi.Response
        Response to send back to the user.
    """
    if details:
        context.logger.warning(error.value, error=details)
    else:
        context.logger.warning("Authentication failed", error=error.value)
    context.state.state = None
    context.state.return_url = None
    context.state.login_start = None
    await context.events.login_failure.publish(LoginFailureEvent())
    return templates.TemplateResponse(
        context.request,
        "login-error.html",
        context={
            "error": error,
            "message": error.value,
            "details": details,
            "error_footer": context.config.error_footer,
        },
        headers={"Cache-Control": "no-cache, no-store"},
        status_code=status.HTTP_403_FORBIDDEN,
    )


async def _construct_login_response(
    code: str, state: str, context: RequestContext
) -> Response:
    """Handle the return from an external authentication provider.

    Handles the target of the redirect back from an external authentication
    provider with new authentication state information.

    If there is no authentication state in the user's cookie, it is likely
    that the user was attempting logins in multiple tabs and already logged in
    via some other tab. Redirect the user to their destination, which in the
    worst case will just restart the authentication with proper state.

    Parameters
    ----------
    code
        Authentication code from the provider.
    state
        Opaque state used to verify that this user initiated the
        authentication.
    context
        Context of the incoming request.

    Returns
    -------
    fastapi.Response
        Either a redirect to the resource the user was trying to reach before
        authentication, to the login URL, or an HTML page with an error
        message if the authentication failed.

    Raises
    ------
    ExternalUserInfoError
        Raised if an error is encountered retrieving user information from a
        user information provider.
    NoScopesError
        Raised if the user has no valid scopes.
    PermissionDeniedError
        Raised if the username is invalid.
    ProviderError
        Raised if there is some problem retrieving information from the
        authentication provider.
    """
    return_url = context.state.return_url
    if not return_url:
        return await _error_user(context, LoginError.RETURN_URL_MISSING)
    context.rebind_logger(return_url=return_url)
    if not context.state.state:
        msg = "Login state missing, redirecting without authentication"
        context.logger.info(msg)
        return RedirectResponse(return_url)
    if state != context.state.state:
        return await _error_user(context, LoginError.STATE_INVALID)

    # Retrieve the user identity and authorization information based on the
    # reply from the authentication provider, and construct a token.
    provider = context.factory.create_provider()
    user_info = await provider.create_user_info(code, state, context.state)
    token = await _construct_token(context, user_info)

    # Record login event.
    event = LoginSuccessEvent(username=user_info.username)
    if context.state.login_start:
        elapsed = datetime.now(tz=UTC) - context.state.login_start
        event.elapsed = elapsed.total_seconds()
    await context.events.login_success.publish(event)

    # Store the token, record metrics, clear the login state, and send the
    # user back to what they were doing.
    context.state.token = token
    context.state.state = None
    context.state.return_url = None
    context.state.login_start = None
    return RedirectResponse(return_url)
