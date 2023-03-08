"""Initial authentication handlers (``/login``)."""

import base64
import os
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import RedirectResponse, Response

from ..dependencies.context import RequestContext, context_dependency
from ..dependencies.return_url import return_url_with_header
from ..exceptions import (
    FirestoreError,
    InvalidReturnURLError,
    LDAPError,
    OIDCNotEnrolledError,
    PermissionDeniedError,
    ProviderError,
    ProviderWebError,
)
from ..route import SlackRouteErrorHandler
from ..templates import templates

router = APIRouter(route_class=SlackRouteErrorHandler)

__all__ = ["get_login"]


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
    STATE_INVALID = "Authentication state mismatch"
    STATE_MISSING = "No authentication state"


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
    code: Optional[str] = Query(
        None,
        title="Provider code",
        description="Set by the authentication provider after authentication",
        example="V2hrNqgM_eiIjXvV41RlMw",
    ),
    state: Optional[str] = Query(
        None,
        title="Authentication state",
        description=(
            "Set by the authentication provider after authentication to"
            " protect against session fixation"
        ),
        example="wkC2bAP5VFpDioKc3JfaDA",
    ),
    return_url: Optional[str] = Depends(return_url_with_header),
    context: RequestContext = Depends(context_dependency),
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
    # This is subtle and requires some explanation.  Most modern webapps
    # involve a lot of background JavaScript.  If the user has a tab open when
    # their session expires, those background JavaScript requests will start
    # turning into redirects to Gafaelfawr and thus to this code.  Since there
    # isn't a good way to see whether a request is a background JavaScript
    # request versus a browser loading a page, we will generate an
    # authentication redirect for each one.
    #
    # This means that if we generate new random state for each request, there
    # is a race condition.  The user may go to a page with an expired session
    # and get redirected to log in.  While they are logging in at the external
    # provider, another open tab may kick off one of these JavaScript
    # requests, which generates a new redirect and replaces the state stored
    # in their session cookie.  Then, when they return from authentication,
    # the state will have changed, and the authentication attempt will fail.
    #
    # Work around this by reusing the same random state until the user
    # completes an authentication.  This does not entirely close the window
    # for the race condition because it's possible that two requests will both
    # see sessions without state, both generate state, and then both set
    # cookies, and only one of them will win.  However, that race condition
    # window is much smaller and is unlikely to persist across authentication
    # requests.
    state = context.state.state
    if not state:
        state = base64.urlsafe_b64encode(os.urandom(16)).decode()
        context.state.state = state

    # Get the authentication provider URL send the user there.
    provider = context.factory.create_provider()
    redirect_url = provider.get_redirect_url(state)
    return RedirectResponse(redirect_url)


async def handle_provider_return(
    code: str, state: str | None, context: RequestContext
) -> Response:
    """Handle the return from an external authentication provider.

    Handles the target of the redirect back from an external authentication
    provider with new authentication state information.

    Parameters
    ----------
    code
        The authentication code from the provider.
    state
        The opaque state used to verify that this user initiated the
        authentication.  This can be `None`, but that will always be an
        error.
    context
        The context of the incoming request.

    Returns
    -------
    fastapi.Response
        Either a redirect to the resource the user was trying to reach before
        authentication or an HTML page with an error message if the
        authentication failed.

    Raises
    ------
    fastapi.HTTPException
        The authentication request is invalid or retrieving authentication
        information from the provider failed.
    """
    if not state:
        return _login_error_user(context, LoginError.STATE_MISSING)

    # Extract details from the reply, check state, and get the return URL.
    if state != context.state.state:
        return _login_error_user(context, LoginError.STATE_INVALID)
    return_url = context.state.return_url
    if not return_url:
        return _login_error_user(context, LoginError.RETURN_URL_MISSING)
    context.rebind_logger(return_url=return_url)

    # Retrieve the user identity and authorization information based on the
    # reply from the authentication provider.
    provider = context.factory.create_provider()
    try:
        user_info = await provider.create_user_info(code, state, context.state)
    except OIDCNotEnrolledError as e:
        if context.config.oidc and context.config.oidc.enrollment_url:
            url = context.config.oidc.enrollment_url
            context.logger.info("Redirecting user to enrollment URL", url=url)
            headers = {"Cache-Control": "no-cache, no-store"}
            return RedirectResponse(url, headers=headers)
        else:
            return _login_error_user(context, LoginError.NOT_ENROLLED, str(e))
    except FirestoreError as e:
        return _login_error_system(context, LoginError.FIRESTORE_FAILED, e)
    except ProviderWebError as e:
        return _login_error_system(context, LoginError.PROVIDER_NETWORK, e)
    except LDAPError as e:
        return _login_error_system(context, LoginError.LDAP_FAILED, e)
    except ProviderError as e:
        return _login_error_system(context, LoginError.PROVIDER_FAILED, e)
    except PermissionDeniedError as e:
        await provider.logout(context.state)
        return _login_error_user(context, LoginError.INVALID_USERNAME, str(e))

    # Get the scopes for this user.
    user_info_service = context.factory.create_user_info_service()
    scopes = await user_info_service.get_scopes(user_info)
    if scopes is None:
        await provider.logout(context.state)
        await user_info_service.invalidate_cache(user_info.username)
        msg = f"{user_info.username} is not a member of any authorized groups"
        return _login_error_user(context, LoginError.GROUPS_MISSING, msg)

    # Construct a token.
    admin_service = context.factory.create_admin_service()
    token_service = context.factory.create_token_service()
    try:
        async with context.session.begin():
            if await admin_service.is_admin(user_info.username):
                scopes = sorted(scopes + ["admin:token"])
            token = await token_service.create_session_token(
                user_info, scopes=scopes, ip_address=context.ip_address
            )
    except PermissionDeniedError as e:
        await provider.logout(context.state)
        return _login_error_user(context, LoginError.INVALID_USERNAME, str(e))
    context.state.token = token

    # Successful login, so clear the login state and send the user back to
    # what they were doing.
    context.state.state = None
    context.state.return_url = None
    return RedirectResponse(return_url)


def _login_error_system(
    context: RequestContext, error: LoginError, exc: Exception
) -> Response:
    """Generate an error page for a system login failure.

    Report errors back to the user in a somewhat more human-readable form than
    a JSON error message. This function is for errors on the Gafaelfawr side
    that should also be reported to Slack. Use `_login_error_system` for
    errors internal to Gafaelfawr.

    Parameters
    ----------
    context
        The context of the incoming request.
    error
        The type of error.
    exc
        The exception representing the error.

    Returns
    -------
    fastapi.Response
        The response to send back to the user.
    """
    context.logger.error(error.value, error=str(exc))
    return templates.TemplateResponse(
        "login-error.html",
        context={
            "request": context.request,
            "error": error,
            "message": error.value,
            "details": str(exc),
            "error_footer": context.config.error_footer,
        },
        headers={"Cache-Control": "no-cache, no-store"},
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


def _login_error_user(
    context: RequestContext, error: LoginError, details: Optional[str] = None
) -> Response:
    """Generate an error page for a user login failure.

    Report errors back to the user in a somewhat more human-readable form than
    a JSON error message. This function is for errors on the user's side. Use
    `_login_error_system` for errors internal to Gafaelfawr.

    Parameters
    ----------
    context
        The context of the incoming request.
    error
        The type of error.
    details
        Additional error details, if provided.

    Returns
    -------
    fastapi.Response
        The response to send back to the user.
    """
    if details:
        context.logger.warning(error.value, error=details)
    else:
        context.logger.warning("Authentication failed", error=error.value)
    return templates.TemplateResponse(
        "login-error.html",
        context={
            "request": context.request,
            "error": error,
            "message": error.value,
            "details": details,
            "error_footer": context.config.error_footer,
        },
        headers={"Cache-Control": "no-cache, no-store"},
        status_code=status.HTTP_403_FORBIDDEN,
    )
