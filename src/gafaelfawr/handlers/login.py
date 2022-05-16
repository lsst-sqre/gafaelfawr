"""Initial authentication handlers (``/login``)."""

import base64
import os
from enum import Enum
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import RedirectResponse, Response
from httpx import HTTPError

from ..config import Config
from ..dependencies.context import RequestContext, context_dependency
from ..dependencies.return_url import return_url_with_header
from ..exceptions import (
    FirestoreError,
    InvalidReturnURLError,
    LDAPError,
    NoUsernameMappingError,
    PermissionDeniedError,
    ProviderError,
)
from ..models.token import TokenGroup
from ..templates import templates

router = APIRouter()

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
        "Protected applications redirect to this URL when the user is not"
        " authenticated to start the authentication process. The user will"
        " then be sent to an authentication provider, back to this URL with"
        " additional parameters to complete the process, and then back to the"
        " protected site."
    ),
    responses={
        307: {"description": "Redirect to provider or destination"},
        403: {
            "content": {"text/html": {}},
            "description": "Error authenticating the user",
        },
    },
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    summary="Authenticate browser",
    tags=["browser"],
)
@router.get("/oauth2/callback", include_in_schema=False, tags=["browser"])
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
    return_url: Optional[str], context: RequestContext
) -> RedirectResponse:
    """Redirect the user to an external authentication provider.

    Handles the initial processing and redirect to an external provider,
    storing necessary state in the user's session cookie.

    Parameters
    ----------
    return_url : `str`, optional
        The return URL to which to send the user after authentication.
    context : `gafaelfawr.dependencies.config.RequestContext`
        The context of the incoming request.

    Returns
    -------
    response : `fastapi.RedirectResponse`
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
    auth_provider = context.factory.create_provider()
    redirect_url = auth_provider.get_redirect_url(state)
    return RedirectResponse(redirect_url)


async def handle_provider_return(
    code: str, state: Optional[str], context: RequestContext
) -> Response:
    """Handle the return from an external authentication provider.

    Handles the target of the redirect back from an external authentication
    provider with new authentication state information.

    Parameters
    ----------
    code : `str`
        The authentication code from the provider.
    state : `str`, optional
        The opaque state used to verify that this user initiated the
        authentication.  This can be `None`, but that will always be an
        error.
    context : `gafaelfawr.dependencies.config.RequestContext`
        The context of the incoming request.

    Returns
    -------
    response : ``fastapi.Response``
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
        return login_error(context, LoginError.STATE_MISSING)

    # Extract details from the reply, check state, and get the return URL.
    if state != context.state.state:
        return login_error(context, LoginError.STATE_INVALID)
    return_url = context.state.return_url
    if not return_url:
        return login_error(context, LoginError.RETURN_URL_MISSING)
    context.rebind_logger(return_url=return_url)

    # Retrieve the user identity and authorization information based on the
    # reply from the authentication provider.
    auth_provider = context.factory.create_provider()
    try:
        user_info = await auth_provider.create_user_info(
            code, state, context.state
        )
    except NoUsernameMappingError as e:
        if context.config.oidc and context.config.oidc.enrollment_url:
            url = context.config.oidc.enrollment_url
            context.logger.info("Redirecting user to enrollment URL", url=url)
            return RedirectResponse(url)
        else:
            return login_error(context, LoginError.NOT_ENROLLED, str(e))
    except FirestoreError as e:
        return login_error(context, LoginError.FIRESTORE_FAILED, str(e))
    except HTTPError as e:
        return login_error(context, LoginError.PROVIDER_NETWORK, str(e))
    except LDAPError as e:
        return login_error(context, LoginError.LDAP_FAILED, str(e))
    except ProviderError as e:
        return login_error(context, LoginError.PROVIDER_FAILED, str(e))

    # If we normally get group information from LDAP, the groups returned by
    # the authentication provider will be empty, but we still want to
    # determine the user's scopes.
    groups: Optional[List[TokenGroup]]
    if context.config.ldap:
        user_info_service = context.factory.create_user_info_service()
        username = user_info.username
        groups = await user_info_service.get_groups_from_ldap(username)
    else:
        groups = user_info.groups

    # Get the user's scopes.  If this returns None, the user isn't in any
    # recognized groups, which means that we should abort the login and
    # display an error message.
    scopes = get_scopes_from_groups(context.config, groups)
    if scopes is None:
        await auth_provider.logout(context.state)
        msg = f"{user_info.username} is not a member of any authorized groups"
        return login_error(context, LoginError.GROUPS_MISSING, details=msg)

    # Construct a token.
    admin_service = context.factory.create_admin_service()
    async with context.session.begin():
        if await admin_service.is_admin(user_info.username):
            scopes = sorted(scopes + ["admin:token"])
        token_service = context.factory.create_token_service()
        try:
            token = await token_service.create_session_token(
                user_info, scopes=scopes, ip_address=context.ip_address
            )
        except PermissionDeniedError as e:
            await auth_provider.logout(context.state)
            return login_error(context, LoginError.INVALID_USERNAME, str(e))
    context.state.token = token

    # Successful login, so clear the login state and send the user back to
    # what they were doing.
    context.state.state = None
    context.state.return_url = None
    context.logger.info(
        "Successfully authenticated user %s (%s)",
        user_info.username,
        user_info.uid,
        user=user_info.username,
        token=token.key,
        scopes=sorted(scopes),
    )
    return RedirectResponse(return_url)


def get_scopes_from_groups(
    config: Config, groups: Optional[List[TokenGroup]]
) -> Optional[List[str]]:
    """Get scopes from a list of groups.

    Used to determine the scope claim of a token issued based on an OpenID
    Connect authentication.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        Gafaelfawr configuration.
    groups : List[`gafaelfawr.models.token.TokenGroup`]
        The groups of a token.

    Returns
    -------
    scopes : List[`str`] or `None`
        The scopes generated from the group membership based on the
        ``group_mapping`` configuration parameter, or `None` if the user was
        not a member of any known group.
    """
    if not groups:
        return None

    scopes = set(["user:token"])
    found = False
    for group in [g.name for g in groups]:
        if group in config.group_mapping:
            found = True
            scopes.update(config.group_mapping[group])

    return sorted(scopes) if found else None


def login_error(
    context: RequestContext, error: LoginError, details: Optional[str] = None
) -> Response:
    """Generate an error page for a login failure.

    Report errors back to the user in a somewhat more human-readable form than
    a JSON error message.

    Parameters
    ----------
    context : `gafaelfawr.dependencies.config.RequestContext`
        The context of the incoming request.
    error : `LoginError`
        The type of error.
    details : `str`, optional
        Additional error details, if provided.

    Returns
    -------
    response : ``fastapi.Response``
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
        headers={"Cache-Control": "no-cache, must-revalidate"},
        status_code=status.HTTP_403_FORBIDDEN,
    )
