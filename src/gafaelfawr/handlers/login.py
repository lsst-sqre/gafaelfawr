"""Initial authentication handlers (``/login``)."""

from __future__ import annotations

import base64
import os
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from httpx import HTTPError

from gafaelfawr.dependencies import RequestContext, context
from gafaelfawr.dependencies.return_url import return_url_with_header
from gafaelfawr.exceptions import ProviderException
from gafaelfawr.handlers import router

__all__ = ["get_login"]


@router.get("/login")
@router.get("/oauth2/callback")
async def get_login(
    code: Optional[str] = None,
    state: Optional[str] = None,
    return_url: Optional[str] = Depends(return_url_with_header),
    context: RequestContext = Depends(context),
) -> RedirectResponse:
    """Handle an initial login.

    Constructs the authentication URL and redirects the user to the
    authentication provider.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        Incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.

    Raises
    ------
    NotImplementedError
        If no authentication provider is configured.

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
    request : `aiohttp.web.Request`
        Incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.

    Raises
    ------
    aiohttp.web.HTTPError
        Error or redirect depending on the validity of the response from the
        external authentication provider.
    """
    if not return_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "loc": ["query", "rd"],
                "type": "return_url_missing",
                "msg": "No return URL given",
            },
        )
    context.request.state.cookie.return_url = return_url

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
    state = context.request.state.cookie.state
    if not state:
        state = base64.urlsafe_b64encode(os.urandom(16)).decode()
        context.request.state.cookie.state = state

    # Get the authentication provider URL send the user there.
    auth_provider = context.factory.create_provider()
    redirect_url = auth_provider.get_redirect_url(state)
    return RedirectResponse(redirect_url)


async def handle_provider_return(
    code: str, state: Optional[str], context: RequestContext
) -> RedirectResponse:
    """Handle the return from an external authentication provider.

    Handles the target of the redirect back from an external authentication
    provider with new authentication state information.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        Incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.

    Raises
    ------
    aiohttp.web.HTTPError
        Error or redirect depending on the validity of the response from the
        external authentication provider.
    """
    cookie = context.request.state.cookie

    # Extract details from the reply, check state, and get the return URL.
    if state != cookie.state:
        msg = "Authentication state mismatch"
        context.logger.warning("Authentication failed", error=msg)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "msg": "Authentication state mismatch",
                "type": "state_mismatch",
            },
        )
    return_url = cookie.return_url
    context.rebind_logger(return_url=return_url)

    # Build a session based on the reply from the authentication provider.
    auth_provider = context.factory.create_provider()
    try:
        session = await auth_provider.create_session(code, state)
    except ProviderException as e:
        context.logger.warning("Provider authentication failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"type": "provider_failed", "msg": str(e)},
        )
    except HTTPError as e:
        msg = "Cannot contact authentication provider"
        context.logger.exception(msg, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "type": "provider_connect_failed",
                "msg": f"{msg}: {str(e)}",
            },
        )

    # Successful login, so clear the login state and send the user back to
    # what they were doing.
    cookie.state = None
    cookie.return_url = None
    cookie.handle = session.handle
    context.logger.info(
        "Successfully authenticated user %s (%s)",
        session.token.username,
        session.token.uid,
        user=session.token.username,
        token=session.token.jti,
        scope=" ".join(sorted(session.token.scope)),
    )
    return RedirectResponse(return_url)
