"""Initial authentication handlers (``/login``)."""

from __future__ import annotations

import base64
import os
from urllib.parse import urlparse

from aiohttp import ClientResponseError, web
from aiohttp_session import get_session, new_session

from gafaelfawr.handlers import routes
from gafaelfawr.handlers.util import RequestContext
from gafaelfawr.providers.base import ProviderException

__all__ = ["get_login"]


@routes.get("/login", name="login")
@routes.get("/oauth2/callback")
async def get_login(request: web.Request) -> web.Response:
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
    if "code" in request.query:
        return await handle_provider_return(request)
    else:
        return await redirect_to_provider(request)


async def redirect_to_provider(request: web.Request) -> web.Response:
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
    context = RequestContext.from_request(request)

    # Determine where the user is trying to go.
    session = await get_session(request)
    return_url = request.query.get("rd")
    if not return_url:
        return_url = request.headers.get("X-Auth-Request-Redirect")

    # Validate the return URL, including that it's at the same host as this
    # request.
    if not return_url:
        msg = "No destination URL specified"
        context.logger.warning(msg)
        raise web.HTTPBadRequest(reason=msg, text=msg)
    context.logger = context.logger.bind(return_url=return_url)
    if urlparse(return_url).hostname != request.url.raw_host:
        msg = f"Redirect URL not at {request.host}"
        context.logger.warning(msg)
        raise web.HTTPBadRequest(reason=msg, text=msg)
    session["rd"] = return_url

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
    if "state" in session:
        state = session["state"]
    else:
        state = base64.urlsafe_b64encode(os.urandom(16)).decode()
        session["state"] = state

    # Get the authentication provider URL send the user there.
    auth_provider = context.factory.create_provider()
    redirect_url = auth_provider.get_redirect_url(state)
    raise web.HTTPSeeOther(redirect_url)


async def handle_provider_return(request: web.Request) -> web.Response:
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
    context = RequestContext.from_request(request)

    # Extract details from the reply, check state, and get the return URL.
    session = await get_session(request)
    code = request.query["code"]
    state = request.query["state"]
    if request.query["state"] != session.pop("state", None):
        msg = "Authentication state mismatch"
        raise web.HTTPForbidden(reason=msg, text=msg)
    return_url = session.pop("rd")
    context.logger = context.logger.bind(return_url=return_url)

    # Build a session based on the reply from the authentication provider.
    auth_provider = context.factory.create_provider()
    try:
        auth_session = await auth_provider.create_session(code, state)
    except ProviderException as e:
        context.logger.warning("Provider authentication failed", error=str(e))
        raise web.HTTPInternalServerError(reason=str(e), text=str(e))
    except ClientResponseError as e:
        msg = "Cannot contact authentication provider"
        context.logger.exception(msg, error=str(e))
        raise web.HTTPInternalServerError(reason=msg, text=msg)

    # Store the session and send the user back to what they were doing.
    session = await new_session(request)
    session["handle"] = auth_session.handle.encode()
    context.logger = context.logger.bind(
        user=auth_session.token.username,
        token=auth_session.token.jti,
        scope=" ".join(sorted(auth_session.token.scope)),
    )
    context.logger.info(
        "Successfully authenticated user %s (%s)",
        auth_session.token.username,
        auth_session.token.uid,
    )
    raise web.HTTPSeeOther(return_url)
