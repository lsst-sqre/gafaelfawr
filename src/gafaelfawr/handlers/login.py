"""Initial authentication handlers (``/login``)."""

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from aiohttp import ClientResponseError, web
from aiohttp_session import get_session, new_session

from gafaelfawr.handlers import routes
from gafaelfawr.providers.base import ProviderException

if TYPE_CHECKING:
    from gafaelfawr.config import Config
    from gafaelfawr.factory import ComponentFactory
    from gafaelfawr.providers.base import Provider
    from logging import Logger

__all__ = ["get_login", "get_oauth2_callback"]


@routes.get("/login", name="login")
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
    This generates new authentication state each time the user goes to the
    /login handler.  In practice, JavaScript may kick off multiple
    authentication attempts at the same time, which can cause a successful
    authentication to be rejected if another request has overridden the state.
    The state should be reused for some interval.
    """
    return await _login(request)


@routes.get("/oauth2/callback")
async def get_oauth2_callback(request: web.Request) -> web.Response:
    """Alias for /login for oauth2_proxy support.

    Export the login handler on the route used by oauth2_proxy for
    compatibility with older oauth2_proxy installations.  This avoids needing
    to change the redirect_uri registered with an OpenID Connect provider.  It
    can be removed once all registrations have been updated with the /login
    route.

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
    """
    return await _login(request)


async def _login(request: web.Request) -> web.Response:
    """Internal implementation of get_login and get_oauth2_callback."""
    config: Config = request.config_dict["gafaelfawr/config"]
    factory: ComponentFactory = request.config_dict["gafaelfawr/factory"]
    logger: Logger = request["safir/logger"]

    if config.github:
        auth_provider: Provider = factory.create_github_provider(request)
    elif config.oidc:
        auth_provider = factory.create_oidc_provider(request)
    else:
        raise NotImplementedError("No authentication provider configured")

    if "code" in request.query:
        session = await get_session(request)
        code = request.query["code"]
        state = request.query["state"]
        if request.query["state"] != session.pop("state", None):
            msg = "Authentication state mismatch"
            raise web.HTTPForbidden(reason=msg, text=msg)
        return_url = session.pop("rd")

        try:
            auth_session = await auth_provider.create_session(code, state)
        except ProviderException as e:
            logger.warning("Provider authentication failed: %s", str(e))
            raise web.HTTPInternalServerError(reason=str(e), text=str(e))
        except ClientResponseError:
            msg = "Cannot contact authentication provider"
            logger.exception(msg)
            raise web.HTTPInternalServerError(reason=msg, text=msg)

        session = await new_session(request)
        session["handle"] = auth_session.handle.encode()

        logger.info(
            "Successfully authenticated user %s (%s)",
            auth_session.token.username,
            auth_session.token.uid,
        )
        raise web.HTTPSeeOther(return_url)
    else:
        session = await get_session(request)
        return_url = request.query.get("rd")
        if not return_url:
            return_url = request.headers.get("X-Auth-Request-Redirect")

        if not return_url:
            msg = "No destination URL specified"
            logger.warning(msg)
            raise web.HTTPBadRequest(reason=msg, text=msg)
        if urlparse(return_url).hostname != request.url.raw_host:
            msg = f"Redirect URL not at {request.host}"
            logger.warning(msg)
            raise web.HTTPBadRequest(reason=msg, text=msg)

        # Reuse the existing state if one already exists in the session
        # cookie.
        #
        # This is subtle and requires some explanation.  Most modern webapps
        # involve a lot of background JavaScript.  If the user has a tab open
        # when their session expires, those background JavaScript requests
        # will start turning into redirects to Gafaelfawr and thus to this
        # code.  Since there isn't a good way to see whether a request is a
        # background JavaScript request versus a browser loading a page, we
        # will generate an authentication redirect for each one.
        #
        # This means that if we generate new random state for each request,
        # there is a race condition.  The user may go to a page with an
        # expired session and get redirected to log in.  While they are
        # logging in at the external provider, another open tab may kick off
        # one of these JavaScript requests, which generates a new redirect and
        # replaces the state stored in their session cookie.  Then, when they
        # return from authentication, the state will have changed, and the
        # authentication attempt will fail.
        #
        # Work around this by reusing the same random state until the user
        # completes an authentication.  This does not entirely close the
        # window for the race condition because it's possible that two
        # requests will both see sessions without state, both generate state,
        # and then both set cookies, and only one of them will win.  However,
        # that race condition window is much smaller and is unlikely to
        # persist across authentication requests.
        if "state" in session:
            state = session["state"]
        else:
            state = base64.urlsafe_b64encode(os.urandom(16)).decode()
            session["state"] = state

        session["rd"] = return_url
        redirect_url = auth_provider.get_redirect_url(state)
        raise web.HTTPSeeOther(redirect_url)
