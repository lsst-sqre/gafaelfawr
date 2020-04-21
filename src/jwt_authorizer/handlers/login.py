"""Initial authentication handlers (``/login``)."""

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING

from aiohttp import ClientResponseError, web
from aiohttp_session import get_session, new_session

from jwt_authorizer.handlers import routes
from jwt_authorizer.providers.base import ProviderException

if TYPE_CHECKING:
    from jwt_authorizer.config import Config
    from jwt_authorizer.factory import ComponentFactory
    from jwt_authorizer.providers.base import Provider
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
    logger: Logger = request["safir/logger"]
    config: Config = request.config_dict["jwt_authorizer/config"]
    factory: ComponentFactory = request.config_dict["jwt_authorizer/factory"]

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
        request_url = request.query.get("rd")
        if not request_url:
            request_url = request.headers.get("X-Auth-Request-Redirect")
        if not request_url:
            msg = "No destination URL specified"
            raise web.HTTPBadRequest(reason=msg, text=msg)
        if "state" in session:
            state = session["state"]
        else:
            state = base64.urlsafe_b64encode(os.urandom(16)).decode()
            session["state"] = state
        session["rd"] = request_url
        redirect_url = auth_provider.get_redirect_url(state)
        raise web.HTTPSeeOther(redirect_url)
