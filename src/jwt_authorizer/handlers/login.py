"""Initial authentication handlers (``/login``)."""

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING

from aiohttp import web
from aiohttp_session import get_session, new_session

from jwt_authorizer.handlers import routes
from jwt_authorizer.issuer import TokenIssuer
from jwt_authorizer.providers import GitHubProvider
from jwt_authorizer.session import SessionStore

if TYPE_CHECKING:
    from aiohttp import ClientSession
    from aioredis import Redis
    from jwt_authorizer.config import Config


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
    config: Config = request.config_dict["jwt_authorizer/config"]
    redis: Redis = request.config_dict["jwt_authorizer/redis"]
    http_session: ClientSession = request["safir/http_session"]

    if not config.github:
        raise NotImplementedError("No configured authentication provider")
    auth_provider = GitHubProvider(config.github, http_session)

    if "code" in request.query:
        session = await get_session(request)
        code = request.query["code"]
        state = request.query["state"]
        if request.query["state"] != session.pop("state"):
            msg = "OAuth state mismatch"
            raise web.HTTPForbidden(reason=msg, text=msg)
        return_url = session.pop("rd")

        github_token = await auth_provider.get_access_token(code, state)
        user_info = await auth_provider.get_user_info(github_token)

        ticket_prefix = config.session_store.ticket_prefix
        session_store = SessionStore(
            ticket_prefix, config.session_store.oauth2_proxy_secret, redis
        )
        issuer = TokenIssuer(
            config.issuer, ticket_prefix, session_store, redis
        )
        ticket = await issuer.issue_token_from_github(user_info)

        session = await new_session(request)
        session.set_new_identity(ticket.encode(ticket_prefix))

        raise web.HTTPSeeOther(return_url)
    else:
        session = await new_session(request)
        request_url = request.query["rd"]
        state = base64.urlsafe_b64encode(os.urandom(16)).decode()
        session["rd"] = request_url
        session["state"] = state
        redirect_url = auth_provider.get_redirect_url(state)
        raise web.HTTPSeeOther(redirect_url)
