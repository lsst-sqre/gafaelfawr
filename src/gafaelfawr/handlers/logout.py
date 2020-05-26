"""Log out handler (``/logout``)."""

from __future__ import annotations

from urllib.parse import urlparse

from aiohttp import web
from aiohttp_session import get_session

from gafaelfawr.handlers import routes
from gafaelfawr.handlers.util import RequestContext

__all__ = ["get_logout"]


@routes.get("/logout")
async def get_logout(request: web.Request) -> web.Response:
    """Log out and redirect the user.

    The user is redirected to the URL given in the rd parameter, if any, and
    otherwise to the after_logout_url configuration setting.

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
    aiohttp.web.HTTPException
        Redirect the  user to the desired destination, or return an error if
        the requested redirect URL is not valid.
    """
    context = RequestContext.from_request(request)
    session = await get_session(request)
    if session.get("handle"):
        context.logger.info("Successful logout")
    else:
        context.logger.info("Logout of already-logged-out session")
    session.invalidate()

    redirect_url = request.query.get("rd")
    if redirect_url:
        if urlparse(redirect_url).hostname != request.url.raw_host:
            msg = f"Redirect URL not at {request.host}"
            context.logger.warning(msg)
            raise web.HTTPBadRequest(reason=msg, text=msg)
    else:
        redirect_url = context.config.after_logout_url

    raise web.HTTPSeeOther(redirect_url)
