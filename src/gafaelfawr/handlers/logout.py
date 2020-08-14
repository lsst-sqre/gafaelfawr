"""Log out handler (``/logout``)."""

from __future__ import annotations

from aiohttp import web
from aiohttp_session import get_session

from gafaelfawr.handlers import routes
from gafaelfawr.handlers.util import RequestContext, validate_return_url

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

    return_url = request.query.get("rd")
    if return_url:
        validate_return_url(context, return_url)
    else:
        return_url = context.config.after_logout_url
    raise web.HTTPSeeOther(return_url)
