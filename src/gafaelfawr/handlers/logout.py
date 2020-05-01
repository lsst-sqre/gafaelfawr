"""Log out handler (``/logout``)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from aiohttp import web
from aiohttp_session import get_session

from gafaelfawr.handlers import routes

if TYPE_CHECKING:
    from gafaelfawr.config import Config
    from structlog import BoundLogger

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
    config: Config = request.config_dict["gafaelfawr/config"]
    logger: BoundLogger = request["safir/logger"]

    session = await get_session(request)
    session.invalidate()

    redirect_url = request.query.get("rd")
    if redirect_url:
        if urlparse(redirect_url).hostname != request.url.raw_host:
            msg = f"Redirect URL not at {request.host}"
            logger.warning(msg)
            raise web.HTTPBadRequest(reason=msg, text=msg)
    else:
        redirect_url = config.after_logout_url

    raise web.HTTPSeeOther(redirect_url)
