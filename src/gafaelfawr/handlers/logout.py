"""Log out handler (``/logout``)."""

from __future__ import annotations

from typing import Optional

from fastapi import Depends
from fastapi.responses import RedirectResponse

from gafaelfawr.dependencies import RequestContext, context
from gafaelfawr.dependencies.return_url import return_url
from gafaelfawr.handlers import router
from gafaelfawr.middleware.state import State

__all__ = ["get_logout"]


@router.get("/logout")
async def get_logout(
    return_url: Optional[str] = Depends(return_url),
    context: RequestContext = Depends(context),
) -> RedirectResponse:
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
    if context.request.state.cookie.handle:
        context.logger.info("Successful logout")
    else:
        context.logger.info("Logout of already-logged-out session")
    context.request.state.cookie = State()

    if not return_url:
        return_url = context.config.after_logout_url
    return RedirectResponse(return_url)
