"""Log out handler (``/logout``)."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from fastapi.responses import RedirectResponse

from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.dependencies.return_url import return_url
from gafaelfawr.models.state import State

router = APIRouter()

__all__ = ["get_logout"]


@router.get("/logout")
async def get_logout(
    return_url: Optional[str] = Depends(return_url),
    context: RequestContext = Depends(context_dependency),
) -> RedirectResponse:
    """Log out and redirect the user.

    The user is redirected to the URL given in the rd parameter, if any, and
    otherwise to the after_logout_url configuration setting.
    """
    if context.request.state.cookie.handle:
        context.logger.info("Successful logout")
    else:
        context.logger.info("Logout of already-logged-out session")
    context.request.state.cookie = State()

    if not return_url:
        return_url = context.config.after_logout_url
    return RedirectResponse(return_url)
