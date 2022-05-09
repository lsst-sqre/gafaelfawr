"""Log out handler (``/logout``)."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, status
from fastapi.responses import RedirectResponse

from ..dependencies.context import RequestContext, context_dependency
from ..dependencies.return_url import return_url
from ..models.state import State

router = APIRouter()

__all__ = ["get_logout"]


@router.get(
    "/logout",
    response_class=RedirectResponse,
    responses={307: {"description": "Redirect to landing page"}},
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    summary="Log out",
    tags=["browser"],
)
async def get_logout(
    return_url: Optional[str] = Depends(return_url),
    context: RequestContext = Depends(context_dependency),
) -> str:
    """Log out and redirect the user.

    The user is redirected to the URL given in the rd parameter, if any, and
    otherwise to the after_logout_url configuration setting.

    If the user was logged in via GitHub (and Gafaelfawr is still configured
    to use GitHub), the GitHub OAuth authorization grant is also revoked.
    """
    if context.state.token:
        auth_provider = context.factory.create_provider()
        await auth_provider.logout(context.state)
        context.logger.info("Successful logout")
    else:
        context.logger.info("Logout of already-logged-out session")
    context.state = State()

    if not return_url:
        return_url = context.config.after_logout_url
    return return_url
