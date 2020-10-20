"""Handler for the user information route (``/auth/userinfo``)."""

from __future__ import annotations

from typing import Any, Mapping

from fastapi import Depends

from gafaelfawr.auth import verified_token
from gafaelfawr.dependencies import RequestContext, context
from gafaelfawr.handlers import router
from gafaelfawr.tokens import VerifiedToken

__all__ = ["get_userinfo"]


@router.get("/auth/userinfo")
async def get_userinfo(
    context: RequestContext = Depends(context),
    token: VerifiedToken = Depends(verified_token),
) -> Mapping[str, Any]:
    """Return information about the holder of a JWT.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    token : `gafaelfawr.tokens.VerifiedToken`
        The token of the authenticated user.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    context.logger.info("Returned user information")
    return token.claims
