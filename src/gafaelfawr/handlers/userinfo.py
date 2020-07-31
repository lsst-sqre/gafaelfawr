"""Handler for the user information route (``/auth/userinfo``)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aiohttp import web

from gafaelfawr.handlers import routes
from gafaelfawr.handlers.decorators import authenticated_jwt
from gafaelfawr.handlers.util import RequestContext

if TYPE_CHECKING:
    from gafaelfawr.tokens import VerifiedToken

__all__ = ["get_userinfo"]


@routes.get("/auth/userinfo")
@authenticated_jwt
async def get_userinfo(
    request: web.Request, token: VerifiedToken
) -> web.Response:
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
    context = RequestContext.from_request(request)
    context.logger.info("Returned user information")
    return web.json_response(token.claims)
