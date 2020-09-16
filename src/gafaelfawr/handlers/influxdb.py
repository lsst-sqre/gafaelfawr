"""Handler for generating an InfluxDB token (``/auth/tokens/influxdb/new``)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aiohttp import web

from gafaelfawr.exceptions import NotConfiguredException
from gafaelfawr.handlers import routes
from gafaelfawr.handlers.decorators import authenticated_token
from gafaelfawr.handlers.util import RequestContext

if TYPE_CHECKING:
    from gafaelfawr.tokens import VerifiedToken

__all__ = ["get_influxdb"]


@routes.get("/auth/tokens/influxdb/new")
@authenticated_token
async def get_influxdb(
    request: web.Request, token: VerifiedToken
) -> web.Response:
    """Return an InfluxDB-compatible JWT.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    token : `gafaelfawr.tokens.VerifiedToken`
        The user's authentication token.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    context = RequestContext.from_request(request)
    token_issuer = context.factory.create_token_issuer()
    try:
        influxdb_token = token_issuer.issue_influxdb_token(token)
    except NotConfiguredException as e:
        context.logger.warning("Not configured", error=str(e))
        response = {"error": "not_supported", "error_description": str(e)}
        return web.json_response(response, status=400)
    if context.config.issuer.influxdb_username:
        username = context.config.issuer.influxdb_username
    else:
        username = token.username
    context.logger.info("Issued InfluxDB token", influxdb_username=username)
    return web.json_response({"token": influxdb_token})
