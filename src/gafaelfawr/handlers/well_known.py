"""Handler for /.well-known/jwks.json."""

from __future__ import annotations

from aiohttp import web

from gafaelfawr.handlers import routes
from gafaelfawr.handlers.util import RequestContext

__all__ = ["get_well_known_jwks"]


@routes.get("/.well-known/jwks.json")
async def get_well_known_jwks(request: web.Request) -> web.Response:
    """Handler for /.well-known/jwks.json.

    Serve metadata about our signing key.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The outgoing response.
    """
    context = RequestContext.from_request(request)
    keypair = context.config.issuer.keypair
    jwks = keypair.public_key_as_jwks(kid=context.config.issuer.kid)
    context.logger.info("Returned JWKS")
    return web.json_response({"keys": [jwks]})
