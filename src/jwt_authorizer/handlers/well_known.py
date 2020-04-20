"""Handler for /.well-known/jwks.json."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aiohttp import web

from jwt_authorizer.handlers import routes

if TYPE_CHECKING:
    from jwt_authorizer.config import Config

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
    config: Config = request.config_dict["jwt_authorizer/config"]

    jwks = config.issuer.keypair.public_key_as_jwks(kid=config.issuer.kid)
    return web.json_response({"keys": [jwks]})
