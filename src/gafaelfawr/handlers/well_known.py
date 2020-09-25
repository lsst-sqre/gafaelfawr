"""Handler for /.well-known/jwks.json."""

from __future__ import annotations

from aiohttp import web

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.handlers import routes
from gafaelfawr.handlers.util import RequestContext

__all__ = [
    "get_well_known_jwks",
    "get_well_known_openid",
]


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


@routes.get("/.well-known/openid-configuration")
async def get_well_known_openid(request: web.Request) -> web.Response:
    """Handler for /.well-known/openid-configuration.

    Serve metadata about our OpenID Connect implementation.

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
    base_url = context.config.issuer.iss
    response = {
        "issuer": context.config.issuer.iss,
        "authorization_endpoint": base_url + "/auth/openid/login",
        "token_endpoint": base_url + "/auth/openid/token",
        "userinfo_endpoint": base_url + "/auth/userinfo",
        "jwks_uri": base_url + "/.well-known/jwks.json",
        "scopes_supported": ["openid"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [ALGORITHM],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    }
    context.logger.info("Returned OpenID Connect configuration")
    return web.json_response(response)
