"""Handler for /.well-known/jwks.json."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aiohttp import web
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from jwt_authorizer.config import ALGORITHM
from jwt_authorizer.handlers import routes
from jwt_authorizer.util import number_to_base64

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

    private_key = load_pem_private_key(
        config.issuer.key, password=None, backend=default_backend()
    )
    public_numbers = private_key.public_key().public_numbers()
    key_metadata = {
        "alg": ALGORITHM,
        "kty": "RSA",
        "use": "sig",
        "n": number_to_base64(public_numbers.n).decode(),
        "e": number_to_base64(public_numbers.e).decode(),
        "kid": config.issuer.kid,
    }
    return web.json_response({"keys": [key_metadata]})
