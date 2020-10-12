"""Handler for ``/.well-known`` routes."""

from __future__ import annotations

from typing import Dict, List

from fastapi import Depends
from pydantic import BaseModel

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.fastapi.dependencies import RequestContext, context
from gafaelfawr.fastapi.handlers import router

__all__ = [
    "get_well_known_jwks",
    "get_well_known_openid",
]


class KeySet(BaseModel):
    keys: List[Dict[str, str]]
    """List of valid signing keys."""


class OpenIdConfig(BaseModel):
    issuer: str
    """The ``iss`` value for JWTs."""

    authorization_endpoint: str
    """Where to initiate a login."""

    token_endpoint: str
    """Where to retrieve tokens."""

    userinfo_endpoint: str
    """Where to get user information from a token."""

    jwks_uri: str
    """Where to get the valid signing keys."""

    scopes_supported: List[str] = ["openid"]
    """Valid scopes for an authentication request."""

    response_types_supported: List[str] = ["code"]
    """Valid response types in an authentication request."""

    grant_types_supported: List[str] = ["authorization_code"]
    """Valid grant types in an authentication request."""

    subject_types_supported: List[str] = ["public"]
    """Valid subject types in an authentication request."""

    id_token_signing_alg_values_supported: List[str] = [ALGORITHM]
    """Supported JWT algorithms used to sign returned tokens."""

    token_endpoint_auth_methods_supported: List[str] = ["client_secret_post"]
    """Supported mechanisms to authenticate to the token endpoint."""


@router.get("/.well-known/jwks.json", response_model=KeySet)
async def get_well_known_jwks(
    context: RequestContext = Depends(context),
) -> KeySet:
    """Handler for /.well-known/jwks.json.

    Serve metadata about our signing key.

    Parameters
    ----------
    context : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The outgoing response.
    """
    keypair = context.config.issuer.keypair
    jwks = keypair.public_key_as_jwks(kid=context.config.issuer.kid)
    context.logger.info("Returned JWKS")
    return KeySet(keys=[jwks])


@router.get("/.well-known/openid-configuration", response_model=OpenIdConfig)
async def get_well_known_openid(
    context: RequestContext = Depends(context),
) -> OpenIdConfig:
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
    base_url = context.config.issuer.iss
    context.logger.info("Returned OpenID Connect configuration")
    return OpenIdConfig(
        issuer=context.config.issuer.iss,
        authorization_endpoint=base_url + "/auth/openid/login",
        token_endpoint=base_url + "/auth/openid/token",
        userinfo_endpoint=base_url + "/auth/userinfo",
        jwks_uri=base_url + "/.well-known/jwks.json",
    )
