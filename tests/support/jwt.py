"""Create JWTs for testing."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import jwt
from safir.datetime import current_datetime

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.models.oidc import OIDCVerifiedToken

from .constants import TEST_KEYPAIR

__all__ = ["create_upstream_oidc_jwt"]


def create_upstream_oidc_jwt(
    username: str | list[str] | None,
    *,
    kid: str = "orig-kid",
) -> OIDCVerifiedToken:
    """Create a signed token using the OpenID Connect issuer.

    This will match the issuer and audience of the issuer for an OpenID
    Connect authentication.

    Parameters
    ----------
    username
        Username to embed in the token. Also accepts a list to test invalid
        syntax handling, or `None` to omit the claim.
    kid
        Key ID for the token header.

    Returns
    -------
    OIDCVerifiedToken
        The new token.
    """
    config = config_dependency.config()
    assert config.oidc

    now = current_datetime()
    exp = now + timedelta(days=24)
    payload: dict[str, Any] = {
        "aud": config.oidc.audience,
        "iat": int(now.timestamp()),
        "iss": config.oidc.issuer,
        "exp": int(exp.timestamp()),
        "jti": "some-upstream-id",
        "kid": kid,
    }
    if username:
        payload[config.oidc.username_claim] = username

    encoded = jwt.encode(
        payload,
        TEST_KEYPAIR.private_key_as_pem().decode(),
        algorithm=ALGORITHM,
        headers={"kid": kid},
    )

    return OIDCVerifiedToken(
        encoded=encoded, claims=payload, jti=payload["jti"]
    )
