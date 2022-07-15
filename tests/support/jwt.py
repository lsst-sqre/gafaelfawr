"""Create JWTs for testing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.models.oidc import OIDCVerifiedToken

from .constants import TEST_KEYPAIR

__all__ = ["create_upstream_oidc_jwt"]


def create_upstream_oidc_jwt(
    *,
    kid: str = "orig-kid",
    groups: Optional[List[str]] = None,
    **claims: Any,
) -> OIDCVerifiedToken:
    """Create a signed token using the OpenID Connect issuer.

    This will match the issuer and audience of the issuer for an OpenID
    Connect authentication.

    Parameters
    ----------
    kid : `str`, optional
        Key ID for the token header.  Default is ``orig-kid``.
    groups : List[`str`], optional
        Group memberships the generated token should have.
    **claims : `str`, optional
        Other claims to set or override in the token.

    Returns
    -------
    token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
        The new token.
    """
    config = config_dependency.config()
    assert config.oidc

    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=24)
    payload: Dict[str, Any] = {
        "aud": config.oidc.audience,
        "email": "some-user@example.com",
        "iat": int(now.timestamp()),
        "iss": config.oidc.issuer,
        "exp": int(exp.timestamp()),
        "jti": "some-upstream-id",
        "kid": kid,
        "sub": "some-user",
        "uid": "some-user",
        "uidNumber": "1000",
    }
    if groups:
        payload["isMemberOf"] = [
            {"name": g, "id": 1000 + n} for n, g in enumerate(groups)
        ]
    payload.update(claims)
    for claim, value in claims.items():
        if value is None:
            del payload[claim]

    encoded = jwt.encode(
        payload,
        TEST_KEYPAIR.private_key_as_pem().decode(),
        algorithm=ALGORITHM,
        headers={"kid": kid},
    )

    return OIDCVerifiedToken(
        encoded=encoded, claims=payload, jti=payload["jti"]
    )
