"""Create tokens for testing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import jwt

from jwt_authorizer.constants import ALGORITHM
from jwt_authorizer.tokens import VerifiedToken

if TYPE_CHECKING:
    from jwt_authorizer.config import Config
    from typing import Any, Dict, List, Optional

__all__ = ["create_oidc_test_token", "create_test_token"]


def create_test_token(
    config: Config,
    *,
    groups: Optional[List[str]] = None,
    kid: str = "some-kid",
    **claims: str,
) -> VerifiedToken:
    """Create a signed token using the configured test issuer.

    This will match the issuer and audience of the default JWT Authorizer
    issuer, so JWT Authorizer will not attempt to reissue it.

    Parameters
    ----------
    config : `jwt_authorizer.config.Config`
        The configuration.
    groups : List[`str`], optional
        Group memberships the generated token should have.
    kid : str, optional
        The kid to set in the envelope.  Defaults to ``some-kid``.
    **claims : `str`, optional
        Other attributes to set or override in the token.

    Returns
    -------
    token : `jwt_authorizer.tokens.VerifiedToken`
        The generated token.
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=24)
    payload: Dict[str, Any] = {
        "aud": "https://example.com/",
        "email": "some-user@example.com",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": config.issuer.iss,
        "jti": "some-unique-id",
        "sub": "some-user",
        "uid": "some-user",
        "uidNumber": "1000",
    }
    if groups:
        payload["isMemberOf"] = [{"name": g} for g in groups]
    payload.update(claims)

    encoded = jwt.encode(
        payload,
        config.issuer.keypair.private_key_as_pem(),
        algorithm=ALGORITHM,
        headers={"kid": kid},
    ).decode()

    return VerifiedToken(
        encoded=encoded,
        claims=payload,
        jti=payload["jti"],
        username=payload["uid"],
        uid=payload["uidNumber"],
        email=payload["email"],
        scope=payload.get("scope"),
    )


def create_oidc_test_token(
    config: Config, *, groups: Optional[List[str]] = None, **claims: str,
) -> VerifiedToken:
    """Create a signed token using the OpenID Connect issuer.

    This will match the issuer and audience of the issuer for an OpenID
    Connect authentication.

    Parameters
    ----------
    config : `jwt_authorizer.config.Config`
        The configuration.
    groups : List[`str`], optional
        Group memberships the generated token should have.
    **claims : `str`, optional
        Other attributes to set or override in the token.

    Returns
    -------
    token : `jwt_authorizer.tokens.VerifiedToken`
        The new token.
    """
    payload = {
        "aud": "https://test.example.com/",
        "iss": "https://upstream.example.com/",
        "jti": "some-upstream-id",
    }
    payload.update(claims)
    return create_test_token(config, groups=groups, kid="orig-kid", **payload)
