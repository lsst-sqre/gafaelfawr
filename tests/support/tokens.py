"""Create tokens for testing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import jwt

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.models.oidc import OIDCVerifiedToken

if TYPE_CHECKING:
    from typing import Any, Dict, List, Optional, Union

    from gafaelfawr.config import Config

__all__ = ["create_test_token", "create_upstream_oidc_token"]


def create_test_token(
    config: Config,
    groups: Optional[List[str]] = None,
    *,
    kid: str = "some-kid",
    **claims: Union[str, int],
) -> OIDCVerifiedToken:
    """Create a signed token using the configured test issuer.

    This will match the issuer and audience of the default JWT Authorizer
    issuer, so JWT Authorizer will not attempt to reissue it.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        The configuration.
    groups : List[`str`], optional
        Group memberships the generated token should have.
    kid : str, optional
        The kid to set in the envelope.  Defaults to ``some-kid``.
    **claims : Union[`str`, `int`], optional
        Other claims to set or override in the token.

    Returns
    -------
    token : `gafaelfawr.tokens.VerifiedToken`
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
        payload["isMemberOf"] = [
            {"name": g, "id": 1000 + n} for n, g in enumerate(groups)
        ]
    payload.update(claims)

    encoded = jwt.encode(
        payload,
        config.issuer.keypair.private_key_as_pem(),
        algorithm=ALGORITHM,
        headers={"kid": kid},
    ).decode()

    return OIDCVerifiedToken(
        encoded=encoded,
        claims=payload,
        jti=payload["jti"],
        username=payload["uid"],
        uid=payload["uidNumber"],
        email=payload["email"],
        scope=set(payload.get("scope", "").split()),
    )


def create_upstream_oidc_token(
    config: Config,
    kid: str,
    *,
    groups: Optional[List[str]] = None,
    **claims: str,
) -> OIDCVerifiedToken:
    """Create a signed token using the OpenID Connect issuer.

    This will match the issuer and audience of the issuer for an OpenID
    Connect authentication.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        The configuration.
    kid : `str`
        Key ID for the token header.
    groups : List[`str`], optional
        Group memberships the generated token should have.
    **claims : `str`, optional
        Other claims to set or override in the token.

    Returns
    -------
    token : `gafaelfawr.tokens.VerifiedToken`
        The new token.
    """
    assert config.oidc
    payload = {
        "aud": config.oidc.audience,
        "iss": config.oidc.issuer,
        "jti": "some-upstream-id",
    }
    payload.update(claims)
    return create_test_token(config, groups=groups, kid=kid, **payload)
