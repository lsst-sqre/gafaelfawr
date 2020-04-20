"""Create tokens for testing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import jwt

from jwt_authorizer.constants import ALGORITHM
from jwt_authorizer.session import SessionHandle
from jwt_authorizer.tokens import VerifiedToken

if TYPE_CHECKING:
    from tests.support.config import ConfigForTests
    from typing import Any, Dict, List, Optional

__all__ = ["create_test_token", "create_upstream_test_token"]


def create_test_token(
    config: ConfigForTests,
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
    config : `tests.support.config.ConfigForTests`
        The test configuration.
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
        "iss": config.internal_issuer_url,
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
        config.keypair.private_key_as_pem(),
        algorithm=ALGORITHM,
        headers={"kid": kid},
    ).decode()

    return VerifiedToken(encoded=encoded, claims=payload)


def create_upstream_test_token(
    config: ConfigForTests, **claims: str
) -> VerifiedToken:
    """Create a signed token using the upstream issuer.

    This will match the issuer and audience of the upstream issuer for an
    OpenID Connect authentication, so JWT Authorizer will reissue it.

    Parameters
    ----------
    config : `tests.support.config.ConfigForTests`
        The test configuration.
    **claims : `str`, optional
        Other attributes to set or override in the token.

    Returns
    -------
    token : `jwt_authorizer.tokens.VerifiedToken`
        The new token.
    """
    handle = SessionHandle()
    payload = {
        "aud": "https://test.example.com/",
        "iss": "https://upstream.example.com/",
        "jti": handle.key,
    }
    payload.update(claims)
    return create_test_token(
        config, groups=["admin"], kid="orig-kid", **payload
    )
