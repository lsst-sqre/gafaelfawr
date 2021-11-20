"""Create tokens for testing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import jwt

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.models.history import TokenChange, TokenChangeHistoryEntry
from gafaelfawr.models.oidc import OIDCVerifiedToken
from gafaelfawr.models.token import Token, TokenData, TokenType, TokenUserInfo
from gafaelfawr.storage.history import TokenChangeHistoryStore
from gafaelfawr.storage.token import TokenDatabaseStore
from gafaelfawr.util import current_datetime

if TYPE_CHECKING:
    from typing import Any, Dict, List, Optional

    from sqlalchemy.ext.asyncio import AsyncSession

    from gafaelfawr.config import Config

__all__ = ["create_test_token", "create_upstream_oidc_token"]


async def add_expired_session_token(
    user_info: TokenUserInfo,
    *,
    scopes: List[str],
    ip_address: str,
    session: AsyncSession,
) -> None:
    """Add an expired session token to the database.

    This requires going beneath the service layer, since the service layer
    rejects creation of expired tokens (since apart from testing this isn't a
    sensible thing to want to do).

    This does not add the token to Redis, since Redis will refuse to add it
    with a negative expiration time, so can only be used for tests that
    exclusively use the database.

    Parameters
    ----------
    user_info : `gafaelfawr.models.token.TokenUserInfo`
        The user information to associate with the token.
    scopes : List[`str`]
        The scopes of the token.
    ip_address : `str`
        The IP address from which the request came.
    session : `sqlalchemy.ext.asyncio.AsyncSession`
        The database session.
    """
    token_db_store = TokenDatabaseStore(session)
    token_change_store = TokenChangeHistoryStore(session)

    token = Token()
    created = current_datetime()
    expires = created - timedelta(minutes=10)
    data = TokenData(
        token=token,
        token_type=TokenType.session,
        scopes=scopes,
        created=created,
        expires=expires,
        **user_info.dict(),
    )
    history_entry = TokenChangeHistoryEntry(
        token=token.key,
        username=data.username,
        token_type=TokenType.session,
        scopes=scopes,
        expires=expires,
        actor=data.username,
        action=TokenChange.create,
        ip_address=ip_address,
        event_time=created,
    )

    await token_db_store.add(data)
    await token_change_store.add(history_entry)


def create_test_token(
    config: Config,
    groups: Optional[List[str]] = None,
    *,
    kid: str = "some-kid",
    **claims: Any,
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
        config.issuer.keypair.private_key_as_pem().decode(),
        algorithm=ALGORITHM,
        headers={"kid": kid},
    )

    return OIDCVerifiedToken(
        encoded=encoded,
        claims=payload,
        jti=payload["jti"],
        username=payload["uid"],
        uid=payload["uidNumber"],
        email=payload["email"],
        scope=set(payload.get("scope", "").split()),
    )


async def create_upstream_oidc_token(
    *,
    kid: Optional[str] = None,
    groups: Optional[List[str]] = None,
    **claims: Any,
) -> OIDCVerifiedToken:
    """Create a signed token using the OpenID Connect issuer.

    This will match the issuer and audience of the issuer for an OpenID
    Connect authentication.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        The configuration.
    kid : `str`, optional
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
    config = await config_dependency()
    assert config.oidc
    if not kid:
        kid = config.oidc.key_ids[0]
    payload = {
        "aud": config.oidc.audience,
        "iss": config.oidc.issuer,
        "jti": "some-upstream-id",
    }
    payload.update(claims)
    return create_test_token(config, groups=groups, kid=kid, **payload)
