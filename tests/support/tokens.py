"""Create tokens for testing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt
from sqlalchemy.ext.asyncio import async_scoped_session

from gafaelfawr.config import Config
from gafaelfawr.constants import ALGORITHM
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.models.history import TokenChange, TokenChangeHistoryEntry
from gafaelfawr.models.oidc import OIDCVerifiedToken
from gafaelfawr.models.token import (
    Token,
    TokenData,
    TokenGroup,
    TokenType,
    TokenUserInfo,
)
from gafaelfawr.storage.history import TokenChangeHistoryStore
from gafaelfawr.storage.token import TokenDatabaseStore
from gafaelfawr.util import current_datetime

from .constants import TEST_KEYPAIR

__all__ = [
    "add_expired_session_token",
    "create_session_token",
    "create_test_token",
    "create_upstream_oidc_token",
]


async def add_expired_session_token(
    user_info: TokenUserInfo,
    *,
    scopes: List[str],
    ip_address: str,
    session: async_scoped_session,
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


async def create_session_token(
    factory: ComponentFactory,
    *,
    username: Optional[str] = None,
    group_names: Optional[List[str]] = None,
    scopes: Optional[List[str]] = None,
) -> TokenData:
    """Create a session token.

    Parameters
    ----------
    factory : `gafaelfawr.factory.ComponentFactory`
        Factory used to create services to add the token.
    username : `str`, optional
        Override the username of the generated token.
    group_namess : List[`str`], optional
        Group memberships the generated token should have.
    scopes : List[`str`], optional
        Scope for the generated token.

    Returns
    -------
    data : `gafaelfawr.models.token.TokenData`
        The data for the generated token.
    """
    if not username:
        username = "some-user"
    if group_names:
        groups = [TokenGroup(name=g, id=1000) for g in group_names]
    else:
        groups = []
    user_info = TokenUserInfo(
        username=username,
        name="Some User",
        email="someuser@example.com",
        uid=1000,
        groups=groups,
    )
    if not scopes:
        scopes = ["user:token"]
    token_service = factory.create_token_service()
    async with factory.session.begin():
        token = await token_service.create_session_token(
            user_info, scopes=scopes, ip_address="127.0.0.1"
        )
    data = await token_service.get_data(token)
    assert data
    return data


def create_test_token(
    config: Config,
    groups: Optional[List[str]] = None,
    *,
    keypair: Optional[RSAKeyPair] = None,
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
    keypair : `gafaelfawr.keypair.RSAKeyPair`, optional
        Key to use to sign the token.  Default is the internal issuer key.
    kid : str, optional
        The kid to set in the envelope.  Defaults to ``some-kid``.
    **claims : Union[`str`, `int`], optional
        Other claims to set or override in the token.

    Returns
    -------
    token : `gafaelfawr.tokens.VerifiedToken`
        The generated token.
    """
    if not keypair:
        assert config.oidc_server
        keypair = config.oidc_server.keypair
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=24)
    payload: Dict[str, Any] = {
        "aud": "https://example.com/",
        "email": "some-user@example.com",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": "some-unique-id",
        "sub": "some-user",
        "uid": "some-user",
        "uidNumber": "1000",
    }
    if config.oidc_server:
        payload["iss"] = config.oidc_server.issuer
    if groups:
        payload["isMemberOf"] = [
            {"name": g, "id": 1000 + n} for n, g in enumerate(groups)
        ]
    payload.update(claims)

    encoded = jwt.encode(
        payload,
        keypair.private_key_as_pem().decode(),
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
        Key ID for the token header.  Default is ``orig-kid``.
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
        kid = "orig-kid"
    payload = {
        "aud": config.oidc.audience,
        "iss": config.oidc.issuer,
        "jti": "some-upstream-id",
    }
    payload.update(claims)
    return create_test_token(
        config, groups=groups, keypair=TEST_KEYPAIR, kid=kid, **payload
    )
