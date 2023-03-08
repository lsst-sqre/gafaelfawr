"""Create tokens for testing."""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from safir.datetime import current_datetime
from sqlalchemy.ext.asyncio import async_scoped_session

from gafaelfawr.factory import Factory
from gafaelfawr.models.history import TokenChange, TokenChangeHistoryEntry
from gafaelfawr.models.token import (
    Token,
    TokenData,
    TokenGroup,
    TokenType,
    TokenUserInfo,
)
from gafaelfawr.storage.history import TokenChangeHistoryStore
from gafaelfawr.storage.token import TokenDatabaseStore

__all__ = [
    "add_expired_session_token",
    "create_session_token",
]


async def add_expired_session_token(
    user_info: TokenUserInfo,
    *,
    scopes: list[str],
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
    user_info
        The user information to associate with the token.
    scopes
        The scopes of the token.
    ip_address
        The IP address from which the request came.
    session
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
    factory: Factory,
    *,
    username: Optional[str] = None,
    group_names: Optional[list[str]] = None,
    scopes: Optional[list[str]] = None,
) -> TokenData:
    """Create a session token.

    Parameters
    ----------
    factory
        Factory used to create services to add the token.
    username
        Override the username of the generated token.
    group_names
        Group memberships the generated token should have.
    scopes
        Scope for the generated token.

    Returns
    -------
    TokenData
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
        gid=2000,
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
