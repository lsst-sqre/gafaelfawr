"""Create tokens for testing."""

from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from gafaelfawr.factory import Factory
from gafaelfawr.models.enums import TokenChange, TokenType
from gafaelfawr.models.history import TokenChangeHistoryEntry
from gafaelfawr.models.token import Token, TokenData, TokenUserInfo
from gafaelfawr.models.userinfo import Group
from gafaelfawr.storage.history import TokenChangeHistoryStore
from gafaelfawr.storage.token import TokenDatabaseStore

__all__ = [
    "add_expired_session_token",
    "add_github_token",
    "create_session_token",
]


async def add_expired_session_token(
    user_info: TokenUserInfo,
    *,
    scopes: set[str],
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
    user_info
        User information to associate with the token.
    scopes
        Scopes of the token.
    ip_address
        IP address from which the request came.
    session
        Database session.
    """
    token_db_store = TokenDatabaseStore(session)
    token_change_store = TokenChangeHistoryStore(session)

    token = Token()
    created = datetime.now(tz=UTC).replace(microsecond=0)
    expires = created - timedelta(minutes=10)
    data = TokenData(
        token=token,
        token_type=TokenType.session,
        scopes=scopes,
        created=created,
        expires=expires,
        **user_info.model_dump(),
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


async def add_github_token(
    factory: Factory,
    *,
    username: str,
    github_project_id: int,
    scopes: set[str] | None = None,
    parent: str | None = None,
) -> TokenData:
    """Add a token minted by the GitHub Actions token exchange.

    Until the exchange endpoint exists, this requires going beneath the
    service layer. The token is added to both Redis and the database, with a
    creation history entry, so that it can be revoked and audited like a
    real one.

    Parameters
    ----------
    factory
        Factory used to create the backing stores.
    username
        Bot username of the token.
    github_project_id
        ID of the GitHub project that authorized the token.
    scopes
        Scopes of the token.
    parent
        Key of the parent token, if the token is a child token.

    Returns
    -------
    TokenData
        The data for the generated token.
    """
    token_db_store = TokenDatabaseStore(factory.session)
    token_change_store = TokenChangeHistoryStore(factory.session)
    token_redis_store = factory.create_token_redis_store()
    if scopes is None:
        scopes = {"read:all"}

    created = datetime.now(tz=UTC).replace(microsecond=0)
    expires = created + timedelta(hours=1)
    data = TokenData(
        token=Token(),
        username=username,
        token_type=TokenType.github,
        scopes=scopes,
        created=created,
        expires=expires,
    )
    history_entry = TokenChangeHistoryEntry(
        token=data.token.key,
        username=username,
        token_type=TokenType.github,
        parent=parent,
        scopes=scopes,
        expires=expires,
        actor=username,
        action=TokenChange.create,
        ip_address="192.0.2.1",
        event_time=created,
        github_project_id=github_project_id,
    )

    await token_redis_store.store_data(data)
    async with factory.session.begin():
        await token_db_store.add(
            data, parent=parent, github_project_id=github_project_id
        )
        await token_change_store.add(history_entry)
    return data


async def create_session_token(
    factory: Factory,
    *,
    username: str | None = None,
    group_names: list[str] | None = None,
    scopes: set[str] | None = None,
    minimal: bool = False,
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
    minimal
        Whether to generate a minimal token (one without any user
        information). Use this to test with external user information sources
        such as LDAP or Firestore, since otherwise the data stored with the
        token overrides the external source.

    Returns
    -------
    TokenData
        The data for the generated token.
    """
    if not username:
        username = "some-user"
    if group_names:
        groups = [Group(name=g, id=1000) for g in group_names]
    else:
        groups = []
    if minimal:
        user_info = TokenUserInfo(username=username, groups=groups)
    else:
        user_info = TokenUserInfo(
            username=username,
            name="Some User",
            email="someuser@example.com",
            uid=1000,
            gid=2000,
            groups=groups,
        )
    if scopes is None:
        scopes = {"user:token"}
    token_service = factory.create_token_service()
    token = await token_service.create_session_token(
        user_info, scopes=scopes, ip_address="127.0.0.1"
    )
    data = await token_service.get_data(token)
    assert data
    return data
