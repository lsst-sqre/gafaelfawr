"""Manage tokens."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from gafaelfawr.models.token import Token, TokenData, TokenType, TokenUserInfo

if TYPE_CHECKING:
    from typing import List, Optional

    from gafaelfawr.config import Config
    from gafaelfawr.models.token import TokenInfo
    from gafaelfawr.storage.token import TokenDatabaseStore, TokenRedisStore
    from gafaelfawr.storage.transaction import TransactionManager

__all__ = ["TokenManager"]


class TokenManager:
    """Manage tokens.

    Parameters
    ----------
    token_db_store : `gafaelfawr.storage.token.TokenDatabaseStore`
        The database backing store for tokens.
    token_redis_store : `gafaelfawr.storage.token.TokenRedisStore`
        The Redis backing store for tokens.
    transaction_manager : `gafaelfawr.storage.transaction.TransactionManager`
        Database transaction manager.
    """

    def __init__(
        self,
        config: Config,
        token_db_store: TokenDatabaseStore,
        token_redis_store: TokenRedisStore,
        transaction_manager: TransactionManager,
    ) -> None:
        self._config = config
        self._token_db_store = token_db_store
        self._token_redis_store = token_redis_store
        self._transaction_manager = transaction_manager

    async def create_session_token(
        self, userinfo: TokenUserInfo, *, scopes: Optional[List[str]] = None
    ) -> Token:
        """Add a new session token.

        Parameters
        ----------
        userinfo : `gafaelfawr.models.token.TokenUserInfo`
            The user information to associate with the token.
        scopes : List[`str`] or `None`
            The scopes of the token.

        Returns
        -------
        token : `gafaelfawr.models.token.Token`
            The newly-created token.
        """
        token = Token()
        created = datetime.now(tz=timezone.utc).replace(microsecond=0)
        expires = created + timedelta(minutes=self._config.issuer.exp_minutes)
        data = TokenData(
            token=token,
            token_type=TokenType.session,
            scopes=sorted(scopes) if scopes else [],
            created=created,
            expires=expires,
            **userinfo.dict(),
        )
        await self._token_redis_store.store_data(data)
        with self._transaction_manager.transaction():
            self._token_db_store.add(data)
        return token

    async def create_user_token(
        self,
        auth_data: TokenData,
        *,
        token_name: str,
        scopes: Optional[List[str]] = None,
        expires: Optional[datetime] = None,
    ) -> Token:
        """Add a new user token.

        Parameters
        ----------
        auth_data : `gafaelfawr.models.token.TokenData`
            The token data for the authentication token of the user creating
            a user token.
        token_name : `str`
            The name of the token.
        scopes : List[`str`] or `None`
            The scopes of the token.
        expires : `datetime` or `None`
            When the token should expire.  If not given, defaults to the
            expiration of the authentication token taken from ``data``.

        Returns
        -------
        token : `gafaelfawr.models.token.Token`
            The newly-created token.
        """
        token = Token()
        created = datetime.now(tz=timezone.utc).replace(microsecond=0)
        if not expires:
            expires = auth_data.expires
        data = TokenData(
            token=token,
            username=auth_data.username,
            token_type=TokenType.user,
            scopes=sorted(scopes) if scopes else [],
            created=created,
            expires=expires,
            name=auth_data.name,
            uid=auth_data.uid,
            groups=auth_data.groups,
        )
        await self._token_redis_store.store_data(data)
        with self._transaction_manager.transaction():
            self._token_db_store.add(data, token_name)
        return token

    async def get_data(self, token: Token) -> Optional[TokenData]:
        """Retrieve the data for a token from Redis.

        Doubles as a way to check the validity of the token.

        Parameters
        ----------
        token : `gafaelfawr.models.token.Token`
            The token.

        Returns
        -------
        data : `gafaelfawr.models.token.TokenData` or `None`
            The data underlying the token, or `None` if the token is not
            valid.
        """
        return await self._token_redis_store.get_data(token)

    def get_info(self, token: Token) -> Optional[TokenInfo]:
        """Get information about a token."""
        return self._token_db_store.get_info(token)

    async def get_user_info(self, token: Token) -> Optional[TokenUserInfo]:
        """Get user information associated with a token."""
        data = await self.get_data(token)
        if not data:
            return None
        return TokenUserInfo(
            username=data.username,
            name=data.name,
            uid=data.uid,
            groups=data.groups,
        )
