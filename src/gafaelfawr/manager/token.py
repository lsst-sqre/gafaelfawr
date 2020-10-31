"""Manage tokens."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.models.token import TokenUserInfo

if TYPE_CHECKING:
    from typing import Optional

    from gafaelfawr.models.token import Token, TokenData, TokenInfo
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
        token_db_store: TokenDatabaseStore,
        token_redis_store: TokenRedisStore,
        transaction_manager: TransactionManager,
    ) -> None:
        self._token_db_store = token_db_store
        self._token_redis_store = token_redis_store
        self._transaction_manager = transaction_manager

    async def add(self, data: TokenData, name: Optional[str] = None) -> None:
        """Add a new token."""
        await self._token_redis_store.store_data(data)
        with self._transaction_manager.transaction():
            self._token_db_store.add(data, name)

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
