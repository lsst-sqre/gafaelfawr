"""Manage tokens."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from gafaelfawr.exceptions import PermissionDeniedError
from gafaelfawr.models.token import Token, TokenData, TokenType, TokenUserInfo

if TYPE_CHECKING:
    from typing import List, Optional

    from gafaelfawr.config import Config
    from gafaelfawr.models.token import TokenInfo
    from gafaelfawr.storage.token import TokenDatabaseStore, TokenRedisStore
    from gafaelfawr.storage.transaction import TransactionManager

__all__ = ["TokenService"]


class TokenService:
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
        self, user_info: TokenUserInfo, scopes: Optional[List[str]] = None
    ) -> Token:
        """Add a new session token.

        Parameters
        ----------
        user_info : `gafaelfawr.models.token.TokenUserInfo`
            The user information to associate with the token.
        scopes : List[`str`], optional
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
            **user_info.dict(),
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
            self._token_db_store.add(data, token_name=token_name)
        return token

    async def delete_token(self, key: str, auth_data: TokenData) -> bool:
        """Delete a token.

        Parameters
        ----------
        key : `str`
            The key of the token to delete.
        auth_data : `gafaelfawr.models.token.TokenData`
            The token data for the authentication token of the user deleting
            the token.

        Returns
        -------
        success : `bool`
            Whether the token was found and deleted.
        """
        info = self.get_info(key)
        if not info:
            return False
        if info.username != auth_data.username:
            msg = f"Token owned by {info.username}, not {auth_data.username}"
            raise PermissionDeniedError(msg)
        await self._token_redis_store.delete(key)
        with self._transaction_manager.transaction():
            return self._token_db_store.delete(key)

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

    def get_info(self, key: str) -> Optional[TokenInfo]:
        """Get information about a token."""
        return self._token_db_store.get_info(key)

    async def get_internal_token(
        self, token_data: TokenData, service: str, scopes: List[str]
    ) -> Token:
        """Get or create a new internal token.

        The new token will have the same expiration time as the existing token
        on which it's based unless that expiration time is longer than the
        expiration time of normal interactive tokens, in which case it will be
        capped at the interactive token expiration time.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data on which to base the new token.
        service : `str`
            The internal service to which the token is delegated.
        scopes : List[`str`]
            The scopes the new token should have.

        Returns
        -------
        token : `gafaelfawr.models.token.Token`
            The newly-created token.
        """
        if not set(scopes) <= set(token_data.scopes):
            raise PermissionDeniedError("Token does not have required scopes")

        # See if there's already a matching internal token.
        key = self._token_db_store.get_internal_token_key(
            token_data, service, scopes
        )
        if key:
            data = await self._token_redis_store.get_data_by_key(key)
            if data:
                return data.token

        # There is not, so we need to create a new one.
        token = Token()
        created = datetime.now(tz=timezone.utc).replace(microsecond=0)
        expires = created + timedelta(minutes=self._config.issuer.exp_minutes)
        if token_data.expires and token_data.expires < expires:
            expires = token_data.expires
        data = TokenData(
            token=token,
            username=token_data.username,
            token_type=TokenType.internal,
            scopes=scopes,
            created=created,
            expires=expires,
            name=token_data.name,
            uid=token_data.uid,
            groups=token_data.groups,
        )
        await self._token_redis_store.store_data(data)
        with self._transaction_manager.transaction():
            self._token_db_store.add(
                data, service=service, parent=token_data.token.key
            )
        return token

    async def get_notebook_token(self, token_data: TokenData) -> Token:
        """Get or create a new notebook token.

        The new token will have the same expiration time as the existing token
        on which it's based unless that expiration time is longer than the
        expiration time of normal interactive tokens, in which case it will be
        capped at the interactive token expiration time.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data on which to base the new token.

        Returns
        -------
        token : `gafaelfawr.models.token.Token`
            The newly-created token.
        """
        # See if there's already a matching notebook token.
        key = self._token_db_store.get_notebook_token_key(token_data)
        if key:
            data = await self._token_redis_store.get_data_by_key(key)
            if data:
                return data.token

        # There is not, so we need to create a new one.
        token = Token()
        created = datetime.now(tz=timezone.utc).replace(microsecond=0)
        expires = created + timedelta(minutes=self._config.issuer.exp_minutes)
        if token_data.expires and token_data.expires < expires:
            expires = token_data.expires
        data = TokenData(
            token=token,
            username=token_data.username,
            token_type=TokenType.notebook,
            scopes=token_data.scopes,
            created=created,
            expires=expires,
            name=token_data.name,
            uid=token_data.uid,
            groups=token_data.groups,
        )
        await self._token_redis_store.store_data(data)
        with self._transaction_manager.transaction():
            self._token_db_store.add(data, parent=token_data.token.key)
        return token

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

    def list_tokens(
        self, auth_data: TokenData, username: Optional[str] = None
    ) -> List[TokenInfo]:
        """List tokens.

        Parameters
        ----------
        auth_data : `gafaelfawr.models.token.TokenData`
            The token data for the authentication token of the user making
            this modification.
        username : `str`, optional
            Limit results to the given username.

        Returns
        -------
        info : List[`gafaelfawr.models.token.TokenInfo`]
            Information for all matching tokens.

        Raises
        ------
        gafaelfawr.exceptions.PermissionDeniedError
            The user whose tokens are being listed does not match the
            authentication information.
        """
        if username and username != auth_data.username:
            msg = f"{auth_data.username} cannot list tokens for {username}"
            raise PermissionDeniedError(msg)
        return self._token_db_store.list(username=username)

    def modify_token(
        self,
        key: str,
        auth_data: TokenData,
        *,
        token_name: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        expires: Optional[datetime] = None,
    ) -> Optional[TokenInfo]:
        """Modify a token.

        Parameters
        ----------
        key : `str`
            The key of the token to modify.
        auth_data : `gafaelfawr.models.token.TokenData`
            The token data for the authentication token of the user making
            this modification.
        token_name : `str`, optional
            The new name for the token.
        scopes : List[`str`], optional
            The new scopes for the token.
        expires : `datetime`, optional
            The new expiration time for the token.

        Returns
        -------
        info : `gafaelfawr.models.token.TokenInfo` or `None`
            Information for the updated token or `None` if it was not found.

        Raises
        ------
        gafaelfawr.exceptions.PermissionDeniedError
            The token being modified is not owned by the user identified with
            ``auth_data``.
        """
        info = self.get_info(key)
        if not info:
            return None
        if info.username != auth_data.username:
            msg = f"Token owned by {info.username}, not {auth_data.username}"
            raise PermissionDeniedError(msg)
        with self._transaction_manager.transaction():
            return self._token_db_store.modify(
                key, token_name=token_name, scopes=scopes, expires=expires
            )
