"""Storage for tokens."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, cast

from safir.database import datetime_to_db
from sqlalchemy import delete
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import async_scoped_session
from sqlalchemy.future import select
from structlog.stdlib import BoundLogger

from ..exceptions import DeserializeError, DuplicateTokenNameError
from ..models.token import Token, TokenData, TokenInfo, TokenType
from ..schema.subtoken import Subtoken
from ..schema.token import Token as SQLToken
from .base import RedisStorage

__all__ = ["TokenDatabaseStore", "TokenRedisStore"]


class TokenDatabaseStore:
    """Stores and manipulates tokens in the database.

    Tokens exist in both Redis and in the database.  Redis is the source of
    truth for the validity of the token and the only data store that holds the
    supplemental user information that will eventually be replaced by an
    identity management system.  The database is the canonical store for
    user-given token names and for the relationship between tokens.

    Parameters
    ----------
    session : `sqlalchemy.ext.asyncio.async_scoped_session`
        The database session proxy.
    """

    def __init__(self, session: async_scoped_session) -> None:
        self._session = session

    async def add(
        self,
        data: TokenData,
        *,
        token_name: Optional[str] = None,
        service: Optional[str] = None,
        parent: Optional[str] = None,
    ) -> None:
        """Store a new token.

        Parameters
        ----------
        data : `gafaelfawr.models.token.TokenData`
            The corresponding data.
        token_name : `str`, optional
            The human-given name for the token.
        service : `str`, optional
            The service for an internal token.
        parent : `str`, optional
            The key of the parent of this token.

        Raises
        ------
        gafaelfawr.exceptions.DuplicateTokenNameError
            The user already has a token by that name.
        """
        if token_name:
            await self._check_name_conflict(data.username, token_name)
        new = SQLToken(
            token=data.token.key,
            username=data.username,
            token_type=data.token_type,
            token_name=token_name,
            scopes=",".join(sorted(data.scopes)),
            service=service,
            created=datetime_to_db(data.created),
            expires=datetime_to_db(data.expires),
        )
        self._session.add(new)
        await self._session.flush()
        if parent:
            subtoken = Subtoken(parent=parent, child=data.token.key)
            self._session.add(subtoken)

    async def delete(self, key: str) -> bool:
        """Delete a token.

        Parameters
        ----------
        token : `str`
            The key of the token to delete.

        Returns
        -------
        success : `bool`
            Whether the token was found to be deleted.
        """
        stmt = delete(SQLToken).where(SQLToken.token == key)
        result = cast(CursorResult, await self._session.execute(stmt))
        return result.rowcount >= 1

    async def delete_expired(self) -> List[TokenInfo]:
        """Delete entries for expired tokens from the database.

        Returns
        -------
        deleted : List[`gafaelfawr.models.token.TokenInfo`]
            The deleted tokens.
        """
        now = datetime.utcnow()

        # Start by finding all tokens that have expired and gather their
        # information, which in turn will be used to construct history entries
        # by the caller.  This is the same query as get_info, except that it
        # asks for the information for all the tokens at once, saving database
        # round trips.
        deleted = []
        stmt = (
            select(SQLToken, Subtoken.parent)
            .where(SQLToken.expires <= now)
            .join(Subtoken, Subtoken.child == SQLToken.token, isouter=True)
        )
        tokens = await self._session.execute(stmt)
        for token, parent in tokens.all():
            info = TokenInfo.from_orm(token)
            info.parent = parent
            deleted.append(info)

        # Delete the tokens.  In the (broken) case that there is a child token
        # with an expiration ahead of its parent token, this orphans the child
        # token rather than deleting it.  (In other words, it doesn't
        # implement cascading delete semantics.)  These anomalies will be
        # caught by a separate audit pass.
        to_delete = [d.token for d in deleted]
        delete_stmt = delete(SQLToken).where(SQLToken.token.in_(to_delete))
        await self._session.execute(delete_stmt)

        # Return the info for the deleted tokens.
        return deleted

    async def get_children(self, key: str) -> List[str]:
        """Return all children (recursively) of a token.

        Parameters
        ----------
        key : `str`
            The key of the token.

        Returns
        -------
        children : List[`str`]
            The keys of all child tokens of that token, recursively.  The
            direct child tokens will be at the beginning of the list, and
            other tokens will be listed in a breadth-first search order.
        """
        all_children = []
        parents = [key]
        while parents:
            stmt = select(Subtoken.child).where(Subtoken.parent.in_(parents))
            result = await self._session.scalars(stmt)
            children = result.all()
            all_children.extend(children)
            parents = children
        return all_children

    async def get_info(self, key: str) -> Optional[TokenInfo]:
        """Return information about a token.

        Parameters
        ----------
        key : `str`
            The key of the token.

        Returns
        -------
        info : `gafaelfawr.models.token.TokenInfo` or `None`
            Information about that token or `None` if it doesn't exist in the
            database.

        Notes
        -----
        There is probably some way to materialize parent as a relationship
        field on the ORM Token objects, but that gets into gnarly and
        hard-to-understand SQLAlchemy ORM internals.  This approach still does
        only one database query without fancy ORM mappings at the cost of some
        irritating mangling of the return value.
        """
        stmt = (
            select(SQLToken, Subtoken.parent)
            .where(SQLToken.token == key)
            .join(Subtoken, Subtoken.child == SQLToken.token, isouter=True)
        )
        result = (await self._session.execute(stmt)).one_or_none()
        if not result:
            return None
        token, parent = result
        info = TokenInfo.from_orm(token)
        info.parent = parent
        return info

    async def get_internal_token_key(
        self,
        token_data: TokenData,
        service: str,
        scopes: List[str],
        min_expires: datetime,
    ) -> Optional[str]:
        """Retrieve an existing internal child token.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The data for the parent token.
        service : `str`
            The service to which the internal token is delegated.
        scopes : List[`str`]
            The scopes of the delegated token.
        min_expires : `datetime.datetime`
            The minimum expiration time for the token.

        Returns
        -------
        key : `str` or `None`
            The key of an existing internal child token with the desired
            properties, or `None` if none exist.
        """
        stmt = (
            select(Subtoken.child)
            .where(Subtoken.parent == token_data.token.key)
            .join(SQLToken, Subtoken.child == SQLToken.token)
            .where(
                SQLToken.token_type == TokenType.internal,
                SQLToken.service == service,
                SQLToken.scopes == ",".join(sorted(scopes)),
                SQLToken.expires >= datetime_to_db(min_expires),
            )
            .limit(1)
        )
        return await self._session.scalar(stmt)

    async def get_notebook_token_key(
        self, token_data: TokenData, min_expires: datetime
    ) -> Optional[str]:
        """Retrieve an existing notebook child token.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The data for the parent token.
        min_expires : `datetime.datetime`
            The minimum expiration time for the token.

        Returns
        -------
        key : `str` or `None`
            The key of an existing notebook child token, or `None` if none
            exist.
        """
        stmt = (
            select(Subtoken.child)
            .where(Subtoken.parent == token_data.token.key)
            .join(SQLToken, Subtoken.child == SQLToken.token)
            .where(
                SQLToken.token_type == TokenType.notebook,
                SQLToken.expires >= datetime_to_db(min_expires),
            )
            .limit(1)
        )
        return await self._session.scalar(stmt)

    async def list(self, *, username: Optional[str] = None) -> List[TokenInfo]:
        """List tokens.

        Parameters
        ----------
        username : `str` or `None`
            Limit the returned tokens to ones for the given username.

        Returns
        -------
        tokens : List[`gafaelfawr.models.token.TokenInfo`]
            Information about the tokens.
        """
        stmt = select(SQLToken)
        if username:
            stmt = stmt.where(SQLToken.username == username)
        stmt = stmt.order_by(
            SQLToken.last_used.desc(),
            SQLToken.created.desc(),
            SQLToken.token,
        )
        result = await self._session.scalars(stmt)
        return [TokenInfo.from_orm(t) for t in result.all()]

    async def modify(
        self,
        key: str,
        *,
        token_name: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        expires: Optional[datetime] = None,
        no_expire: bool = False,
    ) -> Optional[TokenInfo]:
        """Modify a token.

        Parameters
        ----------
        token : `str`
            The token to modify.
        token_name : `str`, optional
            The new name for the token.
        scopes : List[`str`], optional
            The new scopes for the token.
        expires : `datetime`, optional
            The new expiration time for the token.
        no_expire : `bool`
            If set, the token should not expire.  This is a separate parameter
            because passing `None` to ``expires`` is ambiguous.

        Returns
        -------
        info : `gafaelfawr.models.token.TokenInfo` or `None`
            Information for the updated token or `None` if it was not found.

        Raises
        ------
        gafaelfawr.exceptions.DuplicateTokenNameError
            The user already has a token by that name.
        """
        stmt = select(SQLToken).where(SQLToken.token == key)
        token = await self._session.scalar(stmt)
        if not token:
            return None
        if token_name and token.token_name != token_name:
            await self._check_name_conflict(token.username, token_name)
            token.token_name = token_name
        if scopes:
            token.scopes = ",".join(sorted(scopes))
        if no_expire:
            token.expires = None
        elif expires:
            token.expires = datetime_to_db(expires)
        return TokenInfo.from_orm(token)

    async def _check_name_conflict(
        self, username: str, token_name: str
    ) -> None:
        """Raise exception if the given token name is already used."""
        stmt = select(SQLToken.token).filter_by(
            username=username, token_name=token_name
        )
        name_conflict = await self._session.scalar(stmt)
        if name_conflict:
            msg = f"Token name {token_name} already used"
            raise DuplicateTokenNameError(msg)


class TokenRedisStore:
    """Stores and retrieves token data in Redis.

    Tokens are stored with the key of the token as the Redis key and the data
    of the token as encrypted JSON, including the secret portion of the token.
    To retrieve a token, the caller must provide the full token and the secret
    in the token must match the secret retrieved from Redis.

    This setup means that an attacker who can list the keys in Redis cannot
    use those keys directly as tokens and still needs access to the stored
    Redis data plus the decryption key to be able to reconstruct a token.

    Parameters
    ----------
    storage : `gafaelfawr.storage.base.RedisStorage`
        The underlying storage.
    logger : `structlog.stdlib.BoundLogger`
        Logger for diagnostics.
    """

    def __init__(
        self,
        storage: RedisStorage[TokenData],
        logger: BoundLogger,
    ) -> None:
        self._storage = storage
        self._logger = logger

    async def delete(self, key: str) -> bool:
        """Delete a token from Redis.

        This only requires the token key, not the full token, so that users
        can delete tokens for their account without needing possession of the
        token.

        Parameters
        ----------
        key : `str`
            The key portion of the token.

        Returns
        -------
        success : `bool`
            `True` if the token was found and deleted, `False` otherwise.
        """
        return await self._storage.delete(f"token:{key}")

    async def delete_all(self) -> None:
        """Delete all stored tokens."""
        await self._storage.delete_all("token:*")

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
        data = await self.get_data_by_key(token.key)
        if not data:
            return None

        if data.token != token:
            error = f"Secret mismatch for {token.key}"
            self._logger.error("Cannot retrieve token data", error=error)
            return None

        return data

    async def get_data_by_key(self, key: str) -> Optional[TokenData]:
        """Retrieve the data for a token from Redis by its key.

        This method allows retrieving a working token while bypassing the
        check that the caller is in possession of the secret, and therefore
        must never be used with user-supplied keys.

        Parameters
        ----------
        key : `str`
            The key of the token.

        Returns
        -------
        data : `gafaelfawr.models.token.TokenData` or `None`
            The data underlying the token, or `None` if the token is not
            valid.
        """
        try:
            data = await self._storage.get(f"token:{key}")
        except DeserializeError as e:
            self._logger.error("Cannot retrieve token", error=str(e))
            return None
        return data

    async def store_data(self, data: TokenData) -> None:
        """Store the data for a token.

        Parameters
        ----------
        data : `gafaelfawr.models.token.TokenData`
            The data underlying that token.
        """
        lifetime = None
        if data.expires:
            now = datetime.now(tz=timezone.utc)
            lifetime = int((data.expires - now).total_seconds())
        await self._storage.store(f"token:{data.token.key}", data, lifetime)
