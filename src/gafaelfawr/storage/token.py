"""Storage for tokens."""

from __future__ import annotations

from datetime import datetime

from safir.database import datetime_to_db
from safir.datetime import current_datetime
from safir.redis import DeserializeError, EncryptedPydanticRedisStorage
from safir.slack.webhook import SlackWebhookClient
from sqlalchemy import delete, distinct, func, or_, select
from sqlalchemy.ext.asyncio import async_scoped_session
from structlog.stdlib import BoundLogger

from ..exceptions import DuplicateTokenNameError
from ..models.token import Token, TokenData, TokenInfo, TokenType
from ..schema.subtoken import Subtoken
from ..schema.token import Token as SQLToken

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
    session
        The database session proxy.
    """

    def __init__(self, session: async_scoped_session) -> None:
        self._session = session

    async def add(
        self,
        data: TokenData,
        *,
        token_name: str | None = None,
        parent: str | None = None,
    ) -> None:
        """Store a new token.

        Parameters
        ----------
        data
            The corresponding data.
        token_name
            The human-given name for the token.
        service
            The service for an internal token.
        parent
            The key of the parent of this token.

        Raises
        ------
        DuplicateTokenNameError
            Raised if the user already has a token by that name.
        """
        if token_name:
            await self._check_name_conflict(data.username, token_name)
        new = SQLToken(
            token=data.token.key,
            username=data.username,
            token_type=data.token_type,
            token_name=token_name,
            scopes=",".join(sorted(data.scopes)),
            service=data.service,
            created=datetime_to_db(data.created),
            expires=datetime_to_db(data.expires),
        )
        self._session.add(new)
        await self._session.flush()
        if parent:
            subtoken = Subtoken(parent=parent, child=data.token.key)
            self._session.add(subtoken)

    async def count_unique_sessions(self) -> int:
        """Count the number of unique users with active session tokens.

        Returns
        -------
        int
            Count of users.
        """
        stmt = select(func.count(distinct(SQLToken.username))).where(
            SQLToken.expires > datetime_to_db(current_datetime())
        )
        result = await self._session.execute(stmt)
        return result.scalar_one()

    async def count_user_tokens(self) -> int:
        """Count the number of unexpired user tokens.

        Returns
        -------
        int
            Count of user tokens.
        """
        stmt = (
            select(func.count())
            .select_from(SQLToken)
            .where(
                SQLToken.token_type == TokenType.user,
                or_(
                    SQLToken.expires.is_(None),
                    SQLToken.expires > datetime_to_db(current_datetime()),
                ),
            )
        )
        result = await self._session.execute(stmt)
        return result.scalar_one()

    async def delete(self, key: str) -> bool:
        """Delete a token.

        Parameters
        ----------
        token
            The key of the token to delete.

        Returns
        -------
        bool
            Whether the token was found to be deleted.
        """
        stmt = delete(SQLToken).where(SQLToken.token == key)
        result = await self._session.execute(stmt)
        return result.rowcount >= 1

    async def delete_expired(self) -> list[TokenInfo]:
        """Delete entries for expired tokens from the database.

        Returns
        -------
        list of TokenInfo
            The deleted tokens.
        """
        now = datetime_to_db(current_datetime())

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
            info = TokenInfo.model_validate(token)
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

    async def get_children(self, key: str) -> list[str]:
        """Return all children (recursively) of a token.

        Parameters
        ----------
        str
            The key of the token.

        Returns
        -------
        list of str
            The keys of all child tokens of that token, recursively.  The
            direct child tokens will be at the beginning of the list, and
            other tokens will be listed in a breadth-first search order.
        """
        all_children: list[str] = []
        parents = [key]
        while parents:
            stmt = select(Subtoken.child).where(Subtoken.parent.in_(parents))
            result = await self._session.scalars(stmt)
            children = result.all()
            all_children.extend(children)
            parents = list(children)
        return all_children

    async def get_info(self, key: str) -> TokenInfo | None:
        """Return information about a token.

        Parameters
        ----------
        key
            The key of the token.

        Returns
        -------
        TokenInfo or None
            Information about that token or `None` if it doesn't exist in the
            database.
        """
        # There is probably some way to materialize parent as a relationship
        # field on the ORM Token objects, but that gets into gnarly and
        # hard-to-understand SQLAlchemy ORM internals.  This approach still
        # does only one database query without fancy ORM mappings at the cost
        # of some irritating mangling of the return value.
        stmt = (
            select(SQLToken, Subtoken.parent)
            .where(SQLToken.token == key)
            .join(Subtoken, Subtoken.child == SQLToken.token, isouter=True)
        )
        result = (await self._session.execute(stmt)).one_or_none()
        if not result:
            return None
        token, parent = result
        info = TokenInfo.model_validate(token)
        info.parent = parent
        return info

    async def get_internal_token_key(
        self,
        token_data: TokenData,
        service: str,
        scopes: list[str],
        min_expires: datetime,
    ) -> str | None:
        """Retrieve an existing internal child token.

        Parameters
        ----------
        token_data
            The data for the parent token.
        service
            The service to which the internal token is delegated.
        scopes
            The scopes of the delegated token.
        min_expires
            The minimum expiration time for the token.

        Returns
        -------
        str or None
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
    ) -> str | None:
        """Retrieve an existing notebook child token.

        Parameters
        ----------
        token_data
            The data for the parent token.
        min_expires
            The minimum expiration time for the token.

        Returns
        -------
        str or None
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

    async def list_tokens(
        self,
        *,
        username: str | None = None,
        token_type: TokenType | None = None,
        limit: int | None = None,
    ) -> list[TokenInfo]:
        """List tokens.

        Parameters
        ----------
        username
            Limit the returned tokens to ones for the given username.
        token_type
            Limit the returned tokens to ones of the given type.
        limit
            Limit the number of tokens returned to this count.

        Returns
        -------
        list of TokenInfo
            Information about the tokens.
        """
        stmt = select(SQLToken)
        if username:
            stmt = stmt.where(SQLToken.username == username)
        if token_type:
            stmt = stmt.where(SQLToken.token_type == token_type)
        stmt = stmt.order_by(
            SQLToken.last_used.desc(),
            SQLToken.created.desc(),
            SQLToken.token,
        )
        if limit:
            stmt = stmt.limit(limit)
        result = await self._session.scalars(stmt)
        return [TokenInfo.model_validate(t) for t in result.all()]

    async def list_orphaned(self) -> list[TokenInfo]:
        """List all orphaned tokens.

        Tokens are orphaned if they appear in the subtoken table but their
        parent column is null.

        Returns
        -------
        list of TokenInfo
            Information about the tokens.
        """
        stmt = (
            select(SQLToken)
            .join(Subtoken, Subtoken.child == SQLToken.token)
            .where(Subtoken.parent.is_(None))
        )
        result = await self._session.scalars(stmt)
        return [TokenInfo.model_validate(t) for t in result.all()]

    async def list_with_parents(self) -> list[TokenInfo]:
        """List all tokens including parent information.

        This is a slower and more expensive query than `list`, used for
        audits.

        Returns
        -------
        list of TokenInfo
            Information about the tokens.
        """
        stmt = (
            select(SQLToken, Subtoken.parent)
            .join(Subtoken, Subtoken.child == SQLToken.token, isouter=True)
            .order_by(
                SQLToken.last_used.desc(),
                SQLToken.created.desc(),
                SQLToken.token,
            )
        )
        results = await self._session.execute(stmt)
        token_info = []
        for result in results.all():
            token, parent = result
            info = TokenInfo.model_validate(token)
            info.parent = parent
            token_info.append(info)
        return token_info

    async def modify(
        self,
        key: str,
        *,
        token_name: str | None = None,
        scopes: list[str] | None = None,
        expires: datetime | None = None,
        no_expire: bool = False,
    ) -> TokenInfo | None:
        """Modify a token.

        Parameters
        ----------
        token
            The token to modify.
        token_name
            The new name for the token.
        scopes
            The new scopes for the token.
        expires
            The new expiration time for the token.
        no_expire
            If set, the token should not expire.  This is a separate parameter
            because passing `None` to ``expires`` is ambiguous.

        Returns
        -------
        TokenInfo or None
            Information for the updated token or `None` if it was not found.

        Raises
        ------
        DuplicateTokenNameError
            Raised if the user already has a token by that name.
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
        return TokenInfo.model_validate(token)

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
    storage
        Underlying storage for token data.
    slack_client
        If provided, Slack webhook client to report deserialization errors of
        Redis data.
    logger
        Logger for diagnostics.
    """

    def __init__(
        self,
        storage: EncryptedPydanticRedisStorage[TokenData],
        slack_client: SlackWebhookClient | None,
        logger: BoundLogger,
    ) -> None:
        self._storage = storage
        self._slack = slack_client
        self._logger = logger

    async def delete(self, key: str) -> bool:
        """Delete a token from Redis.

        This only requires the token key, not the full token, so that users
        can delete tokens for their account without needing possession of the
        token.

        Parameters
        ----------
        key
            The key portion of the token.

        Returns
        -------
        bool
            `True` if the token was found and deleted, `False` otherwise.
        """
        return await self._storage.delete(key)

    async def delete_all(self) -> None:
        """Delete all stored tokens."""
        await self._storage.delete_all("*")

    async def get_data(self, token: Token) -> TokenData | None:
        """Retrieve the data for a token from Redis.

        Doubles as a way to check the validity of the token.

        Parameters
        ----------
        token
            The token.

        Returns
        -------
        TokenData or None
            The data underlying the token, or `None` if the token is not
            valid.
        """
        data = await self.get_data_by_key(token.key)
        if not data:
            return None

        if data.token != token:
            error = f"Secret mismatch for {token.key}"
            self._logger.warning("Cannot retrieve token data", error=error)
            return None

        return data

    async def get_data_by_key(self, key: str) -> TokenData | None:
        """Retrieve the data for a token from Redis by its key.

        This method allows retrieving a working token while bypassing the
        check that the caller is in possession of the secret, and therefore
        must never be used with user-supplied keys.

        Parameters
        ----------
        key
            The key of the token.

        Returns
        -------
        TokenData or None
            The data underlying the token, or `None` if the token is not
            valid.
        """
        try:
            data = await self._storage.get(key)
        except DeserializeError as e:
            self._logger.exception("Cannot retrieve token", error=str(e))
            if self._slack:
                await self._slack.post_exception(e)
            return None
        return data

    async def list(self) -> list[str]:
        """List all token keys stored in Redis.

        Returns
        -------
        list of str
            The tokens found in Redis (by looking for valid keys).
        """
        return [k async for k in self._storage.scan("*")]

    async def store_data(self, data: TokenData) -> None:
        """Store the data for a token.

        Parameters
        ----------
        data
            The data underlying that token.
        """
        lifetime = None
        if data.expires:
            now = current_datetime()
            lifetime = int((data.expires - now).total_seconds())
        await self._storage.store(data.token.key, data, lifetime)
