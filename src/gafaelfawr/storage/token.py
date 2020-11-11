"""Storage for tokens."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from gafaelfawr.exceptions import DeserializeException
from gafaelfawr.models.token import TokenInfo
from gafaelfawr.schema.subtoken import Subtoken
from gafaelfawr.schema.token import Token as SQLToken

if TYPE_CHECKING:
    from typing import List, Optional

    from sqlalchemy.orm import Session
    from structlog import BoundLogger

    from gafaelfawr.models.token import Token, TokenData
    from gafaelfawr.storage.base import RedisStorage

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
    session : `sqlalchemy.orm.Session`
        The underlying database session.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(
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
        """
        new = SQLToken(
            token=data.token.key,
            username=data.username,
            token_type=data.token_type,
            token_name=token_name,
            scopes=",".join(sorted(data.scopes)) if data.scopes else None,
            service=service,
            created=data.created,
            expires=data.expires,
        )
        self._session.add(new)
        if parent:
            subtoken = Subtoken(parent=parent, child=data.token.key)
            self._session.add(subtoken)

    def delete(self, key: str) -> bool:
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
        return self._session.query(SQLToken).filter_by(token=key).delete() >= 1

    def get_info(self, key: str) -> Optional[TokenInfo]:
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
        field on `~gafaelfawr.schema.token.Token` objects, but that gets into
        gnarly and hard-to-understand SQLAlchemy ORM internals.  This approach
        still does only one database query without fancy ORM mappings at the
        cost of some irritating mangling of the return value.
        """
        result = (
            self._session.query(SQLToken, Subtoken.parent)
            .filter_by(token=key)
            .join(Subtoken, Subtoken.child == SQLToken.token, isouter=True)
            .one_or_none()
        )
        if result:
            info = TokenInfo.from_orm(result[0])
            info.parent = result[1]
            return info
        else:
            return None

    def list(self, *, username: Optional[str] = None) -> List[TokenInfo]:
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
        if username:
            tokens = (
                self._session.query(SQLToken)
                .filter_by(username=username)
                .order_by(SQLToken.token)
            )
        else:
            tokens = self._session.query(SQLToken).order_by(SQLToken.token)
        return [TokenInfo.from_orm(t) for t in tokens]

    def modify(
        self,
        key: str,
        *,
        token_name: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        expires: Optional[datetime] = None,
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

        Returns
        -------
        info : `gafaelfawr.models.token.TokenInfo`
            Information for the updated token.
        """
        token = self._session.query(SQLToken).filter_by(token=key).scalar()
        if not token:
            return None
        if token_name:
            token.token_name = token_name
        if scopes:
            token.scopes = ",".join(sorted(scopes))
        if expires:
            token.expires = expires
        return TokenInfo.from_orm(token)


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
    logger : `structlog.BoundLogger`
        Logger for diagnostics.
    """

    def __init__(
        self,
        storage: RedisStorage[TokenData],
        logger: BoundLogger,
    ) -> None:
        self._storage = storage
        self._logger = logger

    async def delete(self, key: str) -> None:
        """Delete a token from Redis.

        This only requires the token key, not the full token, so that users
        can delete tokens for their account without needing possession of the
        token.

        Parameters
        ----------
        key : `str`
            The key portion of the token.
        """
        await self._storage.delete(f"token:{key}")

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
        try:
            data = await self._storage.get(f"token:{token.key}")
        except DeserializeException as e:
            self._logger.error("Cannot retrieve token", error=str(e))
            return None
        if not data:
            print("not found", token.key)
            return None

        if data.token != token:
            error = f"Secret mismatch for {token.key}"
            self._logger.error("Cannot retrieve token data", error=error)
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
