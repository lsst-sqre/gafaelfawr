"""Storage for tokens."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.exceptions import DeserializeException
from gafaelfawr.models.token import TokenInfo
from gafaelfawr.schema.token import Token as SQLToken

if TYPE_CHECKING:
    from typing import Optional

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

    def add(self, data: TokenData, token_name: Optional[str] = None) -> None:
        """Store a new token.

        Parameters
        ----------
        data : `gafaelfawr.models.token.TokenData`
            The corresponding data.
        name : `str` or `None`
            The human-given name for the token.
        """
        new = SQLToken(
            token=data.token.key,
            username=data.username,
            token_type=data.token_type,
            token_name=token_name,
            scopes=",".join(sorted(data.scopes)) if data.scopes else None,
            created=data.created,
            expires=data.expires,
        )
        self._session.add(new)

    def get_info(self, token: Token) -> Optional[TokenInfo]:
        """Return information about a token.

        Parameters
        ----------
        token : `gafaelfawr.models.token.Token`
            The token.

        Returns
        -------
        info : `gafaelfawr.models.token.TokenInfo` or `None`
            Information about that token or `None` if it doesn't exist in the
            database.
        """
        token = (
            self._session.query(SQLToken).filter_by(token=token.key).scalar()
        )
        return TokenInfo.from_orm(token) if token else None


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
        await self._storage.store(f"token:{data.token.key}", data)
