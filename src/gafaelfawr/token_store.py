"""Storage for user-issued tokens."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import List, Optional

    from aioredis import Redis
    from aioredis.commands import Pipeline
    from structlog import BoundLogger

    from gafaelfawr.session import Session

__all__ = ["TokenEntry", "TokenStore"]


@dataclass
class TokenEntry:
    """An index entry for a user-issued token.

    Users can issue and manage their own tokens.  The token proper is stored
    as a session and the user is given a session handle to use instead of the
    full JWT, but we need to store some additional metadata to show the user a
    list of their issued tokens and let them revoke them.  This class
    represents one token in that metadata.
    """

    key: str
    """The key of the session handle for this token."""

    scope: str
    """The scope of the token."""

    expires: int
    """When the token expires, in seconds since epoch."""

    encoded: Optional[str] = None
    """The encoded form of the entry, if available.

    This may seem odd to include, but we have to have the encoded form in
    order to delete a token from a Redis set.
    """

    @classmethod
    def from_json(cls, data: str) -> TokenEntry:
        """Deserialize a token entry from JSON.

        Parameters
        ----------
        data : `str`
            Encoded JSON form of a token index entry.

        Returns
        -------
        entry : `TokenEntry`
            The corresponding token index entry.

        Raises
        ------
        json.JSONDecodeError
            The JSON is invalid.
        KeyError
            The JSON is missing a required field.
        """
        entry = json.loads(data)
        return cls(
            key=entry["key"],
            scope=entry["scope"],
            expires=entry["expires"],
            encoded=data,
        )

    def to_json(self) -> str:
        """Encode a token entry into JSON.

        Returns
        -------
        data : `str`
            The JSON corresponding to the entry.
        """
        data = {
            "key": self.key,
            "scope": self.scope,
            "expires": self.expires,
        }
        return json.dumps(data)


class TokenStore:
    """Store, retrieve, revoke, and expire user-created tokens.

    Parameters
    ----------
    redis : `aioredis.Redis`
        Redis client used to store and retrieve tokens.
    logger : `structlog.BoundLogger`
        Logger to report any errors.
    """

    def __init__(self, redis: Redis, logger: BoundLogger) -> None:
        self._redis = redis
        self._logger = logger

    async def get_tokens(self, user_id: str) -> List[TokenEntry]:
        """Retrieve index entries for all tokens for a given user.

        Parameters
        ----------
        user_id : `str`
            Retrieve the tokens of this User ID.

        Returns
        -------
        token_entries : List[`TokenEntry`]
            The index entries for all of that user's tokens.
        """
        redis_key = self._redis_key_for_user(user_id)
        serialized_entries = await self._redis.smembers(redis_key)

        entries = []
        for serialized_entry in serialized_entries:
            try:
                entry = TokenEntry.from_json(serialized_entry)
            except (json.JSONDecodeError, KeyError):
                self._logger.exception("Invalid token entry for %s", user_id)
                continue
            entries.append(entry)

        return entries

    async def expire_tokens(self, user_id: str) -> None:
        """Delete expired tokens for a user.

        Parameters
        ----------
        user_id : `str`
            The user ID.
        """
        entries = await self.get_tokens(user_id)
        now = datetime.now(tz=timezone.utc)
        expired = []
        for entry in entries:
            exp = datetime.fromtimestamp(entry.expires, tz=timezone.utc)
            if exp < now:
                expired.append(entry)

        if expired:
            redis_key = self._redis_key_for_user(user_id)
            pipeline = self._redis.pipeline()
            for entry in expired:
                pipeline.srem(redis_key, entry.encoded)
            await pipeline.execute()

    async def revoke_token(
        self, user_id: str, key: str, pipeline: Pipeline
    ) -> bool:
        """Revoke a token.

        To allow the caller to batch this with other Redis modifications, the
        session will be stored but the pipeline will not be executed.  The
        caller is responsible for executing the pipeline.

        Parameters
        ----------
        user_id : `str`
            User ID to whom the token was issued.
        key : `str`
            Session handle of the issued token.
        pipeline : `aioredis.commands.Pipeline`
            The pipeline to use for token deletion.

        Returns
        -------
        success : `bool`
            True if the token was found and revoked, False otherwise.
        """
        entries = await self.get_tokens(user_id)
        for entry in entries:
            if entry.key == key:
                redis_key = self._redis_key_for_user(user_id)
                pipeline.srem(redis_key, entry.encoded)
                return True
        return False

    def store_session(
        self, user_id: str, session: Session, pipeline: Pipeline
    ) -> None:
        """Store an index entry for a user authentication session.

        Used to populate the token list.  To allow the caller to batch this
        with other Redis modifications, the session will be stored but the
        pipeline will not be executed.  The caller is responsible for
        executing the pipeline.

        Parameters
        ----------
        user_id : `str`
            User ID who is issuing the token.
        session : `gafaelfawr.session.Session`
            The newly-issued token to store an index entry for.
        pipeline : `aioredis.commands.Pipeline`
            The pipeline in which to store the session.
        """
        entry = TokenEntry(
            key=session.handle.key,
            scope=" ".join(sorted(session.token.scope)),
            expires=session.token.claims["exp"],
        )
        redis_key = self._redis_key_for_user(user_id)
        pipeline.sadd(redis_key, entry.to_json())

    def _redis_key_for_user(self, user_id: str) -> str:
        """The Redis key for user-created tokens.

        Parameters
        ----------
        user_id : `str`
            The user ID of the user.

        Returns
        -------
        key : `str`
            The Redis key under which that user's tokens will be stored.
        """
        return f"tokens:{user_id}"
