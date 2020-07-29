"""Storage for user-issued tokens."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from gafaelfawr.storage.base import Serializable

if TYPE_CHECKING:
    from dataclasses import InitVar
    from typing import List, Optional

    from aioredis import Redis
    from aioredis.commands import Pipeline
    from structlog import BoundLogger

    from gafaelfawr.session import Session

__all__ = ["UserTokenEntry", "UserTokenStore"]


@dataclass
class UserTokenEntry(Serializable):
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

    encoded: InitVar[Optional[str]] = None
    """The encoded form of the entry, if available.

    This may seem odd to include, but we have to have the encoded form in
    order to delete a token from a Redis set, and it needs to match what is
    stored in Redis exactly.
    """

    def __post_init__(self, encoded: Optional[str] = None) -> None:
        self._encoded = encoded

    @classmethod
    def from_json(cls, data: str) -> UserTokenEntry:
        entry = json.loads(data)
        return cls(
            key=entry["key"],
            scope=entry["scope"],
            expires=entry["expires"],
            encoded=data,
        )

    @property
    def lifetime(self) -> Optional[int]:
        return self.expires - int(time.time())

    def to_json(self) -> str:
        if self._encoded:
            return self._encoded

        data = {
            "key": self.key,
            "scope": self.scope,
            "expires": self.expires,
        }
        return json.dumps(data)


class UserTokenStore:
    """Store, retrieve, revoke, and expire user-created tokens.

    This does not use the generic Redis storage layer because there is no
    overlap.  This store uses sets in Redis, so storing, retrieving, and
    deleting are all different, and does not encrypt the entries.

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

    async def get_tokens(self, user_id: str) -> List[UserTokenEntry]:
        """Retrieve index entries for all tokens for a given user.

        Parameters
        ----------
        user_id : `str`
            Retrieve the tokens of this User ID.

        Returns
        -------
        token_entries : List[`UserTokenEntry`]
            The index entries for all of that user's tokens.
        """
        redis_key = self._redis_key_for_user(user_id)
        serialized_entries = await self._redis.smembers(redis_key)

        entries = []
        for serialized_entry in serialized_entries:
            try:
                entry = UserTokenEntry.from_json(serialized_entry)
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
        expired = []
        for entry in entries:
            lifetime = entry.lifetime
            if lifetime and lifetime < 0:
                expired.append(entry)

        if expired:
            redis_key = self._redis_key_for_user(user_id)
            pipeline = self._redis.pipeline()
            for entry in expired:
                pipeline.srem(redis_key, entry.to_json())
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
                pipeline.srem(redis_key, entry.to_json())
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
        entry = UserTokenEntry(
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
