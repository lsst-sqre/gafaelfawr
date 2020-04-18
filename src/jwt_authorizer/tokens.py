"""Token storage."""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aioredis import Redis
    from aioredis.commands import Pipeline
    from typing import Any, Dict, List, Tuple

__all__ = [
    "NoUserIdException",
    "TokenStore",
]


class NoUserIdException(Exception):
    """The token does not contain the expected user ID field."""


class TokenStore:
    """Store, retrieve, revoke, and expire user-created tokens.

    Parameters
    ----------
    redis : `aioredis.Redis`
        Redis client used to store and retrieve tokens.
    user_id_key : `str`
        The token field to use as the user ID for calculating a Redis key.
    """

    def __init__(self, redis: Redis, user_id_key: str) -> None:
        self.redis = redis
        self.user_id_key = user_id_key

    async def get_tokens(self, user_id: str) -> List[Dict[str, Any]]:
        """Retrieve all tokens for a given user.

        Parameters
        ----------
        user_id : `str`
            Retrieve the tokens of this User ID.

        Returns
        -------
        tokens : List[Dict[`str`, Any]]
            All of that user's tokens as a list of token contents.
        """
        tokens, _ = await self._get_tokens(user_id)
        return tokens

    async def revoke_token(
        self, user_id: str, handle: str, pipeline: Pipeline
    ) -> bool:
        """Revoke a token.

        To allow the caller to batch this with other Redis modifications, the
        session will be stored but the pipeline will not be executed.  The
        caller is responsible for executing the pipeline.

        Parameters
        ----------
        user_id : `str`
            User ID to whom the token was issued.
        handle : `str`
            Handle of the issued token.
        pipeline : `aioredis.commands.Pipeline`
            The pipeline in which to store the session.

        Returns
        -------
        success : `bool`
            True if the token was found and revoked, False otherwise.
        """
        tokens, serialized_tokens = await self._get_tokens(user_id)
        token_to_revoke = ""
        for token, serialized_token in zip(tokens, serialized_tokens):
            if token["jti"] == handle:
                token_to_revoke = serialized_token

        if token_to_revoke:
            pipeline.srem(self._redis_key_for_user(user_id), token_to_revoke)
            return True
        else:
            return False

    def store_token(self, payload: Dict[str, Any], pipeline: Pipeline) -> None:
        """Store the data of a user-created token in a Redis pipeline.

        Used to populate the token list.  To allow the caller to batch this
        with other Redis modifications, the session will be stored but the
        pipeline will not be executed.  The caller is responsible for
        executing the pipeline.

        Parameters
        ----------
        payload : Dict[`str`, Any]
            The contents of the token.
        pipeline : `aioredis.commands.Pipeline`
            The pipeline in which to store the session.
        """
        pipeline.sadd(self._redis_key_for_token(payload), json.dumps(payload))

    async def _get_tokens(
        self, user_id: str
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Get al the tokens for a given user ID, delete expired ones.

        As a side effect, this function removes all expired tokens for that
        user from Redis.

        Parameters
        ----------
        user_id : `str`
            The user ID.

        Returns
        -------
        user_tokens : List[Dict[`str`, Any]]
            The decoded user tokens.
        valid_serialized_user_tokens : List[`str`]
            The corresponding encoded tokens.
        """
        user_tokens = []
        expired_tokens = []
        key = self._redis_key_for_user(user_id)
        serialized_user_tokens = await self.redis.smembers(key)
        valid_serialized_user_tokens = []

        # Clear out expired token references
        for serialized_token in serialized_user_tokens:
            token = json.loads(serialized_token)
            exp = datetime.utcfromtimestamp(token["exp"])
            if exp < datetime.now():
                expired_tokens.append(serialized_token)
            else:
                user_tokens.append(token)
                valid_serialized_user_tokens.append(serialized_token)

        pipeline = self.redis.pipeline()
        for expired_token in expired_tokens:
            pipeline.srem(key, expired_token)
        await pipeline.execute()

        return user_tokens, valid_serialized_user_tokens

    def _redis_key_for_token(self, token: Dict[str, Any]) -> str:
        """The Redis key for user-created tokens.

        Parameters
        ----------
        token : Dict[`str`, Any]
            The contents of a token identifying the user.

        Returns
        -------
        key : `str`
            The Redis key under which those tokens will be stored.

        Raises
        ------
        NoUserIdException
            The token contents do not contain the expected user ID field.
        """
        if self.user_id_key not in token:
            raise NoUserIdException(f"Field {self.user_id_key} not found")
        user_id = str(token[self.user_id_key])
        return self._redis_key_for_user(user_id)

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
