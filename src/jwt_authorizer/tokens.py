"""Token parsing and storage."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import TYPE_CHECKING

from wtforms import BooleanField, Form, HiddenField, SubmitField

if TYPE_CHECKING:
    import aioredis
    from aiohttp import web
    from aioredis.commands import Pipeline
    from jwt_authorizer.config import Config
    from multidict import MultiDictProxy
    from typing import Any, Dict, List, Optional, Tuple, Union

__all__ = [
    "AlterTokenForm",
    "TokenStore",
    "all_tokens",
    "api_capabilities_token_form",
    "revoke_token",
]

logger = logging.getLogger(__name__)


def api_capabilities_token_form(
    capabilities: Dict[str, str],
    data: Optional[MultiDictProxy[Union[str, bytes, web.FileField]]] = None,
) -> Form:
    """Dynamically generates a form with checkboxes for capabilities.

    Parameters
    ----------
    capabilities : Dict[`str`, `str`]
        A mapping of capability names to descriptions to include in the form.
    data : MultiDictProxy[Union[`str`, `bytes`, FileField]], optional
        The submitted form data, if any.

    Returns
    -------
    form : `wtforms.Form`
        The generated form.
    """

    class NewCapabilitiesToken(Form):
        """Stub form, to which fields will be dynamically added."""

        submit = SubmitField("Generate New Token")

    NewCapabilitiesToken.capability_names = list(capabilities)
    for capability, description in capabilities.items():
        field = BooleanField(label=capability, description=description)
        setattr(NewCapabilitiesToken, capability, field)
    return NewCapabilitiesToken(data)


class AlterTokenForm(Form):
    """Form for altering an existing user token."""

    method_ = HiddenField("method_")
    csrf = HiddenField("_csrf")


async def all_tokens(
    request: web.Request, user_id: str
) -> List[Dict[str, Any]]:
    """Get all the decoded tokens for a given user ID.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    user_id : `str`
        The user ID.

    Returns
    -------
    tokens : List[Dict[`str`, Any]]
        The decoded user tokens.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]
    redis_client = request.config_dict["jwt_authorizer/redis"]

    token_store = TokenStore(redis_client, config.uid_key)
    return await token_store.get_tokens(user_id)


async def revoke_token(
    request: web.Request, user_id: str, handle: str
) -> bool:
    """Revoke a token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    user_id : `str`
        User ID to whom the token was issued.
    handle : `str`
        Handle of the issued token.

    Returns
    -------
    success : `bool`
        True if the token was found and revoked, False otherwise.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]
    redis_client = request.config_dict["jwt_authorizer/redis"]

    token_store = TokenStore(redis_client, config.uid_key)
    pipeline = redis_client.pipeline()
    success = await token_store.revoke_token(user_id, handle, pipeline)
    if success:
        pipeline.delete(handle)
        await pipeline.execute()
        return True
    return False


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

    def __init__(self, redis: aioredis.Redis, user_id_key: str) -> None:
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
