"""Base persistant storage classes.

This module provides the lowest-level storage layer of Gafaelfawr.  Should
Gafaelfawr need to be ported to a storage system other than Redis, the goal is
to keep the required changes largely or entirely confined to this file.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, TypeVar

from cryptography.fernet import Fernet, InvalidToken

from gafaelfawr.exceptions import DeserializeException

if TYPE_CHECKING:
    from typing import Optional, Type

    from aioredis import Redis
    from aioredis.commands import Pipeline

S = TypeVar("S", bound="Serializable")

__all__ = ["RedisStorage", "Serializable"]


class Serializable(ABC):
    """Represents a data element that can be stored in Redis."""

    @classmethod
    @abstractmethod
    def from_json(cls: Type[S], data: str) -> S:
        """Deserialize from JSON.

        Parameters
        ----------
        data : `str`
            JSON-serialized representation.

        Returns
        -------
        obj : `gafaelfawr.storage.base.Serializable`
            The deserialized object.
        """

    @property
    @abstractmethod
    def lifetime(self) -> Optional[int]:
        """The object lifetime in seconds.

        Returns
        -------
        lifetime : `int` or `None`
            The object lifetime in seconds.  The object should expire from the
            data store after that many seconds after the current time.
            Returns `None` if the object should not expire.
        """

    @abstractmethod
    def to_json(self) -> str:
        """Serialize to JSON.

        Returns
        -------
        data : `str`
            The object in JSON-serialized form.
        """


class RedisStorage(Generic[S]):
    """JSON-serialized encrypted storage in Redis.

    Parameters
    ----------
    content : `typing.Type`
        The class of object being stored.
    key : `str`
        Encryption key.  Must be a `~cryptography.fernet.Fernet` key.
    redis : `aioredis.Redis`
        A Redis client configured to talk to the backend store.
    """

    def __init__(self, content: Type[S], key: str, redis: Redis) -> None:
        self._content = content
        self._fernet = Fernet(key.encode())
        self._redis = redis

    async def delete(
        self, key: str, pipeline: Optional[Pipeline] = None
    ) -> None:
        """Delete a stored object.

        Parameters
        ----------
        key : `str`
            The key to delete.
        pipeline : `aioredis.commands.Pipeline`, optional
            If provided, do the delete as part of a pipeline.
        """
        if pipeline:
            pipeline.delete(key)
        else:
            await self._redis.delete(key)

    async def get(self, key: str) -> Optional[S]:
        """Retrieve a stored object.

        Parameters
        ----------
        key : `str`
            The key for the object.

        Returns
        -------
        obj : `Serializable` or `None`
            The deserialized object or `None` if no such object could be
            found.

        Raises
        ------
        gafaelfawr.exceptions.DeserializeException
            The stored object could not be decrypted or deserialized.
        """
        encrypted_data = await self._redis.get(key)
        if not encrypted_data:
            return None

        # Decrypt the data.
        try:
            data = self._fernet.decrypt(encrypted_data)
        except InvalidToken as e:
            msg = f"Cannot decrypt data for {key}: {str(e)}"
            raise DeserializeException(msg)

        # Deserialize the data.
        try:
            return self._content.from_json(data.decode())
        except Exception as e:
            msg = f"Cannot deserialize data for {key}: {str(e)}"
            raise DeserializeException(msg)

    async def store(
        self, key: str, obj: S, pipeline: Optional[Pipeline] = None
    ) -> None:
        """Store an object.

        Parameters
        ----------
        key : `str`
            The key for the object.
        obj : `Serializable`
            The object to store.
        pipeline : `aioredis.commands.Pipeline`, optional
            If provided, the pipeline to use to store the object.
        """
        encrypted_data = self._fernet.encrypt(obj.to_json().encode())
        if pipeline:
            pipeline.set(key, encrypted_data, expire=obj.lifetime)
        else:
            await self._redis.set(key, encrypted_data, expire=obj.lifetime)
