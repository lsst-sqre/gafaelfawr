"""Base persistant storage classes.

This module provides the lowest-level storage layer of Gafaelfawr for the
key/value store.  Should Gafaelfawr need to be ported to a storage system
other than Redis, the goal is to keep the required changes largely or entirely
confined to this file.
"""

from __future__ import annotations

from typing import Generic, Optional, Type, TypeVar

from aioredis import Redis
from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel  # noqa: F401

from gafaelfawr.exceptions import DeserializeException

S = TypeVar("S", bound="BaseModel")

__all__ = ["RedisStorage"]


class RedisStorage(Generic[S]):
    """JSON-serialized encrypted storage in Redis.

    Parameters
    ----------
    content : `typing.Type`
        The class of object being stored.
    key : `str`
        Encryption key.  Must be a `~cryptography.fernet.Fernet` key.
    redis : ``aioredis.Redis``
        A Redis client configured to talk to the backend store.
    """

    def __init__(self, content: Type[S], key: str, redis: Redis) -> None:
        self._content = content
        self._fernet = Fernet(key.encode())
        self._redis = redis

    async def delete(self, key: str) -> bool:
        """Delete a stored object.

        Parameters
        ----------
        key : `str`
            The key to delete.

        Returns
        -------
        success : `bool`
            `True` if the key was found and deleted, `False` otherwise.
        """
        count = await self._redis.delete(key)
        return count > 0

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
            return self._content.parse_raw(data.decode())
        except Exception as e:
            msg = f"Cannot deserialize data for {key}: {str(e)}"
            raise DeserializeException(msg)

    async def store(self, key: str, obj: S, lifetime: Optional[int]) -> None:
        """Store an object.

        Parameters
        ----------
        key : `str`
            The key for the object.
        obj : `Serializable`
            The object to store.
        lifetime : `int` or `None`
            The object lifetime in seconds.  The object should expire from the
            data store after that many seconds after the current time.
            Returns `None` if the object should not expire.
        """
        encrypted_data = self._fernet.encrypt(obj.json().encode())
        await self._redis.set(key, encrypted_data, ex=lifetime)
