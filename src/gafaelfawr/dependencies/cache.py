"""Shared cache of internal and notebook tokens.

This is intended to be process-global, but needs to be created after the app
has been created so that the asyncio locks are associated with the correct
event loop.  The `TokenCache` object should only be used via
`~gafaelfawr.services.token_cache.TokenCacheService`.
"""

import asyncio
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Generic, Optional, Tuple, Type, TypeVar

from cachetools import LRUCache

from ..constants import GID_CACHE_SIZE, TOKEN_CACHE_SIZE, UID_CACHE_SIZE
from ..models.token import Token

LRUIdCache = LRUCache[str, int]
"""Type for the underlying cache."""

LRUTokenCache = LRUCache[Tuple[str, ...], Token]
"""Type for the underlying token cache."""

S = TypeVar("S", bound="BaseCache")

__all__ = [
    "BaseCache",
    "CacheDependency",
    "IdCache",
    "TokenCache",
    "id_cache_dependency",
    "token_cache_dependency",
]


class BaseCache(metaclass=ABCMeta):
    """Base class for caches returned by a cache dependency."""

    @abstractmethod
    async def clear(self) -> None:
        """Invalidate the cache.

        Used primarily for testing.
        """


@dataclass
class IdCache(BaseCache):
    """A cache of UIDs and GIDs.

    This contains only the data structure for the ID cache and some simple
    accessor functions.  All of the logic is handled by
    `~gafaelfawr.services.userinfo.UserInfoService`.

    Notes
    -----
    When there's a cache miss for a UID or GID, the goal is to block the
    expensive Firestore API call until the first requester either finds a
    token in the database or creates a new one, either way adding it to the
    cache.  Hopefully then subsequent requests that were blocked on the lock
    can be answered from the cache.
    """

    gid_cache: LRUIdCache = field(
        default_factory=lambda: LRUCache(GID_CACHE_SIZE)
    )
    """Shared cache storage for the GIDs."""

    gid_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    """Lock protecting the GID cache."""

    uid_cache: LRUIdCache = field(
        default_factory=lambda: LRUCache(UID_CACHE_SIZE)
    )
    """Shared cache storage for the UIDs."""

    uid_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    """Lock protecting the UID cache."""

    async def clear(self) -> None:
        """Invalidate the cache.

        Used primarily for testing.
        """
        async with self.gid_lock:
            self.gid_cache = LRUCache(GID_CACHE_SIZE)
        async with self.uid_lock:
            self.uid_cache = LRUCache(UID_CACHE_SIZE)

    def get_gid(self, group: str) -> Optional[int]:
        """Retrieve the GID for a group if available.

        Parameters
        ----------
        group : `str`
            Name of the group.

        Returns
        -------
        gid : `int` or `None`
            GID if the group is in the cache, otherwise `None`.
        """
        return self.gid_cache.get(group)

    def get_uid(self, username: str) -> Optional[int]:
        """Retrieve the UID for a username if available.

        Parameters
        ----------
        username : `str`
            Username of the user.

        Returns
        -------
        uid : `int` or `None`
            UID if the username is in the cache, otherwise `None`.
        """
        return self.uid_cache.get(username)

    def store_gid(self, group: str, gid: int) -> None:
        """Store the GID for a group in the cache.

        Parameters
        ----------
        group : `str`
            Name of the group.
        gid : `int`
            GID of the group.
        """
        self.gid_cache[group] = gid

    def store_uid(self, username: str, uid: int) -> None:
        """Store the UID for a user in the cache.

        Parameters
        ----------
        username : `str`
            Username of the user.
        uid : `int`
            UID of the user.
        """
        self.uid_cache[username] = uid


@dataclass
class TokenCache(BaseCache):
    """A cache of internal and notebook tokens.

    This contains only the data structure for a token cache.  All of the logic
    is handled by `~gafaelfawr.services.token_cache.TokenCacheService`.

    Notes
    -----
    There is a moderately complex locking structure at play here.  When
    there's a cache miss for an internal or notebook token for a specific
    user, the goal is to block the expensive database lookups or token
    creation for that user until the first requester either finds a token in
    the database or creates a new one, either way adding it to the cache.
    Hopefully then subsequent requests that were blocked on the lock can be
    answered from the cache.

    There is therefore a dictionary of per-user locks, but since we don't know
    the list of users in advance, we have to populate those locks on the fly.
    It shouldn't be necessary to protect the dict of per-user locks with
    another lock because we only need to worry about asyncio concurrency, but
    since FastAPI does use a thread pool, err on the side of caution and use
    the same locking strategy that would be used for multithreaded code.
    """

    cache: LRUTokenCache = field(
        default_factory=lambda: LRUCache(TOKEN_CACHE_SIZE)
    )
    """Shared cache storage for the tokens."""

    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    """Lock protecting the dict of per-user locks."""

    user_lock: Dict[str, asyncio.Lock] = field(default_factory=dict)
    """Dict of per-user locks."""

    async def clear(self) -> None:
        """Invalidate the cache.

        Used primarily for testing.
        """
        async with self.lock:
            self.cache = LRUCache(TOKEN_CACHE_SIZE)
            for user, lock in list(self.user_lock.items()):
                async with lock:
                    del self.user_lock[user]


class CacheDependency(Generic[S]):
    """Manage a single global token cache.

    We have to defer creation of the token cache until application startup,
    since the asyncio locks must be created in the same event loop as the rest
    of the application.  This dependency creates the token cache lazily on
    first request and then maintains it as a singleton.
    """

    def __init__(self, cache_type: Type[S]) -> None:
        self._cache_type = cache_type
        self._cache: Optional[S] = None

    async def __call__(self) -> S:
        """Lazily create and return the cache."""
        if not self._cache:
            self._cache = self._cache_type()
        return self._cache

    async def aclose(self) -> None:
        """Clear the cache.

        Should be called from a shutdown hook to ensure that cache locks are
        not reused across tests when running the test suite.
        """
        if self._cache:
            await self._cache.clear()
            self._cache = None


id_cache_dependency = CacheDependency(IdCache)
"""The dependency that will return the ID cache."""

token_cache_dependency = CacheDependency(TokenCache)
"""The dependency that will return the token cache."""
