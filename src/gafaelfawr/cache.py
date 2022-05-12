"""Shared caches.

These caches are process-global, managed by
`~gafaelfawr.factory.ProcessContext`.  The common theme is some storage
wrapped in an `asyncio.Lock`, possibly with some complex structure to allow
per-user locking.  These services sit below the main service layer and are
only intended for use via their service layer
(`~gafaelfawr.services.token_cache.TokenCacheService`,
`~gafaelfawr.services.ldap.LDAPService`, and
`~gafaelfawr.services.firestore.FirestoreService`).
"""

import asyncio
from abc import ABCMeta, abstractmethod
from types import TracebackType
from typing import Dict, List, Literal, Optional, Tuple, Type

from cachetools import LRUCache

from .constants import ID_CACHE_SIZE, TOKEN_CACHE_SIZE
from .models.token import Token, TokenData

LRUTokenCache = LRUCache[Tuple[str, ...], Token]
"""Type for the underlying token cache."""

__all__ = [
    "BaseCache",
    "IdCache",
    "InternalTokenCache",
    "NotebookTokenCache",
    "TokenCache",
    "TokenLockManager",
]


class BaseCache(metaclass=ABCMeta):
    """Base class for caches managed by a cache dependency."""

    @abstractmethod
    async def clear(self) -> None:
        """Invalidate the cache.

        Used primarily for testing.
        """


class IdCache(BaseCache):
    """A cache of UIDs or GIDs.

    This contains only the data structure for the ID cache and some simple
    accessor functions.  All of the logic is handled by
    `~gafaelfawr.services.firestore.FirestoreService`.  Two instances of this
    class will be created, one for UIDs and one for GIDs.

    UIDs and GIDs, once cached, are immutable, so the caller can first call
    `get` without a lock and safely use the result if it is not `None`.  If
    `get` returns `None`, the caller should take the lock, call `get` again,
    and then allocate and `store` a token if `get` still returns `None`.

    Notes
    -----
    When there's a cache miss for a UID or GID, the goal is to block the
    expensive Firestore API call until the first requester either finds a
    token in the database or creates a new one, either way adding it to the
    cache.  Hopefully then subsequent requests that were blocked on the lock
    can be answered from the cache.
    """

    def __init__(self) -> None:
        self._cache: LRUCache[str, int] = LRUCache(ID_CACHE_SIZE)
        self._lock = asyncio.Lock()

    async def clear(self) -> None:
        """Invalidate the cache.

        Used primarily for testing.
        """
        async with self._lock:
            self._cache = LRUCache(ID_CACHE_SIZE)

    def get(self, name: str) -> Optional[int]:
        """Retrieve the UID or GID for a name, if available.

        Parameters
        ----------
        name : `str`
            Username or group name.

        Returns
        -------
        id : `int` or `None`
            UID or GID if the name is in the cache, else `None`.
        """
        return self._cache.get(name)

    def lock(self) -> asyncio.Lock:
        """Return the cache lock for use in a context manager.

        See `store` for how to use this method.

        Returns
        -------
        lock : `asyncio.Lock`
            The lock for the cache.
        """
        return self._lock

    def store(self, name: str, id: int) -> None:
        """Store the UID or GID for a user or group in the cache.

        Examples
        --------
        .. code-block:: python

            async with id_cache.lock():
                uid = id_cache.get(username)
                if not uid:
                    # do something to allocate a UID
                    id_cache.store(username, uid)

        Parameters
        ----------
        name : `str`
            Name of the user or group.
        id : `int`
            UID or GID to store.
        """
        self._cache[name] = id


class TokenLockManager:
    """Helper class for managing per-user locks.

    This should only be created by `TokenCache`.  It is returned by the
    `TokenCache.lock` method and implements the async context manager
    protocol.

    Parameters
    ----------
    general_lock : `asyncio.Lock`
        Lock protecting the per-user locks.
    user_lock : `asyncio.Lock`
        Per-user lock for a given user.
    """

    def __init__(
        self, general_lock: asyncio.Lock, user_lock: asyncio.Lock
    ) -> None:
        self._general_lock = general_lock
        self._user_lock = user_lock

    async def __aenter__(self) -> asyncio.Lock:
        async with self._general_lock:
            await self._user_lock.acquire()
            return self._user_lock

    async def __aexit__(
        self,
        exc_type: Optional[Type[Exception]],
        exc: Optional[Exception],
        tb: Optional[TracebackType],
    ) -> Literal[False]:
        self._user_lock.release()
        return False


class TokenCache(BaseCache):
    """Base class for a cache of internal or notebook tokens.

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

    Note that the per-user lock must be acquired before the general lock is
    released, so the `lock` method cannot simply return the per-user lock.  To
    see why, imagine that one code path retrieves the per-user lock in
    preparation for acquiring it, and then another code path calls `clear`.
    `clear` acquires the global lock and then deletes the per-user lock, but
    the first caller still has a copy of the per-user lock and thinks it's
    valid.  It may then take that per-user lock, but a third code path could
    also try to lock the same user and get a new per-user lock from the
    post-clearing cache.  Both the first and third code paths will think they
    have a lock and may conflict.  `TokenLockManager` is used to handle this.
    """

    def __init__(self) -> None:
        self._cache: LRUTokenCache = LRUCache(TOKEN_CACHE_SIZE)
        self._lock = asyncio.Lock()
        self._user_locks: Dict[str, asyncio.Lock] = {}

    async def clear(self) -> None:
        """Invalidate the cache.

        Used primarily for testing.
        """
        async with self._lock:
            for user, lock in list(self._user_locks.items()):
                async with lock:
                    del self._user_locks[user]
            self._cache = LRUCache(TOKEN_CACHE_SIZE)

    async def lock(self, username: str) -> TokenLockManager:
        """Return the per-user lock for locking.

        The return value should be used with ``async with`` to hold a lock
        around checking for a cached token and, if one is not found, creating
        and storing a new token.

        Parameters
        ----------
        username : `str`
            Per-user lock to hold.

        Returns
        -------
        lock : `TokenLockManager`
            Async context manager that will take the user lock.
        """
        async with self._lock:
            if username not in self._user_locks:
                lock = asyncio.Lock()
                self._user_locks[username] = lock
            return TokenLockManager(self._lock, self._user_locks[username])


class InternalTokenCache(TokenCache):
    """Cache for internal tokens."""

    def get(
        self, token_data: TokenData, service: str, scopes: List[str]
    ) -> Optional[Token]:
        """Retrieve an internal token from the cache.

        Should only be called while holding the lock.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.
        service : `str`
            The service of the internal token.
        scopes : List[`str`]
            The scopes the internal token should have.

        Returns
        -------
        token : `gafaelfawr.models.token.Token` or `None`
            The cached token or `None` if there is no matching token in the
            cache.

        Notes
        -----
        The token is not checked for validity or expiration.  This must be
        done by the caller, while holding the lock, and the token replaced in
        the cache if it is not valid.
        """
        key = self._build_key(token_data, service, scopes)
        return self._cache.get(key)

    def store(
        self,
        token_data: TokenData,
        service: str,
        scopes: List[str],
        token: Token,
    ) -> None:
        """Store an internal token in the cache.

        Should only be called while holding the lock.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.
        service : `str`
            The service of the internal token.
        scopes : List[`str`]
            The scopes the internal token should have.
        token : `gafaelfawr.models.token.Token`
            The token to cache.
        """
        key = self._build_key(token_data, service, scopes)
        self._cache[key] = token

    def _build_key(
        self, token_data: TokenData, service: str, scopes: List[str]
    ) -> Tuple[str, ...]:
        """Build the cache key for an internal token.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.
        service : `str`
            The service of the internal token.
        scopes : List[`str`]
            The scopes the internal token should have.
        """
        expires = str(token_data.expires) if token_data.expires else "None"
        scope = ",".join(sorted(scopes))
        return (token_data.token.key, expires, service, scope)


class NotebookTokenCache(TokenCache):
    """Cache for notebook tokens."""

    def get(self, token_data: TokenData) -> Optional[Token]:
        """Retrieve a notebook token from the cache.

        Should only be called while holding the lock.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.

        Returns
        -------
        token : `gafaelfawr.models.token.Token` or `None`
            The cached token or `None` if there is no matching token in the
            cache.

        Notes
        -----
        The token is not checked for validity or expiration.  This must be
        done by the caller, while holding the lock, and the token replaced in
        the cache if it is not valid.
        """
        key = self._build_key(token_data)
        return self._cache.get(key)

    def store(self, token_data: TokenData, token: Token) -> None:
        """Store a notebook token in the cache.

        Should only be called while holding the lock.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.
        token : `gafaelfawr.models.token.Token`
            The token to cache.
        """
        key = self._build_key(token_data)
        self._cache[key] = token

    def _build_key(self, token_data: TokenData) -> Tuple[str, ...]:
        """Build the cache key for a notebook token.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.
        """
        expires = str(token_data.expires) if token_data.expires else "None"
        return (token_data.token.key, expires)
