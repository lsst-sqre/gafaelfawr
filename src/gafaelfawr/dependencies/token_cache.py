"""Shared cache of internal and notebook tokens.

This is intended to be process-global, but needs to be created after the app
has been created so that the asyncio locks are associated with the correct
event loop.  The `TokenCache` object should only be used via
`~gafaelfawr.services.token_cache.TokenCacheService`.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from cachetools import LRUCache

from gafaelfawr.constants import TOKEN_CACHE_SIZE
from gafaelfawr.models.token import Token

__all__ = ["TokenCache", "TokenCacheDependency", "token_cache_dependency"]

LRUTokenCache = LRUCache[Tuple[str, ...], Token]
"""Type for the underlying cache."""


@dataclass
class TokenCache:
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


class TokenCacheDependency:
    """Manage a single global token cache.

    We have to defer creation of the token cache until application startup,
    since the asyncio locks must be created in the same event loop as the rest
    of the application.  This dependency creates the token cache lazily on
    first request and then maintains it as a singleton.
    """

    def __init__(self) -> None:
        self._cache: Optional[TokenCache] = None

    async def __call__(self) -> TokenCache:
        """Lazily create and return the token cache."""
        if not self._cache:
            self._cache = TokenCache()
        return self._cache


token_cache_dependency = TokenCacheDependency()
"""The dependency that will return the token cache."""
