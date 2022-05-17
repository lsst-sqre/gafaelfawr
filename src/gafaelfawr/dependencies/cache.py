"""FastAPI dependencies to manage process-global caches."""

from typing import Generic, Optional, Type, TypeVar

from ..cache import BaseCache, IdCache, InternalTokenCache, NotebookTokenCache

S = TypeVar("S", bound="BaseCache")

__all__ = [
    "CacheDependency",
    "gid_cache_dependency",
    "internal_token_cache_dependency",
    "notebook_token_cache_dependency",
    "uid_cache_dependency",
]


class CacheDependency(Generic[S]):
    """Manage a global cache.

    We have to defer creation of the cache until application startup, since
    the asyncio locks must be created in the same event loop as the rest of
    the application.  This dependency creates the cache lazily on first
    request and then maintains it as a singleton.
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


uid_cache_dependency = CacheDependency(IdCache)
"""The dependency that will return the UID cache."""

gid_cache_dependency = CacheDependency(IdCache)
"""The dependency that will return the UID cache."""

internal_token_cache_dependency = CacheDependency(InternalTokenCache)
"""The dependency that will return the internal token cache."""

notebook_token_cache_dependency = CacheDependency(NotebookTokenCache)
"""The dependency that will return the notebook token cache."""
