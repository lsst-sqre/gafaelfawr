"""Cache for internal and notebook tokens."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cachetools import LRUCache

from gafaelfawr.constants import TOKEN_CACHE_SIZE
from gafaelfawr.util import current_datetime

if TYPE_CHECKING:
    from typing import List, Optional, Tuple

    from gafaelfawr.models.token import Token, TokenData
    from gafaelfawr.storage.token import TokenRedisStore

__all__ = ["TokenCache"]


class TokenCache:
    """Cache internal and notebook tokens.

    To reduce latency and database query load, notebook and internal tokens
    for a given parent token are cached in memory and reused as long as the
    request data matches, the token is still valid, and less than half of its
    lifetime has passed.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        The Gafaelfawr configuration.
    redis : `aioredis.Redis`
        The Redis client to use to check validity of the cached token.

    Notes
    -----
    The cache storage is process-global.  It isn't protected by a lock and
    thus isn't thread-safe.  The expectation is that this code will be used by
    a single-process asyncio server, and scaling will be done by adding more
    processes.

    Notebook tokens are cached under the key of the parent token and its
    expiration.  Internal tokens add the service name and the requested
    scopes.  The expiration of the parent token is included since changing the
    expiration of a parent token (for a user token for instance) may allow for
    a longer internal or notebook token, and we don't want to prevent that
    change by returning a cached token.
    """

    _cache: LRUCache[Tuple[str, ...], Token] = LRUCache(TOKEN_CACHE_SIZE)
    """Shared cache storage for the tokens, global to each process."""

    def __init__(self, store: TokenRedisStore) -> None:
        self._store = store

    def clear(self) -> None:
        """Invalidate the cache.

        Used primarily for testing.
        """
        self._cache = LRUCache(TOKEN_CACHE_SIZE)

    async def get_internal_token(
        self, token_data: TokenData, service: str, scopes: List[str]
    ) -> Optional[Token]:
        """Retrieve a cached internal token.

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
            The cached token or `None` if no matching token is cached.
        """
        key = self._internal_key(token_data, service, scopes)
        return await self._get_token(key, token_data.scopes)

    async def get_notebook_token(
        self, token_data: TokenData
    ) -> Optional[Token]:
        """Retrieve a cached notebook token.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.

        Returns
        -------
        token : `gafaelfawr.models.token.Token` or `None`
            The cached token or `None` if no matching token is cached.
        """
        key = self._notebook_key(token_data)
        return await self._get_token(key)

    def store_internal_token(
        self,
        token: Token,
        token_data: TokenData,
        service: str,
        scopes: List[str],
    ) -> None:
        """Cache an internal token.

        Parameters
        ----------
        token : `gafaelfawr.models.token.Token`
            The token to cache.
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.
        service : `str`
            The service of the internal token.
        scopes : List[`str`]
            The scopes the internal token should have.
        """
        key = self._internal_key(token_data, service, scopes)
        self._cache[key] = token

    def store_notebook_token(
        self, token: Token, token_data: TokenData
    ) -> None:
        """Cache a notebook token.

        Parameters
        ----------
        token : `gafaelfawr.models.token.Token`
            The token to cache.
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.
        """
        key = self._notebook_key(token_data)
        self._cache[key] = token

    async def _get_token(
        self, key: Tuple[str, ...], scopes: Optional[List[str]] = None
    ) -> Optional[Token]:
        """Retrieve a cached token by key."""
        token = self._cache.get(key)
        if not token:
            return None
        data = await self._store.get_data(token)
        if not data:
            return None
        if scopes is not None and not (set(data.scopes) <= set(scopes)):
            return None
        if data.expires:
            lifetime = data.expires - data.created
            remaining = data.expires - current_datetime()
            if remaining.total_seconds() < lifetime.total_seconds() / 2:
                return None
        return token

    def _internal_key(
        self, token_data: TokenData, service: str, scopes: List[str]
    ) -> Tuple[str, ...]:
        """Build a cache key for an internal token."""
        scope = ",".join(sorted(scopes))
        expires = str(token_data.expires) if token_data.expires else "None"
        return ("internal", token_data.token.key, expires, service, scope)

    def _notebook_key(self, token_data: TokenData) -> Tuple[str, ...]:
        """Build a cache key for a notebook token."""
        expires = str(token_data.expires) if token_data.expires else "None"
        return ("notebook", token_data.token.key, expires)
