"""Cache for internal and notebook tokens."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from structlog.stdlib import BoundLogger

from ..config import Config
from ..dependencies.token_cache import TokenCache
from ..models.history import TokenChange, TokenChangeHistoryEntry
from ..models.token import Token, TokenData, TokenType
from ..storage.history import TokenChangeHistoryStore
from ..storage.token import TokenDatabaseStore, TokenRedisStore
from ..util import current_datetime

__all__ = ["TokenCacheService"]


class TokenCacheService:
    """Manage cache internal and notebook tokens.

    To reduce latency and database query load, notebook and internal tokens
    for a given parent token are cached in memory and reused as long as the
    request data matches, the token is still valid, and less than half of its
    lifetime has passed.

    Parameters
    ----------
    cache : `gafaelfawr.dependencies.token_cache.TokenCache`
        The underlying cache and locks.
    config : `gafaelfawr.config.Config`
        The Gafaelfawr configuration.
    token_db_store : `gafaelfawr.storage.token.TokenDatabaseStore`
        The database backing store for tokens.
    token_redis_store : `gafaelfawr.storage.token.TokenRedisStore`
        The Redis backing store for tokens.
    token_change_store : `gafaelfawr.storage.history.TokenChangeHistoryStore`
        The backing store for history of changes to tokens.
    logger : ``structlog.stdlib.BoundLogger``
        Logger to use.

    Notes
    -----
    The cache storage is process-global and is locked only for asyncio access,
    not for threaded access.  It is not thread-safe.  The expectation is that
    this code will be used by a single-process asyncio server, and scaling
    will be done by adding more processes.

    Notebook tokens are cached under the key of the parent token and its
    expiration.  Internal tokens add the service name and the requested
    scopes.  The expiration of the parent token is included since changing the
    expiration of a parent token (for a user token for instance) may allow for
    a longer internal or notebook token, and we don't want to prevent that
    change by returning a cached token.
    """

    def __init__(
        self,
        *,
        cache: TokenCache,
        config: Config,
        token_redis_store: TokenRedisStore,
        token_db_store: TokenDatabaseStore,
        token_change_store: TokenChangeHistoryStore,
        logger: BoundLogger,
    ) -> None:
        self._cache = cache
        self._config = config
        self._token_redis_store = token_redis_store
        self._token_db_store = token_db_store
        self._token_change_store = token_change_store
        self._logger = logger

    async def clear(self) -> None:
        """Invalidate the cache.

        Used primarily for testing.
        """
        await self._cache.clear()

    async def get_internal_token(
        self,
        token_data: TokenData,
        service: str,
        scopes: List[str],
        ip_address: str,
    ) -> Token:
        """Retrieve or create an internal token.

        Return the cached token if one is available, a matching token if one
        exists in the database, or a newly-created token if necessary.

        The new token will have the same expiration time as the existing token
        on which it's based unless that expiration time is longer than the
        expiration time of normal interactive tokens, in which case it will be
        capped at the interactive token expiration time.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.
        service : `str`
            The service of the internal token.
        scopes : List[`str`]
            The scopes the internal token should have.
        ip_address : `str`
            The IP address from which the request came.

        Returns
        -------
        token : `gafaelfawr.models.token.Token`
            The cached token or newly-created token.
        """
        key = self._internal_key(token_data, service, scopes)
        token = await self._get_token(key, token_data.scopes)
        if not token:
            lock = await self._acquire_user_lock(token_data.username)
            try:
                # Check again now that we've taken the lock, since another
                # thread of execution may have created and cached a token.
                token = await self._get_token(key, token_data.scopes)
                if token:
                    return token
                token = await self._create_internal_token(
                    token_data, service, scopes, ip_address
                )
                self._cache.cache[key] = token
            finally:
                lock.release()
        return token

    async def get_notebook_token(
        self, token_data: TokenData, ip_address: str
    ) -> Token:
        """Retrieve or create a notebook token.

        Return the cached token if one is available, a matching token if one
        exists in the database, or a newly-created token if necessary.

        The new token will have the same expiration time as the existing token
        on which it's based unless that expiration time is longer than the
        expiration time of normal interactive tokens, in which case it will be
        capped at the interactive token expiration time.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.
        ip_address : `str`
            The IP address from which the request came.

        Returns
        -------
        token : `gafaelfawr.models.token.Token` or `None`
            The cached token or `None` if no matching token is cached.
        """
        key = self._notebook_key(token_data)
        token = await self._get_token(key)
        if not token:
            lock = await self._acquire_user_lock(token_data.username)
            try:
                # Check again now that we've taken the lock, since another
                # thread of execution may have created and cached a token.
                token = await self._get_token(key)
                if token:
                    return token
                token = await self._create_notebook_token(
                    token_data, ip_address
                )
                self._cache.cache[key] = token
            finally:
                lock.release()
        return token

    def store_internal_token(
        self,
        token: Token,
        token_data: TokenData,
        service: str,
        scopes: List[str],
    ) -> None:
        """Cache an internal token.

        Used primarily for the test suite.

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
        self._cache.cache[key] = token

    def store_notebook_token(
        self, token: Token, token_data: TokenData
    ) -> None:
        """Cache a notebook token.

        Used primarily for the test suite.

        Parameters
        ----------
        token : `gafaelfawr.models.token.Token`
            The token to cache.
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.
        """
        key = self._notebook_key(token_data)
        self._cache.cache[key] = token

    async def _acquire_user_lock(self, username: str) -> asyncio.Lock:
        """Acquire a per-user cache lock.

        Parameters
        ----------
        username : `str`
            The user for which to acquire a lock.

        Returns
        -------
        lock : `asyncio.Lock`
            The acquired per-user lock.  The caller is responsible for
            ensuring the lock is released.
        """
        async with self._cache.lock:
            if username in self._cache.user_lock:
                lock = self._cache.user_lock[username]
            else:
                lock = asyncio.Lock()
                self._cache.user_lock[username] = lock
            await lock.acquire()
            return lock

    async def _create_internal_token(
        self,
        token_data: TokenData,
        service: str,
        scopes: List[str],
        ip_address: str,
    ) -> Token:
        """Retrieve or create a new internal token.

        This must be run with the per-user token lock taken so that any other
        requests for a token for the same user will wait until this request is
        complete.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.
        service : `str`
            The service of the internal token.
        scopes : List[`str`]
            The scopes the internal token should have.
        ip_address : `str`
            The IP address from which the request came.
        """
        # See if there's already a matching internal token.
        key = await self._token_db_store.get_internal_token_key(
            token_data, service, scopes, self._minimum_expiration(token_data)
        )
        if key:
            data = await self._token_redis_store.get_data_by_key(key)
            if data:
                return data.token

        # There is not, so we need to create a new one.
        token = Token()
        created = current_datetime()
        expires = created + self._config.token_lifetime
        if token_data.expires and token_data.expires < expires:
            expires = token_data.expires
        data = TokenData(
            token=token,
            username=token_data.username,
            token_type=TokenType.internal,
            scopes=scopes,
            created=created,
            expires=expires,
            name=token_data.name,
            email=token_data.email,
            uid=token_data.uid,
            groups=token_data.groups,
        )
        history_entry = TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.internal,
            parent=token_data.token.key,
            scopes=scopes,
            service=service,
            expires=expires,
            actor=token_data.username,
            action=TokenChange.create,
            ip_address=ip_address,
            event_time=created,
        )

        await self._token_redis_store.store_data(data)
        await self._token_db_store.add(
            data, service=service, parent=token_data.token.key
        )
        await self._token_change_store.add(history_entry)

        self._logger.info(
            "Created new internal token",
            key=token.key,
            service=service,
            token_scope=",".join(data.scopes),
        )

        return token

    async def _create_notebook_token(
        self, token_data: TokenData, ip_address: str
    ) -> Token:
        """Retrieve or create a notebook token.

        This must be run with the per-user token lock taken so that any other
        requests for a token for the same user will wait until this request is
        complete.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data for the parent token.
        ip_address : `str`
            The IP address from which the request came.
        """
        # See if there's already a matching notebook token.
        key = await self._token_db_store.get_notebook_token_key(
            token_data, self._minimum_expiration(token_data)
        )
        if key:
            data = await self._token_redis_store.get_data_by_key(key)
            if data:
                return data.token

        # There is not, so we need to create a new one.
        token = Token()
        created = current_datetime()
        expires = created + self._config.token_lifetime
        if token_data.expires and token_data.expires < expires:
            expires = token_data.expires
        data = TokenData(
            token=token,
            username=token_data.username,
            token_type=TokenType.notebook,
            scopes=token_data.scopes,
            created=created,
            expires=expires,
            name=token_data.name,
            email=token_data.email,
            uid=token_data.uid,
            groups=token_data.groups,
        )
        history_entry = TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.notebook,
            parent=token_data.token.key,
            scopes=data.scopes,
            expires=expires,
            actor=token_data.username,
            action=TokenChange.create,
            ip_address=ip_address,
            event_time=created,
        )

        await self._token_redis_store.store_data(data)
        await self._token_db_store.add(data, parent=token_data.token.key)
        await self._token_change_store.add(history_entry)

        # Cache the token and return it.
        self._logger.info("Created new notebook token", key=token.key)
        return token

    async def _get_token(
        self, key: Tuple[str, ...], scopes: Optional[List[str]] = None
    ) -> Optional[Token]:
        """Retrieve a cached token by key.

        Parameters
        ----------
        key : Tuple[`str`, ...]
            The cache key, created by ``_internal_key`` or ``_notebook_key``.
        scopes : List[`str`], optional
            If provided, ensure that the returned token has scopes that are a
            subset of this scope list.  This is used to force a cache miss if
            an internal token is requested but the requesting token no longer
            has the scopes that the internal token provides.

        Returns
        -------
        token : `gafaelfawr.models.token.Token` or `None`
            The cached token, or `None` on a cache miss.
        """
        token = self._cache.cache.get(key)
        if not token:
            return None
        data = await self._token_redis_store.get_data(token)
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
        expires = str(token_data.expires) if token_data.expires else "None"
        scope = ",".join(sorted(scopes))
        return ("internal", token_data.token.key, expires, service, scope)

    def _notebook_key(self, token_data: TokenData) -> Tuple[str, ...]:
        """Build a cache key for a notebook token."""
        expires = str(token_data.expires) if token_data.expires else "None"
        return ("notebook", token_data.token.key, expires)

    def _minimum_expiration(self, token_data: TokenData) -> datetime:
        """Determine the minimum expiration for a child token.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The data for the parent token for which a child token was
            requested.

        Returns
        -------
        min_expires : `datetime.datetime`
            The minimum acceptable expiration time for the child token.  If
            no child tokens with at least this expiration time exist, a new
            child token should be created.
        """
        min_expires = current_datetime() + timedelta(
            seconds=self._config.token_lifetime.total_seconds() / 2
        )
        if token_data.expires and min_expires > token_data.expires:
            min_expires = token_data.expires
        return min_expires
