"""Cache for internal and notebook tokens."""

from __future__ import annotations

from datetime import datetime, timedelta

import sentry_sdk
from safir.datetime import current_datetime, format_datetime_for_logging
from sqlalchemy.ext.asyncio import async_scoped_session
from structlog.stdlib import BoundLogger

from ..cache import InternalTokenCache, NotebookTokenCache
from ..config import Config
from ..models.enums import TokenChange, TokenType
from ..models.history import TokenChangeHistoryEntry
from ..models.token import Token, TokenData
from ..storage.history import TokenChangeHistoryStore
from ..storage.token import TokenDatabaseStore, TokenRedisStore

__all__ = ["TokenCacheService"]


class TokenCacheService:
    """Manage cache internal and notebook tokens.

    To reduce latency and database query load, notebook and internal tokens
    for a given parent token are cached in memory and reused as long as the
    request data matches, the token is still valid, and less than half of its
    lifetime has passed.

    This class handles both the creation and the caching of internal and
    notebook tokens.

    Parameters
    ----------
    config
        The Gafaelfawr configuration.
    internal_cache
        Cache for internal tokens.
    notebook_cache
        Cache for notebook tokens.
    token_db_store
        The database backing store for tokens.
    token_redis_store
        The Redis backing store for tokens.
    token_change_store
        The backing store for history of changes to tokens.
    session
        Database session, used to create a transaction if a new token needs to
        be created.
    logger
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
        config: Config,
        internal_cache: InternalTokenCache,
        notebook_cache: NotebookTokenCache,
        token_redis_store: TokenRedisStore,
        token_db_store: TokenDatabaseStore,
        token_change_store: TokenChangeHistoryStore,
        session: async_scoped_session,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._internal_cache = internal_cache
        self._notebook_cache = notebook_cache
        self._token_redis_store = token_redis_store
        self._token_db_store = token_db_store
        self._token_change_store = token_change_store
        self._session = session
        self._logger = logger

    async def clear(self) -> None:
        """Invalidate the caches.

        Used primarily for testing.
        """
        await self._internal_cache.clear()
        await self._notebook_cache.clear()

    @sentry_sdk.trace
    async def get_internal_token(
        self,
        token_data: TokenData,
        service: str,
        scopes: set[str],
        ip_address: str,
        *,
        minimum_lifetime: timedelta | None = None,
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
        token_data
            Authentication data for the parent token.
        service
            Service of the internal token.
        scopes
            Scopes the internal token should have.
        ip_address
            IP address from which the request came.
        minimum_lifetime
            If set, the minimum required lifetime of the token.

        Returns
        -------
        Token
            Cached token or newly-created token.
        """
        # Awkward code is to convince mypy that token is not None.
        token = self._internal_cache.get(token_data, service, scopes)
        valid = await self._is_token_valid(token, minimum_lifetime, scopes)
        if token and valid:
            return token
        async with await self._internal_cache.lock(token_data.username):
            token = self._internal_cache.get(token_data, service, scopes)
            valid = await self._is_token_valid(token, minimum_lifetime, scopes)
            if token and valid:
                return token
            async with self._session.begin():
                token = await self._create_internal_token(
                    token_data, service, scopes, ip_address, minimum_lifetime
                )
            self._internal_cache.store(token_data, service, scopes, token)
            return token

    @sentry_sdk.trace
    async def get_notebook_token(
        self,
        token_data: TokenData,
        ip_address: str,
        *,
        minimum_lifetime: timedelta | None = None,
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
        token_data
            The authentication data for the parent token.
        ip_address
            The IP address from which the request came.
        minimum_lifetime
            If set, the minimum required lifetime of the token.

        Returns
        -------
        Token or None
            The cached token, or `None` if no matching token is cached.
        """
        token = self._notebook_cache.get(token_data)
        if token and await self._is_token_valid(token, minimum_lifetime):
            return token
        async with await self._notebook_cache.lock(token_data.username):
            token = self._notebook_cache.get(token_data)
            if token and await self._is_token_valid(token, minimum_lifetime):
                return token
            async with self._session.begin():
                token = await self._create_notebook_token(
                    token_data, ip_address, minimum_lifetime
                )
            self._notebook_cache.store(token_data, token)
            return token

    async def _create_internal_token(
        self,
        token_data: TokenData,
        service: str,
        scopes: set[str],
        ip_address: str,
        minimum_lifetime: timedelta | None = None,
    ) -> Token:
        """Retrieve or create a new internal token.

        This must be run with the per-user token lock taken so that any other
        requests for a token for the same user will wait until this request is
        complete.

        Parameters
        ----------
        token_data
            Authentication data for the parent token.
        service
            Service of the internal token.
        scopes
            Scopes the internal token should have.
        ip_address
            IP address from which the request came.
        minimum_lifetime
            If set, the minimum required lifetime of the token.

        Returns
        -------
        Token
            Retrieved or newly-created internal token.
        """
        # See if there's already a matching internal token.
        key = await self._token_db_store.get_internal_token_key(
            token_data,
            service,
            scopes,
            self._minimum_expiration(token_data, minimum_lifetime),
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
            service=service,
            scopes=scopes,
            created=created,
            expires=expires,
            name=token_data.name,
            email=token_data.email,
            uid=token_data.uid,
            gid=token_data.gid,
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
        try:
            await self._token_db_store.add(data, parent=token_data.token.key)
            await self._token_change_store.add(history_entry)
        except Exception:
            await self._token_redis_store.delete(data.token.key)
            raise

        self._logger.info(
            "Created new internal token",
            token_key=token.key,
            token_expires=format_datetime_for_logging(expires),
            token_scopes=sorted(data.scopes),
            token_service=service,
            token_userinfo=data.to_userinfo_dict(),
        )

        return token

    async def _create_notebook_token(
        self,
        token_data: TokenData,
        ip_address: str,
        minimum_lifetime: timedelta | None = None,
    ) -> Token:
        """Retrieve or create a notebook token.

        This must be run with the per-user token lock taken so that any other
        requests for a token for the same user will wait until this request is
        complete.

        Parameters
        ----------
        token_data
            The authentication data for the parent token.
        ip_address
            The IP address from which the request came.
        minimum_lifetime
            If set, the minimum required lifetime of the token.

        Returns
        -------
        Token
            The retrieved or newly-created notebook token.
        """
        # See if there's already a matching notebook token.
        key = await self._token_db_store.get_notebook_token_key(
            token_data, self._minimum_expiration(token_data, minimum_lifetime)
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
            gid=token_data.gid,
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
        try:
            await self._token_db_store.add(data, parent=token_data.token.key)
            await self._token_change_store.add(history_entry)
        except Exception:
            await self._token_redis_store.delete(data.token.key)
            raise

        # Cache the token and return it.
        self._logger.info(
            "Created new notebook token",
            token_key=token.key,
            token_expires=format_datetime_for_logging(expires),
            token_userinfo=data.to_userinfo_dict(),
        )
        return token

    async def _is_token_valid(
        self,
        token: Token | None,
        minimum_lifetime: timedelta | None = None,
        scopes: set[str] | None = None,
    ) -> bool:
        """Check whether a token is valid.

        Tokens are considered invalid if they cannot be retrieved from Redis,
        don't satisfy a required minimum lifetime, or if more than half of
        their lifetime has expired.

        Parameters
        ----------
        token
            Token to check for validity. `None` is accepted to simplify type
            checking, but will always return `False`.
        scopes
            If provided, ensure that the token has scopes that are a subset of
            this scope list. This is used to force a cache miss if an internal
            token is requested but the requesting token no longer has the
            scopes that the internal token provides.
        minimum_lifetime
            If set, the minimum required lifetime of the token.

        Returns
        -------
        bool
            Whether the token is valid.
        """
        if not token:
            return False
        data = await self._token_redis_store.get_data(token)
        if not data:
            return False
        if scopes is not None and not (data.scopes <= scopes):
            return False
        if data.expires:
            if minimum_lifetime:
                required = minimum_lifetime.total_seconds()
            else:
                required = (data.expires - data.created).total_seconds() / 2
            remaining = data.expires - current_datetime()
            if remaining.total_seconds() < required:
                return False
        return True

    def _minimum_expiration(
        self,
        token_data: TokenData,
        minimum_lifetime: timedelta | None = None,
    ) -> datetime:
        """Determine the minimum expiration for a child token.

        Parameters
        ----------
        token_data
            The data for the parent token for which a child token was
            requested.
        minimum_lifetime
            If set, the minimum required lifetime of the token.

        Returns
        -------
        datetime
            The minimum acceptable expiration time for the child token.  If
            no child tokens with at least this expiration time exist, a new
            child token should be created.
        """
        if minimum_lifetime:
            min_expires = current_datetime() + minimum_lifetime
        else:
            min_expires = current_datetime() + timedelta(
                seconds=self._config.token_lifetime.total_seconds() / 2
            )

        # If the minimum expiration is greater than than the expiration of the
        # parent token, cap it at the expiration of the parent token, since we
        # can never create a child token with a longer expiration than that,
        # so we should use what we find rather than creating a new token that
        # will still have its expiration capped at the same value.
        if token_data.expires and min_expires > token_data.expires:
            min_expires = token_data.expires

        return min_expires
