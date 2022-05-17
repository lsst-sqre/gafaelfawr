"""Create Gafaelfawr components."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import structlog
from aioredis import Redis
from bonsai.asyncio import AIOConnectionPool
from httpx import AsyncClient
from kubernetes_asyncio.client import ApiClient
from safir.database import create_async_session
from sqlalchemy.ext.asyncio import AsyncEngine, async_scoped_session
from sqlalchemy.future import select
from structlog.stdlib import BoundLogger

from .cache import IdCache, InternalTokenCache, NotebookTokenCache
from .config import Config
from .dependencies.config import config_dependency
from .dependencies.ldap import ldap_pool_dependency
from .dependencies.redis import redis_dependency
from .exceptions import NotConfiguredError
from .models.token import TokenData
from .providers.base import Provider
from .providers.github import GitHubProvider
from .providers.oidc import OIDCProvider, OIDCTokenVerifier
from .schema import Admin as SQLAdmin
from .services.admin import AdminService
from .services.firestore import FirestoreService
from .services.influxdb import InfluxDBService
from .services.kubernetes import KubernetesService
from .services.ldap import LDAPService
from .services.oidc import OIDCService
from .services.token import TokenService
from .services.token_cache import TokenCacheService
from .services.userinfo import OIDCUserInfoService, UserInfoService
from .storage.admin import AdminStore
from .storage.base import RedisStorage
from .storage.firestore import FirestoreStorage
from .storage.history import AdminHistoryStore, TokenChangeHistoryStore
from .storage.kubernetes import KubernetesStorage
from .storage.ldap import LDAPStorage
from .storage.oidc import OIDCAuthorization, OIDCAuthorizationStore
from .storage.token import TokenDatabaseStore, TokenRedisStore

__all__ = ["ComponentFactory"]


class ComponentFactory:
    """Build Gafaelfawr components.

    Given the application configuration, construct the components of the
    application on demand.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        Gafaelfawr configuration.
    ldap_pool : `bonsai.asyncio.AIOConnectionPool`
        LDAP connection pool.
    redis : ``aioredis.Redis``
        Redis client.
    session : `sqlalchemy.ext.asyncio.async_scoped_session`
        SQLAlchemy async session.
    http_client : ``httpx.AsyncClient``
        HTTP async client.
    uid_cache : `gafaelfawr.cache.IdCache`
        Shared UID cache.
    gid_cache : `gafaelfawr.cache.IdCache`
        Shared GID cache.
    internal_token_cache : `gafaelfawr.cache.InternalTokenCache`
        Shared internal token cache.
    notebook_token_cache : `gafaelfawr.cache.NotebookTokenCache`
        Shared notebook token cache.
    logger : `structlog.stdlib.BoundLogger`
        Logger to use for errors.
    """

    @classmethod
    @asynccontextmanager
    async def standalone(
        cls, engine: AsyncEngine, check_db: bool = False
    ) -> AsyncIterator[ComponentFactory]:
        """Build Gafaelfawr components outside of a request.

        Intended for background jobs.  Uses the non-request default values for
        the dependencies of `ComponentFactory`.  Do not use this factory
        inside the web application or anywhere that may use the default
        `ComponentFactory`, since they will interfere with each other's
        Redis pools.

        Parameters
        ----------
        engine : `sqlalchemy.ext.asyncio.AsyncEngine`
            Database engine to use for connections.
        check_db : `bool`, optional
            If set to `True`, check database connectivity before returning by
            doing a simple query.

        Yields
        ------
        factory : `ComponentFactory`
            The factory.  Must be used as a context manager.
        """
        config = await config_dependency()
        uid_cache = IdCache()
        gid_cache = IdCache()
        internal_token_cache = InternalTokenCache()
        notebook_token_cache = NotebookTokenCache()
        logger = structlog.get_logger("gafaelfawr")
        logger.debug("Connecting to Redis")
        ldap_pool = await ldap_pool_dependency(config)
        redis = await redis_dependency(config)
        if check_db:
            statement = select(SQLAdmin)
        else:
            statement = None

        session = None
        try:
            session = await create_async_session(engine, statement=statement)
            async with AsyncClient() as client:
                yield cls(
                    config=config,
                    ldap_pool=ldap_pool,
                    redis=redis,
                    session=session,
                    http_client=client,
                    uid_cache=uid_cache,
                    gid_cache=gid_cache,
                    internal_token_cache=internal_token_cache,
                    notebook_token_cache=notebook_token_cache,
                    logger=logger,
                )
        finally:
            await redis_dependency.aclose()
            if session:
                await session.remove()

    def __init__(
        self,
        *,
        config: Config,
        ldap_pool: Optional[AIOConnectionPool],
        redis: Redis,
        session: async_scoped_session,
        http_client: AsyncClient,
        uid_cache: IdCache,
        gid_cache: IdCache,
        internal_token_cache: InternalTokenCache,
        notebook_token_cache: NotebookTokenCache,
        logger: BoundLogger,
    ) -> None:
        self.session = session
        self._config = config
        self._ldap_pool = ldap_pool
        self._redis = redis
        self._http_client = http_client
        self._uid_cache = uid_cache
        self._gid_cache = gid_cache
        self._internal_token_cache = internal_token_cache
        self._notebook_token_cache = notebook_token_cache
        self._logger = logger

    def create_admin_service(self) -> AdminService:
        """Create a new manager object for token administrators.

        Returns
        -------
        admin_service : `gafaelfawr.services.admin.AdminService`
            The new token administrator manager.
        """
        admin_store = AdminStore(self.session)
        admin_history_store = AdminHistoryStore(self.session)
        return AdminService(admin_store, admin_history_store, self._logger)

    def create_firestore_storage(self) -> FirestoreStorage:
        """Create the Firestore storage layer.

        Primarily for use internally and in tests.

        Returns
        -------
        firestore : `gafaelfawr.storage.firestore.FirestoreStorage`
            Newly-created Firestore storage.
        """
        if not self._config.firestore:
            raise NotConfiguredError("Firestore is not configured")
        return FirestoreStorage(self._config.firestore, self._logger)

    def create_influxdb_service(self) -> InfluxDBService:
        """Create an InfluxDB token issuer service.

        Returns
        -------
        influxdb_service : `gafaelfawr.services.influxdb.InfluxDBService`
            Newly-created InfluxDB token issuer.
        """
        if not self._config.influxdb:
            raise NotConfiguredError("No InfluxDB issuer configuration")
        return InfluxDBService(self._config.influxdb)

    def create_kubernetes_service(
        self, api_client: ApiClient
    ) -> KubernetesService:
        """Create a Kubernetes service.

        Parameters
        ----------
        api_client : ``kubernetes_asyncio.client.ApiClient``
            The Kubernetes client.

        Returns
        -------
        kubernetes_service : `gafaelfawr.services.kubernetes.KubernetesService`
            Newly-created Kubernetes service.
        """
        storage = KubernetesStorage(api_client, self._logger)
        token_service = self.create_token_service()
        return KubernetesService(
            token_service=token_service,
            storage=storage,
            session=self.session,
            logger=self._logger,
        )

    def create_oidc_service(self) -> OIDCService:
        """Create a minimalist OpenID Connect server.

        Returns
        -------
        oidc_service : `gafaelfawr.services.oidc.OIDCService`
            A new OpenID Connect server.
        """
        if not self._config.oidc_server:
            msg = "OpenID Connect server not configured"
            raise NotConfiguredError(msg)
        key = self._config.session_secret
        storage = RedisStorage(OIDCAuthorization, key, self._redis)
        authorization_store = OIDCAuthorizationStore(storage)
        token_service = self.create_token_service()
        return OIDCService(
            config=self._config.oidc_server,
            authorization_store=authorization_store,
            token_service=token_service,
            logger=self._logger,
        )

    def create_oidc_user_info_service(self) -> OIDCUserInfoService:
        """Create a user information service for OpenID Connect providers.

        This is a user information service specialized for using an OpenID
        Connect authentication provider.  It understands how to parse
        information out of the token claims.

        Returns
        -------
        user_info_service : `gafaelfawr.services.userinfo.OIDCUserInfoService`
            A new user information service.

        Raises
        ------
        gafaelfawr.exceptions.NotConfiguredError
            The configured authentication provider is not OpenID Connect.
        """
        if not self._config.oidc:
            raise NotConfiguredError("OpenID Connect is not configured")
        firestore = None
        if self._config.firestore:
            firestore_storage = self.create_firestore_storage()
            firestore = FirestoreService(
                uid_cache=self._uid_cache,
                gid_cache=self._gid_cache,
                storage=firestore_storage,
                logger=self._logger,
            )
        ldap = None
        if self._config.ldap and self._ldap_pool:
            ldap_storage = LDAPStorage(
                self._config.ldap, self._ldap_pool, self._logger
            )
            ldap = LDAPService(ldap_storage, self._logger)
        return OIDCUserInfoService(
            config=self._config,
            ldap=ldap,
            firestore=firestore,
            logger=self._logger,
        )

    def create_oidc_token_verifier(self) -> OIDCTokenVerifier:
        """Create a JWT token verifier for OpenID Connect tokens.

        This is normally used only as an implementation detail of the OpenID
        Connect authentication provider, but can be created directly to
        facilitate testing.

        Returns
        -------
        verifier : `gafaelfawr.providers.oidc.OIDCTokenVerifier`
            A new JWT token verifier.
        """
        if not self._config.oidc:
            msg = "OpenID Connect provider not configured"
            raise NotConfiguredError(msg)
        return OIDCTokenVerifier(
            config=self._config.oidc,
            http_client=self._http_client,
            logger=self._logger,
        )

    def create_provider(self) -> Provider:
        """Create an authentication provider.

        Create a provider object for the configured external authentication
        provider.

        Returns
        -------
        provider : `gafaelfawr.providers.base.Provider`
            A new Provider.

        Raises
        ------
        NotImplementedError
            None of the authentication providers are configured.
        """
        if self._config.github:
            return GitHubProvider(
                config=self._config.github,
                http_client=self._http_client,
                logger=self._logger,
            )
        elif self._config.oidc:
            verifier = self.create_oidc_token_verifier()
            user_info_service = self.create_oidc_user_info_service()
            return OIDCProvider(
                config=self._config.oidc,
                verifier=verifier,
                user_info_service=user_info_service,
                http_client=self._http_client,
                logger=self._logger,
            )
        else:
            # This should be caught during configuration file parsing.
            raise NotImplementedError("No authentication provider configured")

    def create_user_info_service(self) -> UserInfoService:
        """Create a user information service.

        This service retrieves metadata about the user, such as their UID,
        groups, and GIDs.  This is the generic service that acts on Gafaelfawr
        tokens, without support for the additional authentication-time methods
        used by authentication providers.

        Returns
        -------
        info_service : `gafaelfawr.services.userinfo.UserInfoService`
            Newly created service.
        """
        firestore = None
        if self._config.firestore:
            firestore_storage = self.create_firestore_storage()
            firestore = FirestoreService(
                uid_cache=self._uid_cache,
                gid_cache=self._gid_cache,
                storage=firestore_storage,
                logger=self._logger,
            )
        ldap = None
        if self._config.ldap and self._ldap_pool:
            ldap_storage = LDAPStorage(
                self._config.ldap, self._ldap_pool, self._logger
            )
            ldap = LDAPService(ldap_storage, self._logger)
        return UserInfoService(
            config=self._config,
            ldap=ldap,
            firestore=firestore,
            logger=self._logger,
        )

    def create_token_cache_service(self) -> TokenCacheService:
        """Create a token cache.

        Returns
        -------
        cache : `gafaelfawr.services.token_cache.TokenCacheService`
            A new token cache.
        """
        key = self._config.session_secret
        storage = RedisStorage(TokenData, key, self._redis)
        token_redis_store = TokenRedisStore(storage, self._logger)
        token_db_store = TokenDatabaseStore(self.session)
        token_change_store = TokenChangeHistoryStore(self.session)
        return TokenCacheService(
            config=self._config,
            internal_cache=self._internal_token_cache,
            notebook_cache=self._notebook_token_cache,
            token_db_store=token_db_store,
            token_redis_store=token_redis_store,
            token_change_store=token_change_store,
            logger=self._logger,
        )

    def create_token_service(self) -> TokenService:
        """Create a TokenService.

        Returns
        -------
        token_service : `gafaelfawr.services.token.TokenService`
            The new token manager.
        """
        token_db_store = TokenDatabaseStore(self.session)
        key = self._config.session_secret
        storage = RedisStorage(TokenData, key, self._redis)
        token_redis_store = TokenRedisStore(storage, self._logger)
        token_change_store = TokenChangeHistoryStore(self.session)
        token_cache_service = TokenCacheService(
            config=self._config,
            internal_cache=self._internal_token_cache,
            notebook_cache=self._notebook_token_cache,
            token_db_store=token_db_store,
            token_redis_store=token_redis_store,
            token_change_store=token_change_store,
            logger=self._logger,
        )
        return TokenService(
            config=self._config,
            token_cache=token_cache_service,
            token_db_store=token_db_store,
            token_redis_store=token_redis_store,
            token_change_store=token_change_store,
            logger=self._logger,
        )

    def reconfigure(self, config: Config) -> None:
        """Change the internal configuration.

        Intended for the test suite, which may have to reconfigure the
        component factory after creating it.

        Parameters
        ----------
        config : `gafaelfawr.config.Config`
            New configuration.
        """
        self._config = config
