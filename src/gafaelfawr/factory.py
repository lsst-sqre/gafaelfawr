"""Create Gafaelfawr components."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import structlog
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.redis import redis_dependency
from gafaelfawr.issuer import TokenIssuer
from gafaelfawr.models.token import TokenData
from gafaelfawr.providers.github import GitHubProvider
from gafaelfawr.providers.oidc import OIDCProvider
from gafaelfawr.services.admin import AdminService
from gafaelfawr.services.kubernetes import KubernetesService
from gafaelfawr.services.oidc import OIDCService
from gafaelfawr.services.token import TokenService
from gafaelfawr.storage.admin import AdminStore
from gafaelfawr.storage.base import RedisStorage
from gafaelfawr.storage.history import (
    AdminHistoryStore,
    TokenChangeHistoryStore,
)
from gafaelfawr.storage.kubernetes import KubernetesStorage
from gafaelfawr.storage.oidc import OIDCAuthorization, OIDCAuthorizationStore
from gafaelfawr.storage.token import TokenDatabaseStore, TokenRedisStore
from gafaelfawr.token_cache import TokenCache
from gafaelfawr.verify import TokenVerifier

if TYPE_CHECKING:
    from typing import AsyncIterator

    from aioredis import Redis
    from structlog.stdlib import BoundLogger

    from gafaelfawr.config import Config
    from gafaelfawr.providers.base import Provider

__all__ = ["ComponentFactory"]


class ComponentFactory:
    """Build Gafaelfawr components.

    Given the application configuration, construct the components of the
    application on demand.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        Gafaelfawr configuration.
    """

    @classmethod
    @asynccontextmanager
    async def standalone(cls) -> AsyncIterator[ComponentFactory]:
        """Build Gafaelfawr components outside of a request.

        Intended for background jobs.  Uses the non-request default values for
        the dependencies of `ComponentFactory`.  Do not use this factory
        inside the web application or anywhere that may use the default
        `ComponentFactory`, since they will interfere with each other's
        Redis pools.

        Notes
        -----
        This creates a database session directly because fastapi_sqlalchemy
        does not work unless an ASGI application has initialized it.

        Yields
        ------
        factory : `ComponentFactory`
            The factory.  Must be used as a context manager.
        """
        config = await config_dependency()
        logger = structlog.get_logger(config.safir.logger_name)
        assert logger
        logger.debug("Connecting to Redis")
        redis = await redis_dependency(config)
        logger.debug("Connecting to PostgreSQL")
        engine = create_async_engine(config.database_url, future=True)
        try:
            factory = sessionmaker(
                engine, expire_on_commit=False, class_=AsyncSession
            )
            async with factory() as session:
                async with session.begin():
                    async with AsyncClient() as client:
                        yield cls(
                            config=config,
                            redis=redis,
                            session=session,
                            http_client=client,
                            logger=logger,
                        )
        finally:
            await redis_dependency.close()
            await engine.dispose()

    def __init__(
        self,
        *,
        config: Config,
        redis: Redis,
        session: AsyncSession,
        http_client: AsyncClient,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._redis = redis
        self._http_client = http_client
        self._logger = logger
        self._session = session

    def create_admin_service(self) -> AdminService:
        """Create a new manager object for token administrators.

        Returns
        -------
        admin_service : `gafaelfawr.services.admin.AdminService`
            The new token administrator manager.
        """
        admin_store = AdminStore(self._session)
        admin_history_store = AdminHistoryStore(self._session)
        return AdminService(admin_store, admin_history_store)

    def create_kubernetes_service(self) -> KubernetesService:
        """Create a Kubernetes service."""
        storage = KubernetesStorage(self._logger)
        token_service = self.create_token_service()
        return KubernetesService(
            token_service=token_service,
            storage=storage,
            logger=self._logger,
        )

    def create_oidc_service(self) -> OIDCService:
        """Create a minimalist OpenID Connect server.

        Returns
        -------
        oidc_service : `gafaelfawr.services.oidc.OIDCService`
            A new OpenID Connect server.
        """
        assert self._config.oidc_server
        key = self._config.session_secret
        storage = RedisStorage(OIDCAuthorization, key, self._redis)
        authorization_store = OIDCAuthorizationStore(storage)
        issuer = self.create_token_issuer()
        token_service = self.create_token_service()
        return OIDCService(
            config=self._config.oidc_server,
            authorization_store=authorization_store,
            issuer=issuer,
            token_service=token_service,
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
            token_verifier = self.create_token_verifier()
            return OIDCProvider(
                config=self._config.oidc,
                verifier=token_verifier,
                http_client=self._http_client,
                logger=self._logger,
            )
        else:
            # This should be caught during configuration file parsing.
            raise NotImplementedError("No authentication provider configured")

    def create_token_cache(self) -> TokenCache:
        """Create a token cache.

        Returns
        -------
        cache : `gafaelfawr.token_cache.TokenCache`
            A new token cache.
        """
        key = self._config.session_secret
        storage = RedisStorage(TokenData, key, self._redis)
        token_redis_store = TokenRedisStore(storage, self._logger)
        return TokenCache(token_redis_store)

    def create_token_issuer(self) -> TokenIssuer:
        """Create a TokenIssuer.

        Returns
        -------
        issuer : `gafaelfawr.issuer.TokenIssuer`
            A new TokenIssuer.
        """
        return TokenIssuer(self._config.issuer)

    def create_token_service(self) -> TokenService:
        """Create a TokenService.

        Returns
        -------
        token_service : `gafaelfawr.services.token.TokenService`
            The new token manager.
        """
        token_db_store = TokenDatabaseStore(self._session)
        key = self._config.session_secret
        storage = RedisStorage(TokenData, key, self._redis)
        token_redis_store = TokenRedisStore(storage, self._logger)
        token_cache = TokenCache(token_redis_store)
        is_postgres = self._config.database_url.startswith("postgresql")
        token_change_store = TokenChangeHistoryStore(
            self._session, is_postgres
        )
        return TokenService(
            config=self._config,
            token_cache=token_cache,
            token_db_store=token_db_store,
            token_redis_store=token_redis_store,
            token_change_store=token_change_store,
            logger=self._logger,
        )

    def create_token_verifier(self) -> TokenVerifier:
        """Create a TokenVerifier from a web request.

        Returns
        -------
        token_verifier : `gafaelfawr.verify.TokenVerifier`
            A new TokenVerifier.
        """
        return TokenVerifier(
            self._config.verifier, self._http_client, self._logger
        )
