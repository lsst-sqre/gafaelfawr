"""Create Gafaelfawr components."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import aclosing, asynccontextmanager
from dataclasses import dataclass
from typing import Self

import redis
import structlog
from bonsai import LDAPClient
from bonsai.asyncio import AIOConnectionPool
from httpx import AsyncClient
from kubernetes_asyncio.client import ApiClient
from redis.backoff import ExponentialBackoff
from redis.retry import Retry
from safir.database import create_async_session
from safir.dependencies.http_client import http_client_dependency
from safir.redis import EncryptedPydanticRedisStorage
from safir.slack.webhook import SlackWebhookClient
from sqlalchemy.ext.asyncio import AsyncEngine, async_scoped_session
from sqlalchemy.future import select
from structlog.stdlib import BoundLogger

from .cache import IdCache, InternalTokenCache, LDAPCache, NotebookTokenCache
from .config import Config
from .constants import REDIS_BACKOFF_MAX, REDIS_BACKOFF_START, REDIS_RETRIES
from .exceptions import NotConfiguredError
from .models.ldap import LDAPUserData
from .models.oidc import OIDCAuthorization
from .models.token import TokenData, TokenGroup
from .providers.base import Provider
from .providers.github import GitHubProvider
from .providers.oidc import OIDCProvider, OIDCTokenVerifier
from .schema import Admin as SQLAdmin
from .services.admin import AdminService
from .services.firestore import FirestoreService
from .services.kubernetes import (
    KubernetesIngressService,
    KubernetesTokenService,
)
from .services.ldap import LDAPService
from .services.oidc import OIDCService
from .services.token import TokenService
from .services.token_cache import TokenCacheService
from .services.userinfo import OIDCUserInfoService, UserInfoService
from .storage.admin import AdminStore
from .storage.firestore import FirestoreStorage
from .storage.forgerock import ForgeRockStorage
from .storage.history import AdminHistoryStore, TokenChangeHistoryStore
from .storage.kubernetes import (
    KubernetesIngressStorage,
    KubernetesTokenStorage,
)
from .storage.ldap import LDAPStorage
from .storage.oidc import OIDCAuthorizationStore
from .storage.token import TokenDatabaseStore, TokenRedisStore

__all__ = ["Factory", "ProcessContext"]


@dataclass(frozen=True, slots=True)
class ProcessContext:
    """Per-process application context.

    This object caches all of the per-process singletons that can be reused
    for every request and only need to be recreated if the application
    configuration changes.  This does not include the database session; each
    request creates a new scoped session that's removed at the end of the
    session to ensure that all transactions are committed or abandoned.
    """

    config: Config
    """Gafaelfawr's configuration."""

    http_client: AsyncClient
    """Shared HTTP client."""

    ldap_pool: AIOConnectionPool | None
    """Connection pool to talk to LDAP, if configured."""

    redis: redis.asyncio.Redis
    """Connection pool to use to talk to Redis."""

    uid_cache: IdCache
    """Shared UID cache."""

    gid_cache: IdCache
    """Shared GID cache."""

    ldap_group_cache: LDAPCache[list[TokenGroup]]
    """Cache of LDAP group information."""

    ldap_group_name_cache: LDAPCache[list[str]]
    """Cache of LDAP group names."""

    ldap_user_cache: LDAPCache[LDAPUserData]
    """Cache of LDAP user data."""

    internal_token_cache: InternalTokenCache
    """Shared internal token cache."""

    notebook_token_cache: NotebookTokenCache
    """Shared notebook token cache."""

    @classmethod
    async def from_config(cls, config: Config) -> Self:
        """Create a new process context from the Gafaelfawr configuration.

        Parameters
        ----------
        config
            The Gafaelfawr configuration.

        Returns
        -------
        ProcessContext
            Shared context for a Gafaelfawr process.
        """
        ldap_pool = None
        if config.ldap:
            client = LDAPClient(config.ldap.url)
            if config.ldap.user_dn and config.ldap.password:
                client.set_credentials(
                    "SIMPLE",
                    user=config.ldap.user_dn,
                    password=config.ldap.password,
                )
            elif config.ldap.use_kerberos:
                client.set_credentials("GSSAPI")
            ldap_pool = AIOConnectionPool(client)

        redis_client = redis.asyncio.from_url(
            config.redis_url,
            password=config.redis_password,
            retry=Retry(
                ExponentialBackoff(
                    base=REDIS_BACKOFF_START, cap=REDIS_BACKOFF_MAX
                ),
                REDIS_RETRIES,
            ),
        )

        return cls(
            config=config,
            http_client=await http_client_dependency(),
            ldap_pool=ldap_pool,
            redis=redis_client,
            uid_cache=IdCache(),
            gid_cache=IdCache(),
            ldap_group_cache=LDAPCache(list[TokenGroup]),
            ldap_group_name_cache=LDAPCache(list[str]),
            ldap_user_cache=LDAPCache(LDAPUserData),
            internal_token_cache=InternalTokenCache(),
            notebook_token_cache=NotebookTokenCache(),
        )

    async def aclose(self) -> None:
        """Clean up a process context.

        Called during shutdown, or before recreating the process context using
        a different configuration.
        """
        await self.redis.close()
        await self.redis.connection_pool.disconnect()
        if self.ldap_pool:
            await self.ldap_pool.close()
        await self.uid_cache.clear()
        await self.gid_cache.clear()
        await self.ldap_group_cache.clear()
        await self.ldap_group_name_cache.clear()
        await self.ldap_user_cache.clear()
        await self.internal_token_cache.clear()
        await self.notebook_token_cache.clear()


class Factory:
    """Build Gafaelfawr components.

    Uses the contents of a `ProcessContext` to construct the components of the
    application on demand.

    Parameters
    ----------
    context
        Shared process context.
    session
        Database session.
    logger
        Logger to use for errors.
    """

    @classmethod
    async def create(
        cls, config: Config, engine: AsyncEngine, *, check_db: bool = False
    ) -> Self:
        """Create a component factory outside of a request.

        Intended for long-running daemons other than the FastAPI web
        application, such as the Kubernetes operator.  This class method
        should only be used in situations where an async context manager
        cannot be used.  Do not use this factory inside the web application or
        anywhere that may use the default `Factory`, since they will interfere
        with each other's Redis pools.

        If an async context manager can be used, call `standalone` rather than
        this method.

        Parameters
        ----------
        config
            Gafaelfawr configuration.
        engine
            Database engine to use for connections.
        check_db
            If set to `True`, check database connectivity before returning by
            doing a simple query.

        Returns
        -------
        Factory
            Newly-created factory.  The caller must call `aclose` on the
            returned object during shutdown.
        """
        logger = structlog.get_logger("gafaelfawr")
        statement = select(SQLAdmin) if check_db else None
        session = await create_async_session(engine, statement=statement)
        try:
            context = await ProcessContext.from_config(config)
            return cls(context, session, logger)
        finally:
            await session.remove()

    @classmethod
    @asynccontextmanager
    async def standalone(
        cls, config: Config, engine: AsyncEngine, *, check_db: bool = False
    ) -> AsyncIterator[Self]:
        """Async context manager for Gafaelfawr components.

        Intended for background jobs.  Uses the non-request default values for
        the dependencies of `Factory`.  Do not use this factory inside the web
        application or anywhere that may use the default `Factory`, since they
        will interfere with each other's Redis pools.

        Parameters
        ----------
        config
            Gafaelfawr configuration.
        engine
            Database engine to use for connections.
        check_db
            If set to `True`, check database connectivity before returning by
            doing a simple query.

        Yields
        ------
        Factory
            The factory.  Must be used as an async context manager.

        Examples
        --------
        .. code-block:: python

           async with Factory.standalone(config, engine) as factory:
               token_service = factory.create_token_service()
               async with factory.session.begin():
                   alerts = await token_service.audit(fix=fix)
        """
        factory = await cls.create(config, engine, check_db=check_db)
        async with aclosing(factory):
            yield factory

    def __init__(
        self,
        context: ProcessContext,
        session: async_scoped_session,
        logger: BoundLogger,
    ) -> None:
        self.session = session
        self._context = context
        self._logger = logger

    @property
    def redis(self) -> redis.asyncio.Redis:
        """Underlying Redis connection pool, mainly for tests."""
        return self._context.redis

    async def aclose(self) -> None:
        """Shut down the factory.

        After this method is called, the factory object is no longer valid and
        must not be used.
        """
        try:
            await self._context.aclose()
        finally:
            await self.session.remove()

    def create_admin_service(self) -> AdminService:
        """Create a new manager object for token administrators.

        Returns
        -------
        AdminService
            The new token administrator manager.
        """
        admin_store = AdminStore(self.session)
        admin_history_store = AdminHistoryStore(self.session)
        return AdminService(admin_store, admin_history_store, self._logger)

    def create_firestore_service(self) -> FirestoreService:
        """Create the Firestore service layer.

        Returns
        -------
        FirestoreService
            Newly-created Firestore service.
        """
        storage = self.create_firestore_storage()
        return FirestoreService(
            uid_cache=self._context.uid_cache,
            gid_cache=self._context.gid_cache,
            storage=storage,
            logger=self._logger,
        )

    def create_firestore_storage(self) -> FirestoreStorage:
        """Create the Firestore storage layer.

        Primarily for use internally and in tests.

        Returns
        -------
        FirestoreStorage
            Newly-created Firestore storage.
        """
        if not self._context.config.firestore:
            raise NotConfiguredError("Firestore is not configured")
        return FirestoreStorage(self._context.config.firestore, self._logger)

    def create_kubernetes_ingress_service(
        self, api_client: ApiClient
    ) -> KubernetesIngressService:
        """Create a service for managing Kubernetes ingresses.

        Parameters
        ----------
        api_client
            The Kubernetes client.

        Returns
        -------
        KubernetesIngressService
            Newly-created Kubernetes service.
        """
        storage = KubernetesIngressStorage(api_client, self._logger)
        return KubernetesIngressService(storage, self._logger)

    def create_kubernetes_token_service(
        self, api_client: ApiClient
    ) -> KubernetesTokenService:
        """Create a service for managing tokens stored in Kubernetes.

        Parameters
        ----------
        api_client
            The Kubernetes client.

        Returns
        -------
        KubernetesTokenService
            Newly-created Kubernetes service.
        """
        storage = KubernetesTokenStorage(api_client, self._logger)
        token_service = self.create_token_service()
        return KubernetesTokenService(
            token_service=token_service,
            storage=storage,
            session=self.session,
            logger=self._logger,
        )

    def create_oidc_service(self) -> OIDCService:
        """Create a minimalist OpenID Connect server.

        Returns
        -------
        OIDCService
            A new OpenID Connect server.
        """
        if not self._context.config.oidc_server:
            msg = "OpenID Connect server not configured"
            raise NotConfiguredError(msg)
        storage = EncryptedPydanticRedisStorage(
            datatype=OIDCAuthorization,
            redis=self._context.redis,
            encryption_key=self._context.config.session_secret,
            key_prefix="oidc:",
        )
        authorization_store = OIDCAuthorizationStore(storage)
        token_service = self.create_token_service()
        slack_client = self.create_slack_client()
        return OIDCService(
            config=self._context.config.oidc_server,
            authorization_store=authorization_store,
            token_service=token_service,
            slack_client=slack_client,
            logger=self._logger,
        )

    def create_oidc_user_info_service(self) -> OIDCUserInfoService:
        """Create a user information service for OpenID Connect providers.

        This is a user information service specialized for using an OpenID
        Connect authentication provider.  It understands how to parse
        information out of the token claims.

        Returns
        -------
        OIDCUserInfoService
            A new user information service.

        Raises
        ------
        NotConfiguredError
            Raised if the configured authentication provider is not OpenID
            Connect.
        """
        if not self._context.config.oidc:
            raise NotConfiguredError("OpenID Connect is not configured")
        firestore = None
        if self._context.config.firestore:
            firestore = self.create_firestore_service()
        forgerock = None
        if self._context.config.forgerock:
            forgerock = ForgeRockStorage(
                config=self._context.config.forgerock,
                http_client=self._context.http_client,
                logger=self._logger,
            )
        ldap = None
        if self._context.config.ldap and self._context.ldap_pool:
            ldap_storage = LDAPStorage(
                self._context.config.ldap,
                self._context.ldap_pool,
                self._logger,
            )
            ldap = LDAPService(
                ldap=ldap_storage,
                group_cache=self._context.ldap_group_cache,
                group_name_cache=self._context.ldap_group_name_cache,
                user_cache=self._context.ldap_user_cache,
                logger=self._logger,
            )
        return OIDCUserInfoService(
            config=self._context.config,
            ldap=ldap,
            firestore=firestore,
            forgerock=forgerock,
            logger=self._logger,
        )

    def create_oidc_token_verifier(self) -> OIDCTokenVerifier:
        """Create a JWT token verifier for OpenID Connect tokens.

        This is normally used only as an implementation detail of the OpenID
        Connect authentication provider, but can be created directly to
        facilitate testing.

        Returns
        -------
        OIDCTokenVerifier
            A new JWT token verifier.
        """
        if not self._context.config.oidc:
            msg = "OpenID Connect provider not configured"
            raise NotConfiguredError(msg)
        return OIDCTokenVerifier(
            config=self._context.config.oidc,
            http_client=self._context.http_client,
            logger=self._logger,
        )

    def create_provider(self) -> Provider:
        """Create an authentication provider.

        Create a provider object for the configured external authentication
        provider.

        Returns
        -------
        Provider
            A new Provider.

        Raises
        ------
        NotImplementedError
            Raised if none of the authentication providers are configured.
        """
        if self._context.config.github:
            return GitHubProvider(
                config=self._context.config.github,
                http_client=self._context.http_client,
                logger=self._logger,
            )
        elif self._context.config.oidc:
            verifier = self.create_oidc_token_verifier()
            user_info_service = self.create_oidc_user_info_service()
            return OIDCProvider(
                config=self._context.config.oidc,
                verifier=verifier,
                user_info_service=user_info_service,
                http_client=self._context.http_client,
                logger=self._logger,
            )
        else:
            # This should be caught during configuration file parsing.
            raise NotImplementedError("No authentication provider configured")

    def create_slack_client(self) -> SlackWebhookClient | None:
        """Create a client for sending messages to Slack.

        Returns
        -------
        safir.slack.webhook.SlackWebhookClient or None
            Configured Slack client if a Slack webhook was configured,
            otherwise `None`.
        """
        if not self._context.config.slack_webhook:
            return None
        return SlackWebhookClient(
            self._context.config.slack_webhook, "Gafaelfawr", self._logger
        )

    def create_token_cache_service(self) -> TokenCacheService:
        """Create a token cache.

        Returns
        -------
        TokenCacheService
            A new token cache.
        """
        storage = EncryptedPydanticRedisStorage(
            datatype=TokenData,
            redis=self._context.redis,
            encryption_key=self._context.config.session_secret,
            key_prefix="token:",
        )
        slack_client = self.create_slack_client()
        token_redis_store = TokenRedisStore(
            storage, slack_client, self._logger
        )
        token_db_store = TokenDatabaseStore(self.session)
        token_change_store = TokenChangeHistoryStore(self.session)
        return TokenCacheService(
            config=self._context.config,
            internal_cache=self._context.internal_token_cache,
            notebook_cache=self._context.notebook_token_cache,
            token_db_store=token_db_store,
            token_redis_store=token_redis_store,
            token_change_store=token_change_store,
            logger=self._logger,
        )

    def create_token_service(self) -> TokenService:
        """Create a TokenService.

        Returns
        -------
        TokenService
            The new token manager.
        """
        token_db_store = TokenDatabaseStore(self.session)
        storage = EncryptedPydanticRedisStorage(
            datatype=TokenData,
            redis=self._context.redis,
            encryption_key=self._context.config.session_secret,
            key_prefix="token:",
        )
        slack_client = self.create_slack_client()
        token_redis_store = TokenRedisStore(
            storage, slack_client, self._logger
        )
        token_change_store = TokenChangeHistoryStore(self.session)
        token_cache_service = TokenCacheService(
            config=self._context.config,
            internal_cache=self._context.internal_token_cache,
            notebook_cache=self._context.notebook_token_cache,
            token_db_store=token_db_store,
            token_redis_store=token_redis_store,
            token_change_store=token_change_store,
            logger=self._logger,
        )
        return TokenService(
            config=self._context.config,
            token_cache=token_cache_service,
            token_db_store=token_db_store,
            token_redis_store=token_redis_store,
            token_change_store=token_change_store,
            logger=self._logger,
        )

    def create_user_info_service(self) -> UserInfoService:
        """Create a user information service.

        This service retrieves metadata about the user, such as their UID,
        groups, and GIDs.  This is the generic service that acts on Gafaelfawr
        tokens, without support for the additional authentication-time methods
        used by authentication providers.

        Returns
        -------
        UserInfoService
            Newly created service.
        """
        firestore = None
        if self._context.config.firestore:
            firestore = self.create_firestore_service()
        ldap = None
        if self._context.config.ldap and self._context.ldap_pool:
            ldap_storage = LDAPStorage(
                self._context.config.ldap,
                self._context.ldap_pool,
                self._logger,
            )
            ldap = LDAPService(
                ldap=ldap_storage,
                group_cache=self._context.ldap_group_cache,
                group_name_cache=self._context.ldap_group_name_cache,
                user_cache=self._context.ldap_user_cache,
                logger=self._logger,
            )
        return UserInfoService(
            config=self._context.config,
            ldap=ldap,
            firestore=firestore,
            logger=self._logger,
        )

    def set_context(self, context: ProcessContext) -> None:
        """Replace the process context.

        Used by the test suite when it reconfigures Gafaelfawr on the fly
        after a factory was already created.

        Parameters
        ----------
        context
            New process context.
        """
        self._context = context

    def set_logger(self, logger: BoundLogger) -> None:
        """Replace the internal logger.

        Used by the context dependency to update the logger for all
        newly-created components when it's rebound with additional context.

        Parameters
        ----------
        logger
            New logger.
        """
        self._logger = logger
