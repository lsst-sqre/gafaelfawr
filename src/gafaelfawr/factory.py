"""Create Gafaelfawr components."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from gafaelfawr.issuer import TokenIssuer
from gafaelfawr.oidc import OIDCServer
from gafaelfawr.providers.github import GitHubProvider
from gafaelfawr.providers.oidc import OIDCProvider
from gafaelfawr.storage.base import RedisStorage
from gafaelfawr.storage.oidc import OIDCAuthorization, OIDCAuthorizationStore
from gafaelfawr.storage.session import SerializedSession, SessionStore
from gafaelfawr.storage.user_token import UserTokenStore
from gafaelfawr.verify import TokenVerifier

if TYPE_CHECKING:
    from typing import Optional

    from aiohttp import ClientSession
    from aioredis import Redis
    from structlog import BoundLogger

    from gafaelfawr.config import Config
    from gafaelfawr.providers.base import Provider


class ComponentFactory:
    """Build Gafaelfawr components.

    Given the application configuration, construct the components of the
    application on demand.  This is broken into a separate class primarily so
    that the test suite can override portions of it.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        Gafaelfawr configuration.
    """

    def __init__(
        self,
        *,
        config: Config,
        redis: Redis,
        http_session: ClientSession,
        logger: Optional[BoundLogger] = None,
    ) -> None:
        if not logger:
            structlog.configure(wrapper_class=structlog.stdlib.BoundLogger)
            logger = structlog.get_logger("gafaelfawr")

        self._config = config
        self._redis = redis
        self._http_session = http_session
        self._logger = logger

    def create_oidc_server(self) -> OIDCServer:
        """Create a minimalist OpenID Connect server.

        Returns
        -------
        oidc_server : `gafaelfawr.openid.OIDCServer`
            A new OpenID Connect server.
        """
        assert self._config.oidc_server
        key = self._config.session_secret
        storage = RedisStorage(OIDCAuthorization, key, self._redis)
        authorization_store = OIDCAuthorizationStore(storage)
        issuer = self.create_token_issuer()
        session_store = self.create_session_store()
        return OIDCServer(
            config=self._config.oidc_server,
            authorization_store=authorization_store,
            issuer=issuer,
            session_store=session_store,
            logger=self._logger,
        )

    def create_provider(self) -> Provider:
        """Create an authentication provider.

        Create a provider object for the configured external authentication
        provider.  Takes the incoming request to get access to the per-request
        logger and the client HTTP session.

        Returns
        -------
        provider : `gafaelfawr.providers.base.Provider`
            A new Provider.

        Raises
        ------
        NotImplementedError
            None of the authentication providers are configured.
        """
        issuer = self.create_token_issuer()
        session_store = self.create_session_store()
        if self._config.github:
            return GitHubProvider(
                config=self._config.github,
                http_session=self._http_session,
                issuer=issuer,
                session_store=session_store,
                logger=self._logger,
            )
        elif self._config.oidc:
            token_verifier = self.create_token_verifier()
            return OIDCProvider(
                config=self._config.oidc,
                verifier=token_verifier,
                issuer=issuer,
                session_store=session_store,
                http_session=self._http_session,
                logger=self._logger,
            )
        else:
            # This should be caught during configuration file parsing.
            raise NotImplementedError("No authentication provider configured")

    def create_session_store(self) -> SessionStore:
        """Create a SessionStore.

        Returns
        -------
        session_store : `gafaelfawr.storage.session.SessionStore`
            A new SessionStore.
        """
        key = self._config.session_secret
        storage = RedisStorage(SerializedSession, key, self._redis)
        verifier = self.create_token_verifier()
        return SessionStore(storage, verifier, self._logger)

    def create_token_issuer(self) -> TokenIssuer:
        """Create a TokenIssuer.

        Returns
        -------
        issuer : `gafaelfawr.issuer.TokenIssuer`
            A new TokenIssuer.
        """
        return TokenIssuer(self._config.issuer)

    def create_token_verifier(self) -> TokenVerifier:
        """Create a TokenVerifier from a web request.

        Returns
        -------
        token_verifier : `gafaelfawr.verify.TokenVerifier`
            A new TokenVerifier.
        """
        return TokenVerifier(
            self._config.verifier, self._http_session, self._logger
        )

    def create_user_token_store(self) -> UserTokenStore:
        """Create a UserTokenStore.

        Returns
        -------
        token_store : `gafaelfawr.storage.user_token.UserTokenStore`
            A new TokenStore.
        """
        return UserTokenStore(self._redis, self._logger)
