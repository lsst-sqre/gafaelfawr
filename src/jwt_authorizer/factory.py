"""Create JWT Authorizer components."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from jwt_authorizer.issuer import TokenIssuer
from jwt_authorizer.providers.github import GitHubProvider
from jwt_authorizer.providers.oidc import OIDCProvider
from jwt_authorizer.session import SessionStore
from jwt_authorizer.token_store import TokenStore
from jwt_authorizer.verify import TokenVerifier

if TYPE_CHECKING:
    from aiohttp import ClientSession, web
    from aioredis import Redis
    from cachetools import TTLCache
    from jwt_authorizer.config import Config
    from logging import Logger
    from typing import Optional


class ComponentFactory:
    """Build JWT Authorizer components.

    Given the application configuration, construct the components of the
    application on demand.  This is broken into a separate class primarily so
    that the test suite can override portions of it.

    Parameters
    ----------
    config : `jwt_authorizer.config.Config`
        JWT Authorizer configuration.
    """

    def __init__(
        self,
        config: Config,
        redis: Redis,
        key_cache: TTLCache,
        http_session: Optional[ClientSession],
    ) -> None:
        self._config = config
        self._redis = redis
        self._key_cache = key_cache
        self._http_session = http_session

    def create_github_provider(self, request: web.Request) -> GitHubProvider:
        """Create a GitHub authentication provider.

        Takes the incoming request to get access to the per-request logger and
        the client HTTP session.

        Parameters
        ----------
        request : `aiohttp.web.Request`
            The incoming request.

        Returns
        -------
        provider : `jwt_authorizer.providers.github.GitHubProvider`
            A new GitHubProvider.
        """
        assert self._config.github
        http_session = self.create_http_session(request)
        issuer = self.create_token_issuer()
        session_store = self.create_session_store(request)
        logger = self.create_logger(request)
        return GitHubProvider(
            config=self._config.github,
            http_session=http_session,
            issuer=issuer,
            session_store=session_store,
            logger=logger,
        )

    def create_oidc_provider(self, request: web.Request) -> OIDCProvider:
        """Create an OpenID Connect authentication provider.

        Takes the incoming request to get access to the per-request logger and
        the client HTTP session.

        Parameters
        ----------
        request : `aiohttp.web.Request`
            The incoming request.

        Returns
        -------
        provider : `jwt_authorizer.providers.oidc.OIDCProvider`
            A new OIDCProvider.
        """
        assert self._config.oidc
        token_verifier = self.create_token_verifier(request)
        issuer = self.create_token_issuer()
        session_store = self.create_session_store(request)
        http_session = self.create_http_session(request)
        logger = self.create_logger(request)
        return OIDCProvider(
            config=self._config.oidc,
            verifier=token_verifier,
            issuer=issuer,
            session_store=session_store,
            http_session=http_session,
            logger=logger,
        )

    def create_session_store(
        self, request: Optional[web.Request] = None
    ) -> SessionStore:
        """Create a SessionStore.

        Parameters
        ----------
        request : `aiohttp.web.Request`, optional
            The incoming request, used to get a logger.  If not given, the
            base logger will be used.

        Returns
        -------
        session_store : `jwt_authorizer.session.SessionStore`
            A new SessionStore.
        """
        key = self._config.session_secret
        verifier = self.create_token_verifier(request)
        logger = self.create_logger(request)
        return SessionStore(key, verifier, self._redis, logger)

    def create_token_issuer(self) -> TokenIssuer:
        """Create a TokenIssuer.

        Returns
        -------
        issuer : `jwt_authorizer.issuer.TokenIssuer`
            A new TokenIssuer.
        """
        return TokenIssuer(self._config)

    def create_token_store(
        self, request: Optional[web.Request] = None
    ) -> TokenStore:
        """Create a TokenStore.

        Parameters
        ----------
        request : `aiohttp.web.Request`, optional
            The incoming request, used to get a logger.  If not given, the
            base logger will be used.

        Returns
        -------
        token_store : `jwt_authorizer.tokens.TokenStore`
            A new TokenStore.
        """
        logger = self.create_logger(request)
        return TokenStore(self._redis, logger)

    def create_token_verifier(
        self, request: Optional[web.Request] = None
    ) -> TokenVerifier:
        """Create a TokenVerifier from a web request.

        Parameters
        ----------
        request : `aiohttp.web.Request`, optional
            The incoming request, used to get a logger.  If not given, the
            base logger will be used.

        Returns
        -------
        token_verifier : `jwt_authorizer.verify.TokenVerifier`
            A new TokenVerifier.
        """
        http_session = self.create_http_session(request)
        logger = self.create_logger(request)
        return TokenVerifier(
            self._config, http_session, self._key_cache, logger
        )

    def create_http_session(
        self, request: Optional[web.Request] = None
    ) -> ClientSession:
        """Create an aiohttp client session.

        Parameters
        ----------
        request : `aiohttp.web.Request`
            The incoming request, used to get the Safir-created session.

        Returns
        -------
        http_session : `aiohttp.ClientSession`
            An aiohttp client session.

        Notes
        -----
        Normally, we use the HTTP session put into the app by Safir.  This is
        not created at the time the component factory is initialized during
        app creation, so we pull it from the request.

        However, in the test suite, we create a mock HTTP client session,
        which is injected into the component factory on creation.  In that
        case, we prefer that one.
        """
        if self._http_session:
            return self._http_session
        assert request
        return request.config_dict["safir/http_session"]

    def create_logger(self, request: Optional[web.Request] = None) -> Logger:
        """Create a logger.

        Prefers the per-request logger if available.  Otherwise, returns a
        top-level logger for the application.
        """
        if request:
            return request["safir/logger"]
        else:
            return structlog.get_logger("jwt_authorizer")
