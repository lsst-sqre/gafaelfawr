"""Create Gafaelfawr components."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from gafaelfawr.issuer import TokenIssuer
from gafaelfawr.providers.github import GitHubProvider
from gafaelfawr.providers.oidc import OIDCProvider
from gafaelfawr.session import SessionStore
from gafaelfawr.token_store import TokenStore
from gafaelfawr.verify import TokenVerifier

if TYPE_CHECKING:
    from aiohttp import ClientSession, web
    from aioredis import Redis
    from cachetools import TTLCache
    from gafaelfawr.config import Config
    from gafaelfawr.providers.base import Provider
    from structlog import BoundLogger
    from typing import Optional


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
        config: Config,
        redis: Redis,
        key_cache: TTLCache,
        http_session: Optional[ClientSession],
    ) -> None:
        self._config = config
        self._redis = redis
        self._key_cache = key_cache
        self._http_session = http_session

    def create_provider(
        self, request: web.Request, logger: BoundLogger
    ) -> Provider:
        """Create an authentication provider.

        Create a provider object for the configured external authentication
        provider.  Takes the incoming request to get access to the per-request
        logger and the client HTTP session.

        Parameters
        ----------
        request : `aiohttp.web.Request`
            The incoming request, used to get the `~aiohttp.ClientSession`.
        logger : `structlog.BoundLogger`
            The logger to use.

        Returns
        -------
        provider : `gafaelfawr.providers.base.Provider`
            A new Provider.

        Raises
        ------
        NotImplementedError
            None of the authentication providers are configured.
        """
        http_session = self.create_http_session(request)
        issuer = self.create_token_issuer()
        session_store = self.create_session_store(request)
        if self._config.github:
            return GitHubProvider(
                config=self._config.github,
                http_session=http_session,
                issuer=issuer,
                session_store=session_store,
                logger=logger,
            )
        elif self._config.oidc:
            token_verifier = self.create_token_verifier(request)
            return OIDCProvider(
                config=self._config.oidc,
                verifier=token_verifier,
                issuer=issuer,
                session_store=session_store,
                http_session=http_session,
                logger=logger,
            )
        else:
            # This should be caught during configuration file parsing.
            raise NotImplementedError("No authentication provider configured")

    def create_session_store(
        self,
        request: Optional[web.Request] = None,
        logger: Optional[BoundLogger] = None,
    ) -> SessionStore:
        """Create a SessionStore.

        Parameters
        ----------
        request : `aiohttp.web.Request`
            The incoming request, used to get the `~aiohttp.ClientSession`.
        logger : `structlog.BoundLogger`, optional
            The logger to use.  If not given, the base logger will be used.

        Returns
        -------
        session_store : `gafaelfawr.session.SessionStore`
            A new SessionStore.
        """
        if not logger:
            logger = structlog.get_logger("gafaelfawr")
        key = self._config.session_secret
        verifier = self.create_token_verifier(request)
        return SessionStore(key, verifier, self._redis, logger)

    def create_token_issuer(self) -> TokenIssuer:
        """Create a TokenIssuer.

        Returns
        -------
        issuer : `gafaelfawr.issuer.TokenIssuer`
            A new TokenIssuer.
        """
        return TokenIssuer(self._config.issuer)

    def create_token_store(
        self, logger: Optional[BoundLogger] = None
    ) -> TokenStore:
        """Create a TokenStore.

        Parameters
        ----------
        logger : `structlog.BoundLogger`, optional
            The logger to use.  If not given, the base logger will be used.

        Returns
        -------
        token_store : `gafaelfawr.tokens.TokenStore`
            A new TokenStore.
        """
        if not logger:
            logger = structlog.get_logger("gafaelfawr")
        return TokenStore(self._redis, logger)

    def create_token_verifier(
        self,
        request: Optional[web.Request] = None,
        logger: Optional[BoundLogger] = None,
    ) -> TokenVerifier:
        """Create a TokenVerifier from a web request.

        Parameters
        ----------
        request : `aiohttp.web.Request`, optional
            The incoming request, used to get the `~aiohttp.ClientSession`.
            This may be omitted only in the test suite, which provides a mock
            `~aiohttp.ClientSession` via a different mechanism.
        logger : `structlog.BoundLogger`, optional
            The logger to use.  If not given, the base logger will be used.

        Returns
        -------
        token_verifier : `gafaelfawr.verify.TokenVerifier`
            A new TokenVerifier.
        """
        if not logger:
            logger = structlog.get_logger("gafaelfawr")
        http_session = self.create_http_session(request)
        return TokenVerifier(
            self._config.verifier, http_session, self._key_cache, logger
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
