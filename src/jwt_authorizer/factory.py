"""Create JWT Authorizer components."""

from __future__ import annotations

from typing import TYPE_CHECKING

from jwt_authorizer.issuer import TokenIssuer
from jwt_authorizer.providers import GitHubProvider
from jwt_authorizer.session import SessionStore
from jwt_authorizer.tokens import TokenStore
from jwt_authorizer.verify import KeyClient, TokenVerifier

if TYPE_CHECKING:
    from aiohttp import ClientSession, web
    from aioredis import Redis
    from jwt_authorizer.config import Config
    from logging import Logger


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

    def __init__(self, config: Config, redis: Redis) -> None:
        self._config = config
        self._redis = redis

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
        token_verifier : `jwt_authorizer.verify.TokenVerifier`
            A new TokenVerifier.
        """
        logger: Logger = request["safir/logger"]
        http_session: ClientSession = request.config_dict["safir/http_session"]

        assert self._config.github
        return GitHubProvider(self._config.github, http_session, logger)

    def create_session_store(self) -> SessionStore:
        """Create a SessionStore.

        Returns
        -------
        session_store : `jwt_authorizer.session.SessionStore`
            A new SessionStore.
        """
        prefix = self._config.session_store.ticket_prefix
        secret = self._config.session_store.oauth2_proxy_secret
        return SessionStore(prefix, secret, self._redis)

    def create_token_issuer(self) -> TokenIssuer:
        """Create a TokenIssuer.

        Returns
        -------
        issuer : `jwt_authorizer.issuer.TokenIssuer`
            A new TokenIssuer.
        """
        prefix = self._config.session_store.ticket_prefix
        session_store = self.create_session_store()
        return TokenIssuer(
            self._config.issuer, prefix, session_store, self._redis
        )

    def create_token_store(self) -> TokenStore:
        """Create a TokenStore.

        Returns
        -------
        token_store : `jwt_authorizer.tokens.TokenStore`
            A new TokenStore.
        """
        return TokenStore(self._redis, self._config.uid_key)

    def create_token_verifier(self, request: web.Request) -> TokenVerifier:
        """Create a TokenVerifier from a web request.

        Takes the incoming request to get access to the per-request logger and
        the client HTTP session.

        Parameters
        ----------
        request : `aiohttp.web.Request`
            The incoming request.

        Returns
        -------
        token_verifier : `jwt_authorizer.verify.TokenVerifier`
            A new TokenVerifier.
        """
        logger: Logger = request["safir/logger"]
        http_session: ClientSession = request.config_dict["safir/http_session"]

        key_client = KeyClient(http_session)
        return TokenVerifier(self._config.issuers, key_client, logger)
