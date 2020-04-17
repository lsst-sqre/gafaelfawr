"""OpenID Connect authentication provider."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from jwt_authorizer.providers.base import Provider, ProviderException
from jwt_authorizer.session import Session, SessionHandle
from jwt_authorizer.tokens import Token

if TYPE_CHECKING:
    from aiohttp import ClientSession
    from logging import Logger
    from jwt_authorizer.config import OIDCConfig
    from jwt_authorizer.issuer import TokenIssuer
    from jwt_authorizer.session import SessionStore
    from jwt_authorizer.verify import TokenVerifier

__all__ = ["OIDCException", "OIDCProvider"]


class OIDCException(ProviderException):
    """The OpenID Connect provider returned an error from an API call."""


class OIDCProvider(Provider):
    """Authenticate a user with GitHub.

    Parameters
    ----------
    config : `jwt_authorizer.config.OIDCConfig`
        Configuration for the OpenID Connect authentication provider.
    verifier : `jwt_authorizer.verify.TokenVerifier`
        Token verifier to use to verify the token returned by the provider.
    http_session : `aiohttp.ClientSession`
        Session to use to make HTTP requests.
    issuer : `jwt_authorizer.issuer.TokenIssuer`
        Issuer to use to generate new tokens.
    session_store : `jwt_authorizer.session.SessionStore`
        Store for authentication sessions.
    logger : `logging.Logger`
        Logger for any log messages.
    """

    def __init__(
        self,
        *,
        config: OIDCConfig,
        verifier: TokenVerifier,
        http_session: ClientSession,
        issuer: TokenIssuer,
        session_store: SessionStore,
        logger: Logger,
    ) -> None:
        self._config = config
        self._verifier = verifier
        self._http_session = http_session
        self._issuer = issuer
        self._session_store = session_store
        self._logger = logger

    def get_redirect_url(self, state: str) -> str:
        """Get the login URL to which to redirect the user.

        Parameters
        ----------
        state : `str`
            A random string used for CSRF protection.

        Returns
        -------
        url : `str`
            The encoded URL to which to redirect the user.
        """
        scopes = ["openid"]
        scopes.extend(self._config.scopes)
        params = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_url,
            "scope": " ".join(scopes),
            "state": state,
        }
        params.update(self._config.login_params)
        self._logger.info(
            "Redirecting user to %s for authentication", self._config.login_url
        )
        return f"{self._config.login_url}?{urlencode(params)}"

    async def create_session(self, code: str, state: str) -> Session:
        """Given the code from a successful authentication, get a token.

        Parameters
        ----------
        code : `str`
            Code returned by a successful authentication.
        state : `str`
            The same random string used for the redirect URL.

        Returns
        -------
        session : `jwt_authorizer.session.Session`
            The new authentication session.

        Raises
        ------
        aiohttp.ClientResponseError
            An HTTP client error occurred trying to talk to the authentication
            provider.
        jwt.exceptions.InvalidTokenError
            The token returned by the OpenID Connect provider was invalid.
        OIDCException
            The OpenID Connect provider responded with an error to a request.
        """
        data = {
            "grant_type": "authorization_code",
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "code": code,
            "redirect_uri": self._config.redirect_url,
        }
        self._logger.info(
            "Retrieving ID token from %s", self._config.token_url
        )
        r = await self._http_session.post(
            self._config.token_url,
            data=data,
            headers={"Accept": "application/json"},
            raise_for_status=True,
        )
        result = await r.json()
        if "id_token" not in result:
            msg = f"No id_token in token reply from {self._config.token_url}"
            raise OIDCException(msg)

        token = await self._verifier.verify(Token(encoded=result["id_token"]))

        handle = SessionHandle()
        token = self._issuer.reissue_token(token, jti=handle.key)
        session = Session.create(handle, token)
        await self._session_store.store_session(session)
        return session
