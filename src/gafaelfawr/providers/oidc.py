"""OpenID Connect authentication provider."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

import jwt

from gafaelfawr.exceptions import OIDCException, VerifyTokenException
from gafaelfawr.providers.base import Provider
from gafaelfawr.session import Session, SessionHandle
from gafaelfawr.tokens import Token

if TYPE_CHECKING:
    from aiohttp import ClientSession
    from structlog import BoundLogger

    from gafaelfawr.config import OIDCConfig
    from gafaelfawr.issuer import TokenIssuer
    from gafaelfawr.storage.session import SessionStore
    from gafaelfawr.verify import TokenVerifier

__all__ = ["OIDCProvider"]


class OIDCProvider(Provider):
    """Authenticate a user with GitHub.

    Parameters
    ----------
    config : `gafaelfawr.config.OIDCConfig`
        Configuration for the OpenID Connect authentication provider.
    verifier : `gafaelfawr.verify.TokenVerifier`
        Token verifier to use to verify the token returned by the provider.
    issuer : `gafaelfawr.issuer.TokenIssuer`
        Issuer to use to generate new tokens.
    session_store : `gafaelfawr.storage.session.SessionStore`
        Store for authentication sessions.
    http_session : `aiohttp.ClientSession`
        Session to use to make HTTP requests.
    logger : `structlog.BoundLogger`
        Logger for any log messages.
    """

    def __init__(
        self,
        *,
        config: OIDCConfig,
        verifier: TokenVerifier,
        issuer: TokenIssuer,
        session_store: SessionStore,
        http_session: ClientSession,
        logger: BoundLogger,
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
        session : `gafaelfawr.session.Session`
            The new authentication session.

        Raises
        ------
        aiohttp.ClientResponseError
            An HTTP client error occurred trying to talk to the authentication
            provider.
        jwt.exceptions.InvalidTokenError
            The token returned by the OpenID Connect provider was invalid.
        gafaelfawr.exceptions.OIDCException
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
        )

        # If the call failed, try to extract an error from the reply.  If that
        # fails, just raise an exception for the HTTP status.
        try:
            result = await r.json()
        except Exception:
            if r.status != 200:
                r.raise_for_status()
            else:
                msg = "Response from {self._config.token_url} not valid JSON"
                raise OIDCException(msg)
        if r.status != 200 and "error" in result:
            msg = result["error"] + ": " + result["error_description"]
            raise OIDCException(msg)
        elif r.status != 200:
            r.raise_for_status()
        if "id_token" not in result:
            msg = f"No id_token in token reply from {self._config.token_url}"
            raise OIDCException(msg)

        # Extract and verify the token.
        unverified_token = Token(encoded=result["id_token"])
        try:
            token = await self._verifier.verify_oidc_token(unverified_token)
        except (jwt.InvalidTokenError, VerifyTokenException) as e:
            msg = f"OpenID Connect token verification failed: {str(e)}"
            raise OIDCException(msg)

        # Store it as a session and return the session.
        handle = SessionHandle()
        token = self._issuer.reissue_token(token, jti=handle.key)
        session = Session.create(handle, token)
        await self._session_store.store_session(session)
        return session
