"""OpenID Connect identity provider support."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.exceptions import (
    DeserializeException,
    InvalidClientError,
    InvalidGrantError,
    UnauthorizedClientException,
)
from gafaelfawr.session import SessionHandle

if TYPE_CHECKING:
    from typing import Optional

    from structlog import BoundLogger

    from gafaelfawr.config import OIDCServerConfig
    from gafaelfawr.issuer import TokenIssuer
    from gafaelfawr.storage.oidc import (
        OIDCAuthorizationCode,
        OIDCAuthorizationStore,
    )
    from gafaelfawr.storage.session import SessionStore
    from gafaelfawr.tokens import VerifiedToken

__all__ = ["OIDCServer"]


class OIDCServer:
    """Minimalist OpenID Connect identity provider.

    This provides just enough of the OpenID Connect protocol to satisfy
    Chronograf (and possibly some other applications).  It is the underlying
    implementation of the ``/auth/openid`` routes.

    Parameters
    ----------
    authorization_store : `gafaelfawr.storage.oidc.OIDCAuthorizationStore`
        The underlying storage for OpenID Connect authorizations.
    issuer : `gafaelfawr.issuer.TokenIssuer`
        JWT issuer.
    session_store : `gafaelfawr.storage.session.SessionStore`
        Storage for authentication sessions.
    logger : `structlog.BoundLogger`
        Logger for diagnostics.

    Notes
    -----
    Expects the following flow:

    #. User is sent to ``/auth/openid/login`` for initial authentication.
    #. User is redirected back to the application with an authorization code.
    #. Application submits code to ``/auth/openid/token``.
    #. Application receives an access token and an ID token (the same).
    #. Application gets user information from ``/auth/openid/userinfo``.

    The handler code in :py:mod:`gafaelfawr.handlers.oidc` is responsible
    for parsing the requests from the user.  This object creates the
    authorization code (with its associated Redis entry) for step 2, and then
    returns the token for that code in step 4.
    """

    def __init__(
        self,
        *,
        config: OIDCServerConfig,
        authorization_store: OIDCAuthorizationStore,
        issuer: TokenIssuer,
        session_store: SessionStore,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._authorization_store = authorization_store
        self._issuer = issuer
        self._session_store = session_store
        self._logger = logger

    def is_valid_client(self, client_id: str) -> bool:
        """Whether a client_id is a valid registered client."""
        return any((c.client_id == client_id for c in self._config.clients))

    async def issue_code(
        self, client_id: str, redirect_uri: str, session_handle: SessionHandle
    ) -> OIDCAuthorizationCode:
        """Issue a new authorization code.

        Parameters
        ----------
        client_id : `str`
            The client ID with access to this authorization.
        redirect_uri : `str`
            The intended return URI for this authorization.
        session_handle : `gafaelfawr.session.SessionHandle`
            The handle for the underlying authentication session.

        Returns
        -------
        code : `gafaelfawr.session.SessionHandle`
            The OpenID Connect authorization code.

        Raises
        ------
        gafaelfawr.exceptions.UnauthorizedClientException
            The provided client ID is not registered as an OpenID Connect
            client.
        """
        if not self.is_valid_client(client_id):
            raise UnauthorizedClientException(f"Unknown client ID {client_id}")
        return await self._authorization_store.create(
            client_id, redirect_uri, session_handle
        )

    async def redeem_code(
        self,
        client_id: str,
        client_secret: Optional[str],
        redirect_uri: str,
        code: OIDCAuthorizationCode,
    ) -> VerifiedToken:
        """Redeem an authorization code.

        Parameters
        ----------
        client_id : `str`
            The client ID of the OpenID Connect client.
        client_secret : `str` or `None`
            The secret for that client.  A secret of `None` will never be
            valid, but is accepted so that error handling can be unified.
        redirect_uri : `str`
            The return URI of the OpenID Connect client.
        code : `gafaelfawr.session.SessionHandle`
            The OpenID Connect authorization code.

        Returns
        -------
        token : `gafaelfawr.tokens.VerifiedToken`
            A newly-issued JWT for this client.

        Raises
        ------
        gafaelfawr.exceptions.InvalidClientError
            If the client ID is not known or the client secret does not match
            the client ID.
        gafaelfawr.exceptions.InvalidGrantError
            If the code is not valid, the client is not allowed to use it,
            or the underlying authorization or session does not exist.
        """
        self._check_client_secret(client_id, client_secret)
        try:
            authorization = await self._authorization_store.get(code)
        except DeserializeException as e:
            msg = f"Cannot get authorization for {code.key}: {str(e)}"
            raise InvalidGrantError(msg)
        if not authorization:
            msg = f"Unknown authoriation code {code.key}"
            raise InvalidGrantError(msg)

        if authorization.client_id != client_id:
            msg = (
                f"Authorization client ID mismatch for {code.key}:"
                f" {authorization.client_id} != {client_id}"
            )
            raise InvalidGrantError(msg)
        if authorization.redirect_uri != redirect_uri:
            msg = (
                f"Authorization redirect URI mismatch for {code.key}:"
                f" {authorization.redirect_uri} != {redirect_uri}"
            )
            raise InvalidGrantError(msg)

        session = await self._session_store.get_session(
            authorization.session_handle
        )
        if not session:
            msg = f"Invalid underlying session for authorization {code.key}"
            raise InvalidGrantError(msg)
        token = self._issuer.reissue_token(
            session.token, jti=code.key, scope="openid", internal=True
        )

        # The code is valid and we're going to return success, so delete it
        # from Redis so that it cannot be reused.
        await self._authorization_store.delete(code)
        return token

    def _check_client_secret(
        self, client_id: str, client_secret: Optional[str]
    ) -> None:
        """Check that the client ID and client secret match.

        Parameters
        ----------
        client_id : `str`
            The OpenID Connect client ID.
        client_secret : `str` or `None`
            The secret for that client ID.

        Raises
        ------
        gafaelfawr.exceptions.InvalidClientError
            If the client ID isn't known or the secret doesn't match.
        """
        if not client_secret:
            raise InvalidClientError("No client_secret provided")
        for client in self._config.clients:
            if client.client_id == client_id:
                if client.client_secret == client_secret:
                    return
                else:
                    msg = f"Invalid secret for {client_id}"
                    raise InvalidClientError(msg)
        raise InvalidClientError(f"Unknown client ID {client_id}")
