"""OpenID Connect identity provider support."""

from __future__ import annotations

from datetime import datetime, timezone

import jwt
from structlog.stdlib import BoundLogger

from ..config import OIDCServerConfig
from ..constants import ALGORITHM
from ..exceptions import (
    DeserializeError,
    InvalidClientError,
    InvalidGrantError,
    InvalidTokenError,
    UnauthorizedClientError,
)
from ..models.oidc import (
    JWKS,
    OIDCAuthorization,
    OIDCAuthorizationCode,
    OIDCConfig,
    OIDCToken,
    OIDCVerifiedToken,
)
from ..models.token import Token, TokenUserInfo
from ..storage.oidc import OIDCAuthorizationStore
from .token import TokenService

__all__ = ["OIDCService"]


class OIDCService:
    """Minimalist OpenID Connect identity provider.

    This provides just enough of the OpenID Connect protocol to satisfy
    Chronograf (and possibly some other applications).  It is the underlying
    implementation of the ``/auth/openid`` routes.

    Parameters
    ----------
    config
        OpenID Connect server configuration.
    authorization_store
        The underlying storage for OpenID Connect authorizations.
    token_service
        Token manipulation service.
    logger
        Logger for diagnostics.

    Notes
    -----
    Expects the following flow:

    #. User is sent to ``/auth/openid/login`` for initial authentication.
    #. User is redirected back to the application with an authorization code.
    #. Application submits code to ``/auth/openid/token``.
    #. Application receives an access token and an ID token (the same).
    #. Application gets user information from ``/auth/openid/userinfo``.

    The handler code is responsible for parsing the requests from the user.
    This object creates the authorization code (with its associated Redis
    entry) for step 2, and then returns the token for that code in step 4.
    """

    def __init__(
        self,
        *,
        config: OIDCServerConfig,
        authorization_store: OIDCAuthorizationStore,
        token_service: TokenService,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._authorization_store = authorization_store
        self._token_service = token_service
        self._logger = logger

    async def delete_all_codes(self) -> None:
        """Invalidate all issued OpenID Connect codes."""
        await self._authorization_store.delete_all()

    def get_jwks(self) -> JWKS:
        """Return the key set for the OpenID Connect server."""
        key_id = self._config.key_id
        return self._config.keypair.public_key_as_jwks(kid=key_id)

    def get_openid_configuration(self) -> OIDCConfig:
        """Return the OpenID Connect configuration for the internal server."""
        base_url = self._config.issuer
        return OIDCConfig(
            issuer=base_url,
            authorization_endpoint=base_url + "/auth/openid/login",
            token_endpoint=base_url + "/auth/openid/token",
            userinfo_endpoint=base_url + "/auth/openid/userinfo",
            jwks_uri=base_url + "/.well-known/jwks.json",
        )

    def is_valid_client(self, client_id: str) -> bool:
        """Whether a client_id is a valid registered client.

        Parameters
        ----------
        client_id
            ``client_id`` parameter from the client.
        """
        return any(c.client_id == client_id for c in self._config.clients)

    async def issue_code(
        self, client_id: str, redirect_uri: str, token: Token
    ) -> OIDCAuthorizationCode:
        """Issue a new authorization code.

        Parameters
        ----------
        client_id
            The client ID with access to this authorization.
        redirect_uri
            The intended return URI for this authorization.
        token
            The underlying authentication token.

        Returns
        -------
        OIDCAuthorizationCode
            The code for a newly-created and stored authorization.

        Raises
        ------
        UnauthorizedClientError
            The provided client ID is not registered as an OpenID Connect
            client.
        """
        if not self.is_valid_client(client_id):
            raise UnauthorizedClientError(f"Unknown client ID {client_id}")
        authorization = OIDCAuthorization(
            client_id=client_id, redirect_uri=redirect_uri, token=token
        )
        await self._authorization_store.create(authorization)
        return authorization.code

    def issue_token(
        self, user_info: TokenUserInfo, **claims: str
    ) -> OIDCVerifiedToken:
        """Issue an OpenID Connect token.

        This creates a new OpenID Connect token with data taken from the
        internal Gafaelfawr token.

        Parameters
        ----------
        user_info
            The token data on which to base the token.
        **claims
            Additional claims to add to the token.

        Returns
        -------
        OIDCVerifiedToken
            The new token.
        """
        now = datetime.now(timezone.utc)
        expires = now + self._config.lifetime
        payload = {
            "aud": self._config.audience,
            "iat": int(now.timestamp()),
            "iss": self._config.issuer,
            "exp": int(expires.timestamp()),
            "name": user_info.name,
            "preferred_username": user_info.username,
            "sub": user_info.username,
            "uid_number": user_info.uid,
            **claims,
        }
        encoded_token = jwt.encode(
            payload,
            self._config.keypair.private_key_as_pem().decode(),
            algorithm=ALGORITHM,
            headers={"kid": self._config.key_id},
        )
        return OIDCVerifiedToken(
            encoded=encoded_token,
            claims=payload,
            username=payload["sub"],
            uid=payload["uid_number"],
            jti=payload.get("jti"),
        )

    async def redeem_code(
        self,
        client_id: str,
        client_secret: str | None,
        redirect_uri: str,
        code: OIDCAuthorizationCode,
    ) -> OIDCVerifiedToken:
        """Redeem an authorization code.

        Parameters
        ----------
        client_id
            The client ID of the OpenID Connect client.
        client_secret
            The secret for that client.  A secret of `None` will never be
            valid, but is accepted so that error handling can be unified.
        redirect_uri
            The return URI of the OpenID Connect client.
        code
            The OpenID Connect authorization code.

        Returns
        -------
        OIDCVerifiedToken
            A newly-issued JWT for this client.

        Raises
        ------
        InvalidClientError
            If the client ID is not known or the client secret does not match
            the client ID.
        InvalidGrantError
            If the code is not valid, the client is not allowed to use it,
            or the underlying authorization or session does not exist.
        """
        self._check_client_secret(client_id, client_secret)
        try:
            authorization = await self._authorization_store.get(code)
        except DeserializeError as e:
            msg = f"Cannot get authorization for {code.key}: {str(e)}"
            raise InvalidGrantError(msg) from e
        if not authorization:
            msg = f"Unknown authorization code {code.key}"
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

        user_info = await self._token_service.get_user_info(
            authorization.token
        )
        if not user_info:
            msg = f"Invalid underlying token for authorization {code.key}"
            raise InvalidGrantError(msg)
        token = self.issue_token(user_info, jti=code.key, scope="openid")

        # The code is valid and we're going to return success, so delete it
        # from Redis so that it cannot be reused.
        await self._authorization_store.delete(code)
        return token

    def verify_token(self, token: OIDCToken) -> OIDCVerifiedToken:
        """Verify a token issued by the internal OpenID Connect server.

        Parameters
        ----------
        token
            An encoded token.

        Returns
        -------
        OIDCVerifiedToken
            The verified token.

        Raises
        ------
        InvalidTokenError
            The issuer of this token is unknown and therefore the token cannot
            be verified.
        """
        try:
            payload = jwt.decode(
                token.encoded,
                self._config.keypair.public_key_as_pem().decode(),
                algorithms=[ALGORITHM],
                audience=self._config.audience,
            )
            return OIDCVerifiedToken(
                encoded=token.encoded,
                claims=payload,
                jti=payload["jti"],
                username=payload["sub"],
            )
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(str(e)) from e
        except KeyError as e:
            raise InvalidTokenError(f"Missing claim {str(e)}") from e

    def _check_client_secret(
        self, client_id: str, client_secret: str | None
    ) -> None:
        """Check that the client ID and client secret match.

        Parameters
        ----------
        client_id
            The OpenID Connect client ID.
        client_secret
            The secret for that client ID.

        Raises
        ------
        InvalidClientError
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
