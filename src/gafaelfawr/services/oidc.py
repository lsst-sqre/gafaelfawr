"""OpenID Connect identity provider support."""

from __future__ import annotations

from typing import Any

import jwt
from safir.datetime import current_datetime
from safir.redis import DeserializeError
from safir.slack.webhook import SlackWebhookClient
from structlog.stdlib import BoundLogger

from ..config import OIDCServerConfig
from ..constants import ALGORITHM
from ..exceptions import (
    InvalidClientError,
    InvalidGrantError,
    InvalidRequestError,
    InvalidTokenError,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
)
from ..models.oidc import (
    JWKS,
    OIDCAuthorization,
    OIDCAuthorizationCode,
    OIDCConfig,
    OIDCScope,
    OIDCToken,
    OIDCVerifiedToken,
)
from ..models.token import Token, TokenUserInfo
from ..storage.oidc import OIDCAuthorizationStore
from .token import TokenService
from .userinfo import UserInfoService

__all__ = ["OIDCService"]

_SCOPE_CLAIMS = {
    OIDCScope.openid: frozenset(
        ["aud", "iat", "iss", "exp", "jti", "nonce", "scope", "sub"]
    ),
    OIDCScope.profile: frozenset(["name", "preferred_username"]),
    OIDCScope.email: frozenset(["email"]),
    OIDCScope.rubin: frozenset(["data_rights"]),
}
"""Mapping of scope values to the claims to expose for that scope."""


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
    user_info_service
        User information service.
    slack_client
        If provided, a Slack webhook client to use to report corruption of the
        underlying Redis store.
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
        user_info_service: UserInfoService,
        slack_client: SlackWebhookClient | None = None,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._authorization_store = authorization_store
        self._token_service = token_service
        self._user_info = user_info_service
        self._slack = slack_client
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
        self,
        *,
        client_id: str,
        redirect_uri: str,
        token: Token,
        scopes: list[OIDCScope],
        nonce: str | None = None,
    ) -> OIDCAuthorizationCode:
        """Issue a new authorization code.

        Parameters
        ----------
        client_id
            Client ID with access to this authorization.
        redirect_uri
            Intended return URI for this authorization.
        token
            Underlying authentication token.
        scopes
            Requested scopes.
        nonce
            Client-provided nonce.

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
            client_id=client_id,
            redirect_uri=redirect_uri,
            token=token,
            scopes=scopes,
            nonce=nonce,
        )
        await self._authorization_store.create(authorization)
        return authorization.code

    async def issue_id_token(
        self, authorization: OIDCAuthorization
    ) -> OIDCVerifiedToken:
        """Issue an OpenID Connect token.

        This creates a new OpenID Connect token with data taken from the
        internal Gafaelfawr token.

        Parameters
        ----------
        authorization
            Authorization code used to request a token.

        Returns
        -------
        OIDCVerifiedToken
            The new token.

        Raises
        ------
        InvalidGrantError
            Raised if the underlying authorization or session does not exist.
        """
        token_data = await self._token_service.get_data(authorization.token)
        if not token_data:
            code = authorization.code.key
            msg = f"Invalid underlying token for authorization {code}"
            raise InvalidGrantError(msg)
        user_info = await self._user_info.get_user_info_from_token(token_data)

        # Build a payload of every claim we support, and then filter it by the
        # list of claims that were requested via either claims or scopes and
        # by dropping any claims that were None.
        now = current_datetime()
        payload: dict[str, Any] = {
            "aud": authorization.client_id,
            "auth_time": int(token_data.created.timestamp()),
            "data_rights": self._build_data_rights_for_user(user_info),
            "iat": int(now.timestamp()),
            "iss": str(self._config.issuer),
            "email": user_info.email,
            "exp": int(token_data.expires.timestamp()),
            "jti": authorization.code.key,
            "name": user_info.name,
            "nonce": authorization.nonce,
            "preferred_username": token_data.username,
            "scope": " ".join(s.value for s in authorization.scopes),
            "sub": token_data.username,
        }
        payload = self._filter_claims(payload, authorization)

        # Encode the token.
        encoded_token = jwt.encode(
            payload,
            self._config.keypair.private_key_as_pem().decode(),
            algorithm=ALGORITHM,
            headers={"kid": self._config.key_id},
        )
        return OIDCVerifiedToken(
            encoded=encoded_token, claims=payload, jti=payload.get("jti")
        )

    async def redeem_code(
        self,
        *,
        grant_type: str | None,
        client_id: str | None,
        client_secret: str | None,
        redirect_uri: str | None,
        code: str | None,
    ) -> OIDCVerifiedToken:
        """Redeem an authorization code.

        None of the parameters may be `None` in practice, but `None` is
        accepted and rejected wih an exception so that error handling can be
        unified.

        Parameters
        ----------
        grant_type
            Type of token grant requested.
        client_id
            Client ID of the OpenID Connect client.
        client_secret
            Secret for that client.  A secret of `None` will never be valid,
            but is accepted so that error handling can be unified.
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
            Raised if the client ID is not known or the client secret does not
            match the client ID.
        InvalidGrantError
            Raised if the code is not valid, the client is not allowed to use
            it, or the underlying authorization or session does not exist.
        InvalidRequestError
            Raised if the token redemption request is syntactically invalid.
        UnsupportedGrantTypeError
            Raised if the requested grant type isn't supported.
        """
        if not grant_type or not client_id or not code or not redirect_uri:
            raise InvalidRequestError("Invalid token request")
        if grant_type != "authorization_code":
            raise UnsupportedGrantTypeError(f"Invalid grant type {grant_type}")
        auth_code = OIDCAuthorizationCode.from_str(code)

        # Authorize the client.
        self._check_client_secret(client_id, client_secret)

        # Retrieve the metadata associated with the authorization code.
        try:
            authorization = await self._authorization_store.get(auth_code)
        except DeserializeError as e:
            msg = f"Cannot get authorization for {auth_code.key}: {e!s}"
            self._logger.exception(msg)
            if self._slack:
                await self._slack.post_exception(e)
            raise InvalidGrantError(msg) from e
        if not authorization:
            msg = f"Unknown authorization code {auth_code.key}"
            raise InvalidGrantError(msg)

        # Authorize the request.
        if authorization.client_id != client_id:
            msg = (
                f"Authorization client ID mismatch for {auth_code.key}:"
                f" {authorization.client_id} != {client_id}"
            )
            raise InvalidGrantError(msg)
        if authorization.redirect_uri != redirect_uri:
            msg = (
                f"Authorization redirect URI mismatch for {auth_code.key}:"
                f" {authorization.redirect_uri} != {redirect_uri}"
            )
            raise InvalidGrantError(msg)

        # Construct and return the token. The authorization code has now been
        # redeemed, so delete it so that it cannot be reused.
        token = await self.issue_id_token(authorization)
        await self._authorization_store.delete(auth_code)
        return token

    def verify_token(self, token: OIDCToken) -> OIDCVerifiedToken:
        """Verify a token issued by the internal OpenID Connect server.

        Any currently-registered client audience is accepted as a valid
        audience.

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
        audiences = (c.client_id for c in self._config.clients)
        try:
            payload = jwt.decode(
                token.encoded,
                self._config.keypair.public_key_as_pem().decode(),
                algorithms=[ALGORITHM],
                audience=audiences,
            )
            return OIDCVerifiedToken(
                encoded=token.encoded, claims=payload, jti=payload["jti"]
            )
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(str(e)) from e
        except KeyError as e:
            raise InvalidTokenError(f"Missing claim {e!s}") from e

    def _build_data_rights_for_user(
        self, user_info: TokenUserInfo
    ) -> str | None:
        """Construct the data rights string for the user.

        This is a space-separated list of data releases to which the user has
        access, based on the mapping rules from group names to data releases
        in the Gafaelfawr configuration. This claim is very Rubin-specific.

        Parameters
        ----------
        user_info
            Metadata for the user.

        Returns
        -------
        str or None
            Space-separated list of data release keywords or `None` if the
            user has no data rights.
        """
        if not user_info.groups:
            return None
        releases: set[str] = set()
        for group in user_info.groups:
            mapping = self._config.data_rights_mapping.get(group.name)
            if mapping:
                releases.update(mapping)
        return " ".join(sorted(releases))

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

    def _filter_claims(
        self,
        payload: dict[str, Any],
        authorization: OIDCAuthorization,
    ) -> dict[str, Any]:
        """Filter claims according to the request.

        Parameters
        ----------
        payload
            Full set of claims based on the user's metadata and token.
        authorization
            OpenID Connect authorization, which contains the client-requested
            scopes and claims. For now, only the ``id_token`` portion of the
            claims request is honored.

        Returns
        -------
        dict
            Filtered claims based on the requested scopes and claims.
        """
        wanted: set[str] = set()
        for scope in authorization.scopes:
            wanted.update(_SCOPE_CLAIMS.get(scope, set()))
        return {
            k: v for k, v in payload.items() if v is not None and k in wanted
        }
