"""OpenID Connect authentication provider."""

from __future__ import annotations

from urllib.parse import urlencode

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import AsyncClient, HTTPError, HTTPStatusError
from structlog.stdlib import BoundLogger

from ..config import OIDCConfig
from ..constants import ALGORITHM
from ..exceptions import (
    FetchKeysError,
    MissingUsernameClaimError,
    OIDCError,
    OIDCNotEnrolledError,
    OIDCWebError,
    UnknownAlgorithmError,
    UnknownKeyIdError,
    VerifyTokenError,
)
from ..models.oidc import OIDCToken, OIDCVerifiedToken
from ..models.state import State
from ..models.token import TokenUserInfo
from ..services.userinfo import OIDCUserInfoService
from ..util import base64_to_number
from .base import Provider

__all__ = ["OIDCProvider", "OIDCTokenVerifier"]


class OIDCProvider(Provider):
    """Authenticate a user with GitHub.

    Parameters
    ----------
    config
        OpenID Connect authentication provider configuration.
    verifier
        JWT token verifier for OpenID Connect tokens.
    user_info_service
        Service for retrieving user metadata like UID.
    http_client
        Session to use to make HTTP requests.
    logger
        Logger for any log messages.
    """

    def __init__(
        self,
        *,
        config: OIDCConfig,
        verifier: OIDCTokenVerifier,
        user_info_service: OIDCUserInfoService,
        http_client: AsyncClient,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._verifier = verifier
        self._user_info = user_info_service
        self._http_client = http_client
        self._logger = logger

    def get_redirect_url(self, state: str) -> str:
        """Get the login URL to which to redirect the user.

        Parameters
        ----------
        state
            A random string used for CSRF protection.

        Returns
        -------
        str
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
            "Redirecting user for authentication",
            login_url=self._config.login_url,
        )
        return f"{self._config.login_url}?{urlencode(params)}"

    async def create_user_info(
        self, code: str, state: str, session: State
    ) -> TokenUserInfo:
        """Given the code from a successful authentication, get a token.

        Parameters
        ----------
        code
            Code returned by a successful authentication.
        state
            The same random string used for the redirect URL, not used.
        session
            The session state, not used by this provider.

        Returns
        -------
        TokenUserInfo
            The user information corresponding to that authentication.

        Raises
        ------
        FirestoreError
            Raised if retrieving or assigning a UID from Firestore failed.
        LDAPError
            Raised if Gafaelfawr was configured to get user groups, username,
            or numeric UID from LDAP, but the attempt failed due to some
            error.
        OIDCError
            Raised if the OpenID Connect provider responded with an error to a
            request or the group membership in the resulting token was not
            valid.
        OIDCWebError
            An HTTP client error occurred trying to talk to the authentication
            provider.
        """
        token_url = self._config.token_url
        logger = self._logger.bind(token_url=token_url)
        data = {
            "grant_type": "authorization_code",
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "code": code,
            "redirect_uri": self._config.redirect_url,
        }
        logger.info("Retrieving ID token")

        # If the call failed, try to extract an error from the reply.  If that
        # fails, just raise an exception for the HTTP status.
        result = None
        try:
            r = await self._http_client.post(
                token_url,
                data=data,
                headers={"Accept": "application/json"},
            )
            result = r.json()
            r.raise_for_status()
        except HTTPError as e:
            if result and "error" in result:
                description = result.get("error_description")
                if description:
                    msg = result["error"] + ": " + description
                else:
                    msg = result["error"]
                raise OIDCError(f"Error retrieving ID token: {msg}") from None
            raise OIDCWebError.from_exception(e) from e
        except Exception as e:
            msg = f"Response from {token_url} not valid JSON"
            logger.exception(msg, response=r.text)
            raise OIDCError(msg) from e
        if "id_token" not in result:
            msg = f"No id_token in token reply from {token_url}"
            raise OIDCError(msg)

        # Extract and verify the token and determine the user's username,
        # numeric UID, and groups.  These may come from the token or from
        # LDAP, depending on configuration.
        unverified_token = OIDCToken(encoded=result["id_token"])
        try:
            token = await self._verifier.verify_token(unverified_token)
            return await self._user_info.get_user_info_from_oidc_token(token)
        except MissingUsernameClaimError as e:
            raise OIDCNotEnrolledError(str(e)) from e
        except (jwt.InvalidTokenError, VerifyTokenError) as e:
            logger.exception("Error verifying ID token", msg=str(e))
            msg = f"OpenID Connect token verification failed: {e!s}"
            raise OIDCError(msg) from e

    async def logout(self, session: State) -> None:
        """User logout callback.

        Currently, this does nothing.

        Parameters
        ----------
        session
            The session state, which contains the GitHub access token.
        """


class OIDCTokenVerifier:
    """Verify a JWT issued by an OpenID Connect provider.

    Parameters
    ----------
    config
        OpenID Connect authentication provider configuration.
    http_client
        Session to use to make HTTP requests.
    logger
        Logger for any log messages.
    """

    def __init__(
        self, config: OIDCConfig, http_client: AsyncClient, logger: BoundLogger
    ) -> None:
        self._config = config
        self._http_client = http_client
        self._logger = logger

    async def verify_token(self, token: OIDCToken) -> OIDCVerifiedToken:
        """Verify the provided JWT from an OpenID Connect provider.

        Parameters
        ----------
        token
            JWT to verify.

        Returns
        -------
        OIDCVerifiedToken
            The verified token contents.

        Raises
        ------
        jwt.exceptions.InvalidTokenError
            Raised if the token is invalid.
        OIDCWebError
            Raised if unable to retrieve signing keys from the provider.
        VerifyTokenError
            Raised if the token failed to verify or was invalid in some way.
        """
        unverified_header = jwt.get_unverified_header(token.encoded)
        unverified_token = jwt.decode(
            token.encoded,
            algorithms=[ALGORITHM],
            options={"verify_signature": False},
        )
        if "iss" not in unverified_token:
            raise jwt.InvalidIssuerError("No iss claim in token")
        issuer_url = unverified_token["iss"]
        if "kid" not in unverified_header:
            raise UnknownKeyIdError("No kid in token header")
        key_id = unverified_header["kid"]

        self._logger.debug("Verifying OIDC token", token_data=unverified_token)
        if issuer_url != self._config.issuer:
            raise jwt.InvalidIssuerError(f"Unknown issuer: {issuer_url}")

        key = await self._get_key_as_pem(issuer_url, key_id)
        payload = jwt.decode(
            token.encoded,
            key,
            algorithms=[ALGORITHM],
            audience=self._config.audience,
        )

        return OIDCVerifiedToken(
            encoded=token.encoded,
            claims=payload,
            jti=payload.get("jti", "UNKNOWN"),
        )

    async def _get_key_as_pem(self, issuer_url: str, key_id: str) -> str:
        """Get the key for an issuer.

        Gets a key as PEM, given the issuer and the request key ID.

        Parameters
        ----------
        issuer_url
            The URL of the issuer.
        key_id
            The key ID to retrieve for the issuer in question.

        Returns
        -------
        bytes
            The issuer's key in PEM format.

        Raises
        ------
        FetchKeysError
            Raised if provider key data doesn't contain the needed key or
            is syntactically invalid.
        OIDCWebError
            Raised if unable to retrieve signing keys from the provider.
        UnknownAlgorithError
            Raised if the requested key ID was found, but is for an
            unsupported algorithm.
        UnknownKeyIdError
            Raised if the requested key ID was not present in the issuer
            configuration or was not found in that issuer's JWKS.
        """
        self._logger.debug("Getting key %s from %s", key_id, issuer_url)

        # Retrieve the JWKS information.
        keys = await self._get_keys(issuer_url)

        # Find the key that we want.
        key = None
        for k in keys:
            if key_id == k["kid"]:
                key = k
        if not key:
            msg = f"Issuer {issuer_url} has no kid {key_id}"
            raise UnknownKeyIdError(msg)
        if key["alg"] != ALGORITHM:
            msg = (
                f"Issuer {issuer_url} kid {key_id} had algorithm"
                f" {key['alg']} not {ALGORITHM}"
            )
            raise UnknownAlgorithmError(msg)

        # Convert and return the key.
        e = base64_to_number(key["e"])
        m = base64_to_number(key["n"])
        return self._build_public_key(e, m)

    @staticmethod
    def _build_public_key(exponent: int, modulus: int) -> str:
        """Convert an exponent and modulus to a PEM-encoded key."""
        components = rsa.RSAPublicNumbers(exponent, modulus)
        public_key = components.public_key(backend=default_backend())
        return public_key.public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        ).decode()

    async def _get_keys(self, issuer_url: str) -> list[dict[str, str]]:
        """Fetch the key set for an issuer.

        Parameters
        ----------
        issuer_url
            URL of the issuer.

        Returns
        -------
        list of dict
            List of keys (in JWKS format) for the given issuer.

        Raises
        ------
        FetchKeysError
            Raised if unable to parse the key data or find the needed key.
        OIDCWebError
            Raised if unable to retrieve signing keys from the provider.
        """
        url = await self._get_jwks_uri(issuer_url)
        if not url:
            url = issuer_url.rstrip("/") + "/.well-known/jwks.json"

        try:
            r = await self._http_client.get(url)
            r.raise_for_status()
        except HTTPError as e:
            raise OIDCWebError.from_exception(e) from e

        try:
            body = r.json()
            return body["keys"]
        except Exception as e:
            msg = f"No keys property in JWKS metadata for {url}"
            raise FetchKeysError(msg) from e

    async def _get_jwks_uri(self, issuer_url: str) -> str | None:
        """Retrieve the JWKS URI for a given issuer.

        Ask for the OpenID Connect metadata and determine the JWKS URI from
        that.

        Parameters
        ----------
        issuer_url
            URL of the issuer.

        Returns
        -------
        str or None
            URI for the JWKS of that issuer, or `None` if the OpenID Connect
            metadata is not present.

        Raises
        ------
        FetchKeysError
            Raised if the OpenID Connect metadata doesn't contain the expected
            parameter.
        OIDCWebError
            Raised if unable to retrieve signing keys from the provider.
        """
        url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
        try:
            r = await self._http_client.get(url)
            r.raise_for_status()
        except HTTPStatusError as e:
            if r.status_code == 404:
                return None
            raise OIDCWebError.from_exception(e) from e
        except HTTPError as e:
            raise OIDCWebError.from_exception(e) from e

        try:
            body = r.json()
            return body["jwks_uri"]
        except Exception as e:
            msg = f"No jwks_uri property in OIDC metadata for {issuer_url}"
            raise FetchKeysError(msg) from e
