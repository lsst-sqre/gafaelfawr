"""OpenID Connect authentication provider."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlencode, urljoin

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import AsyncClient, RequestError
from pydantic import ValidationError
from structlog.stdlib import BoundLogger

from ..config import OIDCConfig
from ..constants import ALGORITHM
from ..exceptions import (
    FetchKeysException,
    InvalidTokenClaimsException,
    MissingClaimsException,
    OIDCException,
    UnknownAlgorithmException,
    UnknownKeyIdException,
    VerifyTokenException,
)
from ..models.oidc import OIDCToken, OIDCVerifiedToken
from ..models.state import State
from ..models.token import TokenGroup, TokenUserInfo
from ..storage.ldap import LDAPStorage
from ..util import base64_to_number
from .base import Provider

__all__ = ["OIDCProvider", "OIDCTokenVerifier"]


class OIDCProvider(Provider):
    """Authenticate a user with GitHub.

    Parameters
    ----------
    config : `gafaelfawr.config.OIDCConfig`
        OpenID Connect authentication provider configuration.
    verifier : `OIDCTokenVerifier`
        JWT token verifier for OpenID Connect tokens.
    ldap_storage : `gafaelfawr.storage.ldap.LDAPStorage`
        LDAP storage layer for retrieving user metadata.
    http_client : ``httpx.AsyncClient``
        Session to use to make HTTP requests.
    logger : `structlog.stdlib.BoundLogger`
        Logger for any log messages.
    """

    def __init__(
        self,
        *,
        config: OIDCConfig,
        verifier: OIDCTokenVerifier,
        ldap_storage: Optional[LDAPStorage],
        http_client: AsyncClient,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._verifier = verifier
        self._ldap_storage = ldap_storage
        self._http_client = http_client
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
            "Redirecting user to %s for authentication",
            self._config.login_url,
        )
        return f"{self._config.login_url}?{urlencode(params)}"

    async def create_user_info(
        self, code: str, state: str, session: State
    ) -> TokenUserInfo:
        """Given the code from a successful authentication, get a token.

        Parameters
        ----------
        code : `str`
            Code returned by a successful authentication.
        state : `str`
            The same random string used for the redirect URL, not used.
        session : `gafaelfawr.models.state.State`
            The session state, not used by this provider.

        Returns
        -------
        user_info : `gafaelfawr.models.token.TokenUserInfo`
            The user information corresponding to that authentication.

        Raises
        ------
        gafaelfawr.exceptions.OIDCException
            The OpenID Connect provider responded with an error to a request
            or the group membership in the resulting token was not valid.
        gafaelfawr.exceptions.LDAPException
            Gafaelfawr was configured to get user groups or numeric UID from
            LDAP, but the attempt failed due to some error.
        ``httpx.HTTPError``
            An HTTP client error occurred trying to talk to the authentication
            provider.
        jwt.exceptions.InvalidTokenError
            The token returned by the OpenID Connect provider was invalid.
        """
        token_url = self._config.token_url
        data = {
            "grant_type": "authorization_code",
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "code": code,
            "redirect_uri": self._config.redirect_url,
        }
        self._logger.info("Retrieving ID token from %s", token_url)
        r = await self._http_client.post(
            token_url,
            data=data,
            headers={"Accept": "application/json"},
        )

        # If the call failed, try to extract an error from the reply.  If that
        # fails, just raise an exception for the HTTP status.
        try:
            result = r.json()
        except Exception:
            if r.status_code != 200:
                r.raise_for_status()
            else:
                msg = "Response from {token_url} not valid JSON"
                raise OIDCException(msg)
        if r.status_code != 200 and "error" in result:
            msg = result["error"] + ": " + result["error_description"]
            raise OIDCException(msg)
        elif r.status_code != 200:
            r.raise_for_status()
        if "id_token" not in result:
            msg = f"No id_token in token reply from {token_url}"
            raise OIDCException(msg)

        # Extract and verify the token and determine the user's UID and
        # groups.  These may come from the token or from LDAP, depending on
        # configuration.
        unverified_token = OIDCToken(encoded=result["id_token"])
        try:
            token = await self._verifier.verify_token(unverified_token)
            uid = None
            if self._ldap_storage:
                async with self._ldap_storage.connect() as conn:
                    uid = await conn.get_uid(token.username)
                    groups = await conn.get_groups(token.username)
            else:
                groups = self._verifier.get_groups_from_token(token)
            if not uid:
                uid = self._verifier.get_uid_from_token(token)
        except (jwt.InvalidTokenError, VerifyTokenException) as e:
            msg = f"OpenID Connect token verification failed: {str(e)}"
            raise OIDCException(msg)

        # Return the relevant information extracted from the token.
        return TokenUserInfo(
            username=token.username,
            name=token.claims.get("name"),
            email=token.claims.get("email"),
            uid=uid,
            groups=groups,
        )

    async def logout(self, session: State) -> None:
        """User logout callback.

        Currently, this does nothing.

        Parameters
        ----------
        session : `gafaelfawr.models.state.State`
            The session state, which contains the GitHub access token.
        """
        pass


class OIDCTokenVerifier:
    """Verify a JWT issued by an OpenID Connect provider.

    Parameters
    ----------
    config : `gafaelfawr.config.OIDCConfig`
        OpenID Connect authentication provider configuration.
    http_client : ``httpx.AsyncClient``
        Session to use to make HTTP requests.
    logger : `structlog.stdlib.BoundLogger`
        Logger for any log messages.
    """

    def __init__(
        self, config: OIDCConfig, http_client: AsyncClient, logger: BoundLogger
    ) -> None:
        self._config = config
        self._http_client = http_client
        self._logger = logger

    async def verify_token(self, token: OIDCToken) -> OIDCVerifiedToken:
        """Verifies the provided JWT from an OpenID Connect provider.

        Parameters
        ----------
        token : `gafaelfawr.models.oidc.OIDCToken`
            JWT to verify.

        Returns
        -------
        verified_token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The verified token contents.

        Raises
        ------
        jwt.exceptions.InvalidTokenError
            The token is invalid.
        gafaelfawr.exceptions.VerifyTokenException
            The token failed to verify or was invalid in some way.
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
            raise UnknownKeyIdException("No kid in token header")
        key_id = unverified_header["kid"]

        if "jti" in unverified_token:
            self._logger.debug(
                "Verifying token %s from issuer %s",
                unverified_token["jti"],
                issuer_url,
            )
        else:
            self._logger.debug("Verifying token from issuer %s", issuer_url)

        if issuer_url != self._config.issuer:
            raise jwt.InvalidIssuerError(f"Unknown issuer: {issuer_url}")

        key = await self._get_key_as_pem(issuer_url, key_id)
        payload = jwt.decode(
            token.encoded,
            key,
            algorithms=[ALGORITHM],
            audience=self._config.audience,
        )

        if self._config.username_claim not in payload:
            msg = f"No {self._config.username_claim} claim in token"
            self._logger.warning(msg, claims=payload)
            raise MissingClaimsException(msg)

        return OIDCVerifiedToken(
            encoded=token.encoded,
            claims=payload,
            jti=payload.get("jti", "UNKNOWN"),
            username=payload[self._config.username_claim],
        )

    def get_uid_from_token(self, token: OIDCVerifiedToken) -> int:
        """Verify and return the numeric UID from the token.

        This is separate from `verify_token` because we don't want to try to
        parse the token claims for a numeric UID if Gafaelfawr was configured
        to get the numeric UID from LDAP instead.  The caller of
        `verify_token` should call this method afterwards if the numeric UID
        from a JWT claim is required.

        Parameters
        ----------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The previously verified token.

        Returns
        -------
        uid : `int`
            The numeric UID of the user as obtained from the token.

        Raises
        ------
        gafaelfawr.exceptions.MissingClaimsException
            The token is missing the required numeric UID claim.
        gafaelfawr.exceptions.InvalidTokenClaimsException
            The numeric UID claim contains something that is not a number.
        """
        if self._config.uid_claim not in token.claims:
            msg = f"No {self._config.uid_claim} claim in token"
            self._logger.warning(msg, claims=token.claims)
            raise MissingClaimsException(msg)
        try:
            uid = int(token.claims[self._config.uid_claim])
        except Exception:
            msg = f"Invalid {self._config.uid_claim} claim in token"
            self._logger.warning(msg, claims=token.claims)
            raise InvalidTokenClaimsException(msg)
        return uid

    def get_groups_from_token(
        self,
        token: OIDCVerifiedToken,
    ) -> List[TokenGroup]:
        """Determine the user's groups from token claims.

        Invalid groups are logged and ignored.

        Parameters
        ----------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The previously verified token.

        Returns
        -------
        groups : List[`gafaelfawr.models.token.TokenGroup`]
            List of groups derived from the ``isMemberOf`` token claim.

        Raises
        ------
        gafaelfawr.exceptions.InvalidTokenClaimsException
            The ``isMemberOf`` claim has an invalid syntax.
        """
        groups = []
        invalid_groups = {}
        try:
            for oidc_group in token.claims.get("isMemberOf", []):
                if "name" not in oidc_group:
                    continue
                name = oidc_group["name"]
                if "id" not in oidc_group:
                    invalid_groups[name] = "missing id"
                    continue
                try:
                    gid = int(oidc_group["id"])
                    groups.append(TokenGroup(name=name, id=gid))
                except (TypeError, ValueError, ValidationError) as e:
                    invalid_groups[name] = str(e)
        except TypeError as e:
            msg = f"isMemberOf claim has invalid format: {str(e)}"
            self._logger.error(
                "Unable to get groups from token",
                error=msg,
                claim=token.claims.get("isMemberOf", []),
                user=token.username,
            )
            raise InvalidTokenClaimsException(msg)

        if invalid_groups:
            self._logger.warning(
                "Ignoring invalid groups in OIDC token",
                error="isMemberOf claim value could not be parsed",
                invalid_groups=invalid_groups,
            )

        return groups

    def _build_token(
        self, encoded: str, claims: Mapping[str, Any]
    ) -> OIDCVerifiedToken:
        """Build a VerifiedToken from an encoded token and its verified claims.

        The resulting token will always have a ``uid`` attribute of `None`.
        If the user's numeric UID should come from a JWT claim, the caller
        should call `verify_oidc_token_uid`.

        Parameters
        ----------
        encoded : str
            The encoded form of the token.
        claims : Mapping[`str`, Any]
            The claims of a verified token.

        Returns
        -------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The resulting token.

        Raises
        ------
        gafaelfawr.exceptions.MissingClaimsException
            The token is missing required claims.
        """
        if self._config.username_claim not in claims:
            msg = f"No {self._config.username_claim} claim in token"
            self._logger.warning(msg, claims=claims)
            raise MissingClaimsException(msg)

        return OIDCVerifiedToken(
            encoded=encoded,
            claims=claims,
            jti=claims.get("jti", "UNKNOWN"),
            username=claims[self._config.username_claim],
        )

    async def _get_key_as_pem(self, issuer_url: str, key_id: str) -> str:
        """Get the key for an issuer.

        Gets a key as PEM, given the issuer and the request key ID.

        Parameters
        ----------
        issuer_url : `str`
            The URL of the issuer.
        key_id : `str`
            The key ID to retrieve for the issuer in question.

        Returns
        -------
        key : `bytes`
            The issuer's key in PEM format.

        Raises
        ------
        gafaelfawr.exceptions.FetchKeysException
            Unable to retrieve the key set for the specified issuer.
        gafaelfawr.exceptions.UnknownAlgorithException
            The requested key ID was found, but is for an unsupported
            algorithm.
        gafaelfawr.exceptions.UnknownKeyIdException
            The requested key ID was not present in the issuer configuration
            or was not found in that issuer's JWKS.
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
            raise UnknownKeyIdException(msg)
        if key["alg"] != ALGORITHM:
            msg = (
                f"Issuer {issuer_url} kid {key_id} had algorithm"
                f" {key['alg']} not {ALGORITHM}"
            )
            raise UnknownAlgorithmException(msg)

        # Convert and return the key.
        e = base64_to_number(key["e"])
        m = base64_to_number(key["n"])
        public_key = self._build_public_key(e, m)
        return public_key

    @staticmethod
    def _build_public_key(exponent: int, modulus: int) -> str:
        """Convert an exponent and modulus to a PEM-encoded key."""
        components = rsa.RSAPublicNumbers(exponent, modulus)
        public_key = components.public_key(backend=default_backend())
        return public_key.public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        ).decode()

    async def _get_keys(self, issuer_url: str) -> List[Dict[str, str]]:
        """Fetch the key set for an issuer.

        Parameters
        ----------
        issuer_url : `str`
            URL of the issuer.

        Returns
        -------
        body : List[Dict[`str`, `str`]]
            List of keys (in JWKS format) for the given issuer.

        Raises
        ------
        gafaelfawr.exceptions.FetchKeysException
            On failure to retrieve a set of keys from the issuer.
        """
        url = await self._get_jwks_uri(issuer_url)
        if not url:
            url = urljoin(issuer_url, ".well-known/jwks.json")

        try:
            r = await self._http_client.get(url)
            if r.status_code != 200:
                reason = f"{r.status_code} {r.reason_phrase}"
                msg = f"Cannot retrieve keys from {url}: {reason}"
                raise FetchKeysException(msg)
        except RequestError:
            raise FetchKeysException(f"Cannot retrieve keys from {url}")

        try:
            body = r.json()
            return body["keys"]
        except Exception:
            msg = f"No keys property in JWKS metadata for {url}"
            raise FetchKeysException(msg)

    async def _get_jwks_uri(self, issuer_url: str) -> Optional[str]:
        """Retrieve the JWKS URI for a given issuer.

        Ask for the OpenID Connect metadata and determine the JWKS URI from
        that.

        Parameters
        ----------
        issuer_url : `str`
            URL of the issuer.

        Returns
        -------
        url : `str` or `None`
            URI for the JWKS of that issuer, or None if the OpenID Connect
            metadata is not present.

        Raises
        ------
        gafaelfawr.exceptions.FetchKeysException
            If the OpenID Connect metadata doesn't contain the expected
            parameter.
        """
        url = urljoin(issuer_url, ".well-known/openid-configuration")
        try:
            r = await self._http_client.get(url)
            if r.status_code != 200:
                return None
        except RequestError:
            return None

        try:
            body = r.json()
            return body["jwks_uri"]
        except Exception:
            msg = f"No jwks_uri property in OIDC metadata for {issuer_url}"
            raise FetchKeysException(msg)
