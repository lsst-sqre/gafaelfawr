"""Verify a JWT."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urljoin

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import AsyncClient, RequestError
from jwt.exceptions import InvalidIssuerError
from structlog.stdlib import BoundLogger

from gafaelfawr.config import VerifierConfig
from gafaelfawr.constants import ALGORITHM
from gafaelfawr.exceptions import (
    FetchKeysException,
    InvalidTokenClaimsException,
    InvalidTokenError,
    MissingClaimsException,
    UnknownAlgorithmException,
    UnknownKeyIdException,
)
from gafaelfawr.models.oidc import OIDCToken, OIDCVerifiedToken
from gafaelfawr.util import base64_to_number

__all__ = ["TokenVerifier"]


class TokenVerifier:
    """Verifies the validity of a JWT.

    Used for verifying tokens issued by external issuers, such as during an
    OpenID Connect authentication.

    Parameters
    ----------
    config : `gafaelfawr.config.VerifierConfig`
        The JWT Authorizer configuration.
    http_client : ``httpx.AsyncClient``
        The client to use for making requests.
    logger : ``structlog.stdlib.BoundLogger``
        Logger to use to report status information.
    """

    def __init__(
        self,
        config: VerifierConfig,
        http_client: AsyncClient,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._http_client = http_client
        self._logger = logger

    def verify_internal_token(self, token: OIDCToken) -> OIDCVerifiedToken:
        """Verify a token issued by the internal issuer.

        Parameters
        ----------
        token : `gafaelfawr.models.oidc.OIDCToken`
            An encoded token.

        Returns
        -------
        verified_token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The verified token.

        Raises
        ------
        gafaelfawr.exceptions.InvalidTokenError
            The issuer of this token is unknown and therefore the token cannot
            be verified.
        gafaelfawr.exceptions.MissingClaimsException
            The token is missing required claims.
        """
        try:
            payload = jwt.decode(
                token.encoded,
                self._config.keypair.public_key_as_pem().decode(),
                algorithms=[ALGORITHM],
                audience=self._config.aud,
            )
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(str(e))
        return self._build_token(token.encoded, payload)

    async def verify_oidc_token(self, token: OIDCToken) -> OIDCVerifiedToken:
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
            The token is invalid or the issuer is unknown.
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
            raise InvalidIssuerError("No iss claim in token")
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

        if issuer_url != self._config.oidc_iss:
            raise InvalidIssuerError(f"Unknown issuer: {issuer_url}")
        if self._config.oidc_kids:
            if key_id not in self._config.oidc_kids:
                msg = f"kid {key_id} not allowed for {issuer_url}"
                raise UnknownKeyIdException(msg)

        key = await self._get_key_as_pem(issuer_url, key_id)
        payload = jwt.decode(
            token.encoded,
            key,
            algorithms=[ALGORITHM],
            audience=self._config.oidc_aud,
        )

        return self._build_token(token.encoded, payload)

    def _build_token(
        self, encoded: str, claims: Mapping[str, Any]
    ) -> OIDCVerifiedToken:
        """Build a VerifiedToken from an encoded token and its verified claims.

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
        if self._config.uid_claim not in claims:
            msg = f"No {self._config.uid_claim} claim in token"
            self._logger.warning(msg, claims=claims)
            raise MissingClaimsException(msg)
        try:
            uid = int(claims[self._config.uid_claim])
        except Exception:
            msg = f"Invalid {self._config.uid_claim} claim in token"
            self._logger.warning(msg, claims=claims)
            raise InvalidTokenClaimsException(msg)

        return OIDCVerifiedToken(
            encoded=encoded,
            claims=claims,
            jti=claims.get("jti", "UNKNOWN"),
            username=claims[self._config.username_claim],
            uid=uid,
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
