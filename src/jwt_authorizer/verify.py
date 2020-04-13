"""Verify a JWT."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urljoin

import jwt
from cachetools import TTLCache
from cachetools.keys import hashkey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from jwt_authorizer.config import ALGORITHM
from jwt_authorizer.util import base64_to_number

if TYPE_CHECKING:
    from aiohttp import ClientResponse, ClientSession, web
    from logging import Logger
    from jwt_authorizer.config import Config, Issuer
    from typing import Any, Dict, List, Optional

__all__ = [
    "KeyClient",
    "KeyClientException",
    "TokenVerifier",
    "UnknownAlgorithmException",
    "UnknownKeyIdException",
    "create_token_verifier",
]


class KeyClientException(Exception):
    """Cannot retrieve the keys from an issuer."""


class UnknownAlgorithmException(Exception):
    """The issuer key was for an unsupported algorithm."""


class UnknownKeyIdException(Exception):
    """The reqeusted key ID was not found for an issuer."""


class KeyClient:
    """Client to retrieve a key from an issuer.

    Handles retrieving the OpenID Connect metadata and the JWKS for an issuer
    and extracting the keys.  Intended to be overridden by the test suite to
    replace the get_url function.

    Parameters
    ----------
    session : `aiohttp.ClientSession`
        The session to use for making requests.
    """

    def __init__(self, session: ClientSession) -> None:
        self.session = session

    async def get_keys(self, issuer: Issuer) -> List[Dict[str, str]]:
        """Fetch the key set for an issuer.

        Parameters
        ----------
        url : `str`
            URL to fetch.

        Returns
        -------
        body : List[Dict[`str`, `str`]]
            List of keys (in JWKS format) for the given issuer.

        Raises
        ------
        KeyClientException
            On failure to retrieve a set of keys from the issuer.
        """
        url = await self._get_jwks_uri(issuer)
        if not url:
            url = urljoin(issuer.url, ".well-known/jwks.json")

        r = await self.get_url(url)
        if r.status != 200:
            msg = f"Cannot retrieve keys from {url}"
            raise KeyClientException(msg)

        body = await r.json()
        if "keys" not in body:
            msg = f"No keys property in JWKS metadata for {url}"
            raise KeyClientException(msg)

        return body["keys"]

    async def get_url(self, url: str) -> ClientResponse:
        """Retrieve a URL.

        Intended for overriding by a test class to avoid actual HTTP
        requests.

        Parameters
        ----------
        url : `str`
            URL to retrieve.

        Returns
        -------
        response : `aiohttp.ClientResponse`
            The response.
        """
        return await self.session.get(url)

    async def _get_jwks_uri(self, issuer: Issuer) -> Optional[str]:
        """Retrieve the JWKS URI for a given issuer.

        Ask for the OpenID Connect metadata and determine the JWKS URI from
        that.

        Parameters
        ----------
        issuer : `jwt_authorizer.config.Issuer`
            JWT issuer whose URI to retrieve.

        Returns
        -------
        url : `str`, optional
            URI for the JWKS of that issuer, or None if the OpenID Connect
            metadata is not present.

        Raises
        ------
        KeyClientException
            If the OpenID Connect metadata doesn't contain the expected
            parameter.
        """
        url = urljoin(issuer.url, ".well-known/openid-configuration")
        r = await self.get_url(url)
        if r.status != 200:
            return None

        body = await r.json()
        if "jwks_uri" not in body:
            msg = f"No jwks_uri property in OIDC metadata for {issuer.url}"
            raise KeyClientException(msg)

        return body["jwks_uri"]


class TokenVerifier:
    """Verifies the validity of a JWT.

    Parameters
    ----------
    issuers : Dict[`str`, `jwt_authorizer.config.Issuer`]
        Known token issuers and their metadata.
    client : `KeyClient`
        Class to use to retrieve issuer key sets.
    logger : `logging.Logger`
        Logger to use to report status information.
    """

    def __init__(
        self,
        issuers: Dict[str, Issuer],
        key_client: KeyClient,
        logger: Logger,
    ) -> None:
        self._issuers = issuers
        self._key_client = key_client
        self._logger = logger
        self._cache = TTLCache(maxsize=16, ttl=600)

    async def verify(self, token: str) -> Dict[str, Any]:
        """Verifies the provided JWT.

        Parameters
        ----------
        token : `str`
            JWT to verify.

        Returns
        -------
        verified_token: Dict[`str`, Any]
            The verified token contents.

        Raises
        ------
        jwt.exceptions.InvalidIssuerError
            The issuer of this token is unknown and therefore the token cannot
            be verified.
        Exception
            Some other verification failure.
        """
        unverified_header = jwt.get_unverified_header(token)
        unverified_token = jwt.decode(
            token, algorithms=ALGORITHM, verify=False
        )
        issuer_url = unverified_token["iss"]
        if issuer_url not in self._issuers:
            raise jwt.InvalidIssuerError(f"Unknown issuer: {issuer_url}")
        issuer = self._issuers[issuer_url]

        key = await self._get_key_as_pem(issuer, unverified_header["kid"])
        return jwt.decode(
            token, key, algorithms=ALGORITHM, audience=issuer.audience
        )

    async def _get_key_as_pem(self, issuer: Issuer, key_id: str) -> bytes:
        """Get the key for an issuer.

        Gets a key as PEM, given the issuer and the request key ticket_id.

        Parameters
        ----------
        issuer : `jwt_authorizer.config.Issuer`
            The metadata of the issuer.
        key_id : `str`
            The key ID to retrieve for the issuer in question.

        Returns
        -------
        key : `bytes`
            The issuer's key in PEM format.

        Raises
        ------
        KeyClientException
            Unable to retrieve the key set for the specified issuer.
        UnknownAlgorithException
            The requested key ID was found, but is for an unsupported
            algorithm.
        UnknownKeyIdException
            The requested key ID was not present in the issuer configuration
            or was not found in that issuer's JWKS.

        Notes
        -----
        This function will automatically cache the last 16 keys for up to 10
        minutes to cut down on network retrieval of the keys.
        """
        cache_key = hashkey(issuer, key_id)
        if cache_key in self._cache:
            return self._cache[cache_key]

        self._logger.info("Getting key %s from %s", key_id, issuer.url)
        if issuer.key_ids and key_id not in issuer.key_ids:
            msg = f"kid {key_id} not found in configuration for {issuer.url}"
            raise UnknownKeyIdException(msg)

        # Retrieve the JWKS information.
        keys = await self._key_client.get_keys(issuer)

        # Find the key that we want.
        for k in keys:
            if key_id == k["kid"]:
                key = k
        if not key:
            msg = f"Issuer {issuer.url} has no kid {key_id}"
            raise UnknownKeyIdException(msg)
        if key["alg"] != ALGORITHM:
            msg = (
                f"Issuer {issuer.url} kid {key_id} had algorithm"
                f" {key['alg']} not {ALGORITHM}"
            )
            raise UnknownAlgorithmException(msg)

        # Convert, cache, and return the key.
        e = base64_to_number(key["e"])
        m = base64_to_number(key["n"])
        public_key = self._build_public_key(e, m)
        self._cache[cache_key] = public_key
        return public_key

    @staticmethod
    def _build_public_key(exponent: int, modulus: int) -> bytes:
        """Convert an exponent and modulus to a PEM-encoded key."""
        components = rsa.RSAPublicNumbers(exponent, modulus)
        public_key = components.public_key(backend=default_backend())
        return public_key.public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo,
        )


def create_token_verifier(request: web.Request) -> TokenVerifier:
    """Create a TokenVerifier from an app configuration.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    token_verifier : `TokenVerifier`
        A TokenVerifier created from that Flask application configuration.
    """
    logger: Logger = request["safir/logger"]
    config: Config = request.config_dict["jwt_authorizer/config"]

    if "jwt_authorizer/key_client" in request.config_dict:
        key_client = request.config_dict["jwt_authorizer/key_client"]
    else:
        http_session = request["safir/http_session"]
        key_client = KeyClient(http_session)

    return TokenVerifier(config.issuers, key_client, logger)
