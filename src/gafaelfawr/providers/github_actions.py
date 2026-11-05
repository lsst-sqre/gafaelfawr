"""Verification of GitHub Actions ID tokens.

GitHub runs an OpenID Connect identity provider for GitHub Actions that issues
short-lived ID tokens to workflow jobs. The GitHub Actions token exchange
accepts one of those ID tokens as its credential. This module verifies such a
token and extracts the claims used by the project registry.

This is not an authentication provider in the sense of
`~gafaelfawr.providers.base.Provider`, since no user logs in, but it plays the
same role as `~gafaelfawr.providers.oidc.OIDCTokenVerifier` does for the
OpenID Connect authentication provider.
"""

from typing import Any

import jwt
from httpx import AsyncClient, HTTPError
from jwt import PyJWK
from pydantic import ValidationError
from structlog.stdlib import BoundLogger

from ..cache import JWKSCache
from ..config import GitHubTokenExchangeConfig
from ..constants import (
    ALGORITHM,
    GITHUB_ACTIONS_ISSUER,
    GITHUB_ACTIONS_JWT_LEEWAY,
)
from ..exceptions import (
    FetchKeysError,
    GitHubWebError,
    InvalidTokenClaimsError,
    UnknownAlgorithmError,
    UnknownKeyIdError,
)
from ..models.github_actions import GitHubActionsClaims

__all__ = ["GitHubActionsTokenVerifier"]


class GitHubActionsTokenVerifier:
    """Verify an ID token issued by GitHub to a GitHub Actions job.

    Parameters
    ----------
    config
        GitHub Actions token exchange configuration.
    jwks_cache
        Process-wide cache of GitHub's signing keys.
    http_client
        Session to use to make HTTP requests.
    logger
        Logger for any log messages.
    """

    def __init__(
        self,
        config: GitHubTokenExchangeConfig,
        jwks_cache: JWKSCache,
        http_client: AsyncClient,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._jwks_cache = jwks_cache
        self._http_client = http_client
        self._logger = logger

    async def verify_token(self, encoded: str) -> GitHubActionsClaims:
        """Verify a GitHub Actions ID token and return its claims.

        The token must be signed with ``RS256`` by a key in GitHub's JWKS,
        have the GitHub Actions issuer, carry the configured audience, and be
        within its validity window (allowing a small clock skew for the
        ``exp``, ``nbf``, and ``iat`` claims). It must also contain every
        claim that the project registry matches on.

        Parameters
        ----------
        encoded
            Encoded ID token.

        Returns
        -------
        GitHubActionsClaims
            Claims from the verified token.

        Raises
        ------
        jwt.exceptions.InvalidTokenError
            Raised if the token is malformed, has the wrong issuer or
            audience, is outside its validity window, or has an invalid
            signature.
        FetchKeysError
            Raised if GitHub's key data is syntactically invalid.
        GitHubWebError
            Raised if unable to retrieve signing keys from GitHub.
        InvalidTokenClaimsError
            Raised if the token is missing a required claim or a claim has
            an invalid format.
        UnknownAlgorithmError
            Raised if the token or its signing key uses an algorithm other
            than ``RS256``.
        UnknownKeyIdError
            Raised if the token does not name a key ID or names one that is
            not in GitHub's key set, even after refreshing the keys.
        """
        unverified_header = jwt.get_unverified_header(encoded)
        algorithm = unverified_header.get("alg")
        if algorithm != ALGORITHM:
            msg = f"Token algorithm {algorithm} not {ALGORITHM}"
            raise UnknownAlgorithmError(msg)
        key_id = unverified_header.get("kid")
        if not key_id:
            raise UnknownKeyIdError("No kid in token header")

        key = await self._get_key(key_id)
        payload = jwt.decode(
            encoded,
            key,
            algorithms=[ALGORITHM],
            audience=self._config.audience,
            issuer=GITHUB_ACTIONS_ISSUER,
            leeway=GITHUB_ACTIONS_JWT_LEEWAY,
            options={"require": ["aud", "exp", "iss"]},
        )
        self._logger.debug("Verified GitHub Actions token", token_data=payload)

        try:
            return GitHubActionsClaims.model_validate(payload)
        except ValidationError as e:
            claims = ", ".join(
                ".".join(str(loc) for loc in error["loc"])
                for error in e.errors()
            )
            msg = f"Invalid or missing claims in token: {claims}"
            raise InvalidTokenClaimsError(msg) from e

    async def _get_key(self, key_id: str) -> PyJWK:
        """Get the signing key for a key ID.

        Uses the cached key set if the key is present. Otherwise, retrieves a
        fresh key set from GitHub, since GitHub rotates its signing keys, and
        fails if the key is still not present.

        Parameters
        ----------
        key_id
            Key ID from the token header.

        Returns
        -------
        jwt.PyJWK
            Signing key for that key ID.

        Raises
        ------
        FetchKeysError
            Raised if GitHub's key data is syntactically invalid.
        GitHubWebError
            Raised if unable to retrieve signing keys from GitHub.
        UnknownAlgorithmError
            Raised if the requested key ID was found but is for an
            unsupported algorithm.
        UnknownKeyIdError
            Raised if the requested key ID was not found in GitHub's key set.
        """
        key = self._find_key(self._jwks_cache.get(), key_id)
        if not key:
            async with self._jwks_cache.lock():
                # Another request may have refreshed the keys while this one
                # was waiting for the lock.
                key = self._find_key(self._jwks_cache.get(), key_id)
                if not key:
                    keys = await self._fetch_keys()
                    self._jwks_cache.store(keys)
                    key = self._find_key(keys, key_id)
        if not key:
            msg = f"GitHub Actions has no kid {key_id}"
            raise UnknownKeyIdError(msg)
        if key.get("alg", ALGORITHM) != ALGORITHM:
            msg = f"GitHub Actions kid {key_id} had algorithm {key['alg']}"
            raise UnknownAlgorithmError(msg)
        try:
            return PyJWK.from_dict(key, algorithm=ALGORITHM)
        except jwt.PyJWTError as e:
            msg = f"GitHub Actions kid {key_id} is not a valid key: {e!s}"
            raise FetchKeysError(msg) from e

    @staticmethod
    def _find_key(
        keys: list[dict[str, Any]] | None, key_id: str
    ) -> dict[str, Any] | None:
        """Find a key by key ID in a key set.

        Parameters
        ----------
        keys
            Key set in JWKS format, or `None` if there is no key set.
        key_id
            Key ID to find.

        Returns
        -------
        dict or None
            The matching key, or `None` if it is not in the key set.
        """
        if not keys:
            return None
        for key in keys:
            if key.get("kid") == key_id:
                return key
        return None

    async def _fetch_keys(self) -> list[dict[str, Any]]:
        """Retrieve GitHub's current signing keys.

        Reads the JWKS URI from GitHub's OpenID Connect configuration and
        then retrieves the key set from that URI.

        Returns
        -------
        list of dict
            Keys in JWKS format.

        Raises
        ------
        FetchKeysError
            Raised if the OpenID Connect configuration or the key set does
            not have the expected structure.
        GitHubWebError
            Raised if unable to retrieve signing keys from GitHub.
        """
        self._logger.debug("Fetching GitHub Actions signing keys")
        config_url = (
            GITHUB_ACTIONS_ISSUER + "/.well-known/openid-configuration"
        )
        try:
            r = await self._http_client.get(config_url)
            r.raise_for_status()
        except HTTPError as e:
            raise GitHubWebError.from_exception(e) from e
        try:
            jwks_url = r.json()["jwks_uri"]
        except Exception as e:
            msg = f"No jwks_uri property in OIDC metadata for {config_url}"
            raise FetchKeysError(msg) from e

        try:
            r = await self._http_client.get(jwks_url)
            r.raise_for_status()
        except HTTPError as e:
            raise GitHubWebError.from_exception(e) from e
        try:
            keys = r.json()["keys"]
        except Exception as e:
            msg = f"No keys property in JWKS metadata for {jwks_url}"
            raise FetchKeysError(msg) from e
        if not isinstance(keys, list):
            msg = f"Invalid keys property in JWKS metadata for {jwks_url}"
            raise FetchKeysError(msg)
        return keys
