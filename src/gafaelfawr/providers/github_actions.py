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

from datetime import UTC, datetime

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
from ..models.github_actions import (
    GitHubActionsClaims,
    GitHubActionsJWKS,
    GitHubActionsOIDCMetadata,
)

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
        within its validity window. A small clock skew is allowed for the
        ``nbf`` and ``iat`` claims, since rejecting a freshly issued token
        would break every workflow if GitHub's clock is ahead, but ``exp`` is
        checked strictly, since GitHub issues short-lived tokens precisely so
        that a leaked token is quickly worthless and leeway there would only
        widen the window in which one could be replayed. It must also contain
        every claim that the project registry matches on.

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
            Raised if GitHub's key data is syntactically invalid or contains
            no usable keys.
        GitHubWebError
            Raised if unable to retrieve signing keys from GitHub.
        InvalidTokenClaimsError
            Raised if the token is missing a required claim or a claim has
            an invalid format.
        UnknownAlgorithmError
            Raised if the token uses an algorithm other than ``RS256``.
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
            options={"require": ["aud", "exp", "iss"], "verify_exp": False},
        )

        # PyJWT applies the same leeway to exp as to nbf and iat, so check
        # exp separately without leeway, parsing the claim the same way PyJWT
        # does. int rather than float matters: JSON parsing accepts NaN and
        # Infinity, which float would pass through and which never compare
        # as expired. The claim is guaranteed to be present by the require
        # option above.
        now = datetime.now(tz=UTC).timestamp()
        try:
            expires = int(payload["exp"])
        except (TypeError, ValueError, OverflowError) as e:
            msg = f"Invalid exp claim in token: {payload['exp']}"
            raise jwt.DecodeError(msg) from e
        if now >= expires:
            raise jwt.ExpiredSignatureError("Signature has expired")
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
        fails if the key is still not present. Since anyone can send a token
        naming an unknown key ID, the key set is not retrieved again if it
        was retrieved within the minimum refresh interval.

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
            Raised if GitHub's key data is syntactically invalid or contains
            no usable keys.
        GitHubWebError
            Raised if unable to retrieve signing keys from GitHub.
        UnknownKeyIdError
            Raised if the requested key ID was not found in GitHub's key set.
        """
        keys = self._jwks_cache.get()
        if keys is not None and key_id in keys:
            return keys[key_id]
        async with self._jwks_cache.lock():
            # Another request may have refreshed the keys while this one
            # was waiting for the lock.
            keys = self._jwks_cache.get()
            if keys is not None and key_id in keys:
                return keys[key_id]
            if keys is not None and self._jwks_cache.recently_refreshed():
                self._logger.warning(
                    "Not refreshing recently retrieved GitHub Actions keys",
                    kid=key_id,
                )
                msg = f"GitHub Actions has no kid {key_id}"
                raise UnknownKeyIdError(msg)
            jwks_uri = self._jwks_cache.get_jwks_uri()
            if not jwks_uri:
                jwks_uri = await self._get_jwks_uri()
            keys = await self._fetch_keys(jwks_uri)
            self._jwks_cache.store(jwks_uri, keys)
        if key_id not in keys:
            msg = f"GitHub Actions has no kid {key_id}"
            raise UnknownKeyIdError(msg)
        return keys[key_id]

    async def _get_jwks_uri(self) -> str:
        """Retrieve the JWKS URI from GitHub's OpenID Connect metadata.

        Returns
        -------
        str
            URL of GitHub's JSON Web Key Set.

        Raises
        ------
        FetchKeysError
            Raised if the OpenID Connect metadata does not have the expected
            structure or the JWKS URI is not an HTTPS URL.
        GitHubWebError
            Raised if unable to retrieve the metadata from GitHub.
        """
        self._logger.debug("Fetching GitHub Actions OpenID Connect metadata")
        config_url = (
            GITHUB_ACTIONS_ISSUER + "/.well-known/openid-configuration"
        )
        try:
            r = await self._http_client.get(config_url)
            r.raise_for_status()
        except HTTPError as e:
            raise GitHubWebError.from_exception(e) from e
        try:
            metadata = GitHubActionsOIDCMetadata.model_validate(r.json())
        except (ValidationError, ValueError) as e:
            msg = f"Invalid OIDC metadata from {config_url}"
            raise FetchKeysError(msg) from e
        return str(metadata.jwks_uri)

    async def _fetch_keys(self, jwks_uri: str) -> dict[str, PyJWK]:
        """Retrieve and parse GitHub's current signing keys.

        Keys that are missing a key ID, use an algorithm other than
        ``RS256``, or cannot be parsed are skipped with a warning rather than
        failing the whole key set, so that one such key in GitHub's set does
        not prevent verifying tokens signed with the others.

        Parameters
        ----------
        jwks_uri
            URL of GitHub's JSON Web Key Set.

        Returns
        -------
        dict of jwt.PyJWK
            Usable signing keys, indexed by key ID.

        Raises
        ------
        FetchKeysError
            Raised if the key set does not have the expected structure or
            contains no usable keys.
        GitHubWebError
            Raised if unable to retrieve signing keys from GitHub.
        """
        self._logger.debug("Fetching GitHub Actions signing keys")
        try:
            r = await self._http_client.get(jwks_uri)
            r.raise_for_status()
        except HTTPError as e:
            raise GitHubWebError.from_exception(e) from e
        try:
            jwks = GitHubActionsJWKS.model_validate(r.json())
        except (ValidationError, ValueError) as e:
            msg = f"Invalid JWKS from {jwks_uri}"
            raise FetchKeysError(msg) from e

        keys: dict[str, PyJWK] = {}
        for key in jwks.keys:
            key_id = key.get("kid")
            if not key_id or not isinstance(key_id, str):
                self._logger.warning("Ignoring GitHub Actions key without kid")
                continue
            algorithm = key.get("alg", ALGORITHM)
            if algorithm != ALGORITHM:
                self._logger.warning(
                    "Ignoring GitHub Actions key with unsupported algorithm",
                    kid=key_id,
                    alg=algorithm,
                )
                continue
            try:
                keys[key_id] = PyJWK.from_dict(key, algorithm=ALGORITHM)
            except jwt.PyJWTError as e:
                self._logger.warning(
                    "Ignoring invalid GitHub Actions key",
                    kid=key_id,
                    error=str(e),
                )
        if not keys:
            msg = f"No usable {ALGORITHM} keys in JWKS from {jwks_uri}"
            raise FetchKeysError(msg)
        return keys
