"""Verification and exchange of GitHub Actions ID tokens.

GitHub runs an OpenID Connect identity provider for GitHub Actions that issues
short-lived ID tokens to workflow jobs. The GitHub Actions token exchange
accepts one of those ID tokens as its credential, verifies it, and exchanges
it for a Gafaelfawr token for the GitHub project that the ID token matches.
"""

from typing import Any

import jwt
from httpx import AsyncClient, HTTPError
from jwt import PyJWK
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
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
    InvalidSubjectTokenError,
    InvalidTokenClaimsError,
    UnauthorizedScopeError,
    UnknownAlgorithmError,
    UnknownKeyIdError,
)
from ..models.github_actions import (
    GitHubActionsClaims,
    GitHubActionsJWKS,
    GitHubActionsOIDCMetadata,
    GitHubTokenExchangeResult,
)
from ..models.github_project import GitHubProject
from ..storage.github_project import GitHubProjectStore
from .token import TokenService

__all__ = ["GitHubActionsTokenVerifier", "GitHubTokenExchangeService"]


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
        within its validity window. A small clock skew is allowed when
        checking the ``exp``, ``nbf``, and ``iat`` claims. It must also
        contain every claim that the project registry matches on.

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


class GitHubTokenExchangeService:
    """Exchange GitHub Actions ID tokens for Gafaelfawr tokens.

    The exchange is the one route of the GitHub Actions token exchange that a
    workflow calls. It verifies the ID token that GitHub issued to the
    workflow job, finds the enabled GitHub project whose constraints the
    token satisfies, and mints a token of type ``github`` for that project's
    bot user with the scopes and lifetime the project allows.

    Parameters
    ----------
    config
        Configuration for the GitHub Actions token exchange.
    verifier
        Verifier for GitHub Actions ID tokens.
    project_store
        Backing store for GitHub projects.
    token_service
        Token manipulation service, used to mint the token.
    session
        Database session.
    logger
        Logger to use.
    """

    def __init__(
        self,
        *,
        config: GitHubTokenExchangeConfig,
        verifier: GitHubActionsTokenVerifier,
        project_store: GitHubProjectStore,
        token_service: TokenService,
        session: AsyncSession,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._verifier = verifier
        self._project_store = project_store
        self._token_service = token_service
        self._session = session
        self._logger = logger

    async def exchange_token(
        self,
        subject_token: str,
        *,
        scopes: set[str] | None,
        ip_address: str,
    ) -> GitHubTokenExchangeResult:
        """Exchange a GitHub Actions ID token for a Gafaelfawr token.

        The errors raised for a rejected exchange are sent to the client.
        Their messages name the check that failed and values from the
        caller's own ID token, which are already the caller's to read, but
        never describe registry entries that did not match, so that the
        exchange cannot be used to probe what the registry trusts.

        Parameters
        ----------
        subject_token
            Encoded GitHub Actions ID token.
        scopes
            Scopes requested for the token, or `None` to receive every
            scope of the matching project. Requested scopes must be a
            subset of the project's scopes; a request for a scope outside
            that set is rejected rather than silently narrowed, so that a
            misconfigured workflow fails visibly.
        ip_address
            IP address from which the request came, which is that of the
            GitHub Actions runner.

        Returns
        -------
        GitHubTokenExchangeResult
            The minted token and the identity and claims it was minted
            from.

        Raises
        ------
        FetchKeysError
            Raised if GitHub's key data is syntactically invalid or contains
            no usable keys.
        GitHubWebError
            Raised if unable to retrieve signing keys from GitHub.
        InvalidSubjectTokenError
            Raised if the ID token fails verification or matches no enabled
            GitHub project.
        InvalidTokenError
            Raised if the minted token could not be stored, probably due to
            a desynchronization between Redis and the SQL database.
        UnauthorizedScopeError
            Raised if a requested scope is not allowed by the matching
            project.
        """
        claims = await self._verify(subject_token)
        project = await self._match(claims)
        if scopes is None:
            scopes = set(project.scopes)
        else:
            unauthorized = scopes - project.scopes
            if unauthorized:
                msg = (
                    "Requested scopes not allowed for this workflow:"
                    f" {' '.join(sorted(unauthorized))}"
                )
                raise UnauthorizedScopeError(msg)

        # The project's lifetime was capped by the configured maximum when
        # the project was registered, but the configuration may have been
        # lowered since, so apply the environment-wide ceiling again.
        lifetime = min(project.max_lifetime, self._config.max_lifetime)
        token, expires = await self._token_service.create_github_token(
            project, scopes=scopes, lifetime=lifetime, ip_address=ip_address
        )

        self._logger.info(
            "Exchanged GitHub Actions token",
            github_project_id=project.id,
            username=project.username,
            token_key=token.key,
            token_scopes=sorted(scopes),
            token_claims=self._claims_for_logging(claims),
        )
        return GitHubTokenExchangeResult(
            token=token,
            username=project.username,
            github_project_id=project.id,
            scopes=scopes,
            expires=expires,
            claims=claims,
        )

    async def _match(self, claims: GitHubActionsClaims) -> GitHubProject:
        """Find the enabled GitHub project that a token satisfies.

        Parameters
        ----------
        claims
            Claims of the verified token.

        Returns
        -------
        GitHubProject
            The matching project.

        Raises
        ------
        InvalidSubjectTokenError
            Raised if no enabled project matches the token, or if more than
            one does. The latter should be impossible, since the registry
            refuses overlapping enabled projects, but that invariant is
            enforced by the registry service rather than the database, so
            it is checked here rather than relied on.
        """
        async with self._session.begin():
            projects = await self._project_store.list(
                repository=claims.repository
            )
        matches = [p for p in projects if p.matches(claims)]
        if not matches:
            environment = claims.environment or "(none)"
            msg = (
                "No enabled GitHub project matches repository"
                f" {claims.repository} (ID {claims.repository_id}, owner ID"
                f" {claims.repository_owner_id}), workflow"
                f" {claims.job_workflow_ref}, ref {claims.ref}, environment"
                f" {environment}"
            )
            raise InvalidSubjectTokenError(msg)
        if len(matches) > 1:
            self._logger.error(
                "Multiple GitHub projects match token",
                github_project_ids=[p.id for p in matches],
                token_claims=self._claims_for_logging(claims),
            )
            msg = (
                "Multiple GitHub projects match this token, which is a"
                " registry misconfiguration; contact an administrator"
            )
            raise InvalidSubjectTokenError(msg)
        return matches[0]

    async def _verify(self, subject_token: str) -> GitHubActionsClaims:
        """Verify a GitHub Actions ID token.

        Verification failures are converted to the error the client sees,
        with a message that names the check that failed and, for the issuer
        and audience checks, the value the token carried, since those are
        the mistakes a workflow author is most likely to make and the values
        are already theirs to read. Failures to retrieve GitHub's signing
        keys are not the caller's fault and are left to propagate.

        Parameters
        ----------
        subject_token
            Encoded GitHub Actions ID token.

        Returns
        -------
        GitHubActionsClaims
            Claims from the verified token.

        Raises
        ------
        FetchKeysError
            Raised if GitHub's key data is syntactically invalid or contains
            no usable keys.
        GitHubWebError
            Raised if unable to retrieve signing keys from GitHub.
        InvalidSubjectTokenError
            Raised if the token fails verification.
        """
        try:
            return await self._verifier.verify_token(subject_token)
        except jwt.ExpiredSignatureError as e:
            msg = "Token has expired"
            raise InvalidSubjectTokenError(msg) from e
        except jwt.ImmatureSignatureError as e:
            msg = "Token is not yet valid"
            raise InvalidSubjectTokenError(msg) from e
        except jwt.InvalidAudienceError as e:
            audience = self._unverified_claim(subject_token, "aud")
            msg = (
                f"Token audience {audience} does not match the expected"
                f" audience {self._config.audience}"
            )
            raise InvalidSubjectTokenError(msg) from e
        except jwt.InvalidIssuerError as e:
            issuer = self._unverified_claim(subject_token, "iss")
            msg = (
                f"Token issuer {issuer} is not the GitHub Actions issuer"
                f" {GITHUB_ACTIONS_ISSUER}"
            )
            raise InvalidSubjectTokenError(msg) from e
        except jwt.InvalidTokenError as e:
            msg = f"Token failed verification: {e}"
            raise InvalidSubjectTokenError(msg) from e
        except (
            InvalidTokenClaimsError,
            UnknownAlgorithmError,
            UnknownKeyIdError,
        ) as e:
            raise InvalidSubjectTokenError(str(e)) from e

    @staticmethod
    def _claims_for_logging(claims: GitHubActionsClaims) -> dict[str, Any]:
        """Select the claims worth recording in a log message."""
        return claims.model_dump(
            include={
                "repository",
                "job_workflow_ref",
                "ref",
                "environment",
                "event_name",
                "actor",
                "run_id",
                "run_attempt",
                "jti",
            },
            exclude_none=True,
        )

    @staticmethod
    def _unverified_claim(encoded: str, claim: str) -> Any:
        """Read a claim from a token without verifying it.

        Used only to describe a verification failure to the client. The
        token has already failed verification, so nothing is trusted from
        it; the claim is reported back to the caller because the token is
        theirs and the value is what they need to fix.

        Parameters
        ----------
        encoded
            Encoded token.
        claim
            Name of the claim.

        Returns
        -------
        Any
            Value of the claim, or `None` if the token cannot be decoded or
            does not have that claim.
        """
        try:
            payload = jwt.decode(encoded, options={"verify_signature": False})
        except jwt.InvalidTokenError:
            return None
        return payload.get(claim)
