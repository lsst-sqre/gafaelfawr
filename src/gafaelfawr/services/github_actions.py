"""Exchange GitHub Actions ID tokens for Gafaelfawr tokens."""

from typing import Any

import jwt
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import BoundLogger

from ..config import GitHubTokenExchangeConfig
from ..constants import GITHUB_ACTIONS_ISSUER
from ..exceptions import (
    InvalidSubjectTokenError,
    InvalidTokenClaimsError,
    UnauthorizedScopeError,
    UnknownAlgorithmError,
    UnknownKeyIdError,
)
from ..models.github_actions import (
    GitHubActionsClaims,
    GitHubTokenExchangeResult,
)
from ..models.github_project import GitHubProject
from ..providers.github_actions import GitHubActionsTokenVerifier
from ..storage.github_project import GitHubProjectStore
from .token import TokenService

__all__ = ["GitHubTokenExchangeService"]


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
