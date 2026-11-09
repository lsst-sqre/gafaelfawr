"""Models for the GitHub Actions token exchange.

These models describe the claims carried by the OpenID Connect ID tokens that
GitHub issues to GitHub Actions jobs, which the GitHub Actions token exchange
verifies and matches against the project registry, and the reply of the
exchange.
"""

from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, UrlConstraints
from safir.pydantic import UtcDatetime

from ..constants import OAUTH_ACCESS_TOKEN_TYPE
from ..types import Scopes
from .token import Token

__all__ = [
    "GitHubActionsClaims",
    "GitHubActionsJWKS",
    "GitHubActionsOIDCMetadata",
    "GitHubTokenExchangeReply",
    "GitHubTokenExchangeResult",
]


class GitHubActionsClaims(BaseModel):
    """Claims from a verified GitHub Actions ID token.

    Only the claims used by the token exchange are modeled. Claims that the
    registry matches on are required; claims that are only recorded for
    auditing are optional, so that a change in what GitHub includes does not
    break the exchange. Any other claims in the token are ignored.

    GitHub sends the numeric ID claims as strings, which are converted to
    integers here so that they can be compared to the IDs pinned in the
    project registry.
    """

    model_config = ConfigDict(extra="ignore")

    sub: str = Field(
        ...,
        title="Subject",
        description=(
            "Subject of the token, composed by GitHub from other claims. Only"
            " recorded for auditing; matching uses the structured claims."
        ),
        examples=["repo:lsst-sqre/ook:ref:refs/heads/main"],
    )

    jti: str = Field(
        ...,
        title="JWT ID",
        description="Unique identifier of this ID token",
    )

    repository: str = Field(
        ...,
        title="Repository",
        description="Full name of the repository running the workflow",
        examples=["lsst-sqre/ook"],
    )

    repository_id: int = Field(
        ...,
        title="Repository ID",
        description="Numeric GitHub ID of the repository",
    )

    repository_owner: str = Field(
        ...,
        title="Repository owner",
        description="Login of the organization or user owning the repository",
        examples=["lsst-sqre"],
    )

    repository_owner_id: int = Field(
        ...,
        title="Repository owner ID",
        description="Numeric GitHub ID of the repository owner",
    )

    job_workflow_ref: str = Field(
        ...,
        title="Job workflow reference",
        description=(
            "Path and ref of the workflow file running the job. For a job"
            " that calls a reusable workflow, this names the reusable"
            " workflow rather than the calling workflow."
        ),
        examples=["lsst-sqre/ook/.github/workflows/ci.yaml@refs/heads/main"],
    )

    ref: str = Field(
        ...,
        title="Git ref",
        description="Git ref that triggered the workflow run",
        examples=["refs/heads/main"],
    )

    environment: str | None = Field(
        None,
        title="Environment",
        description=(
            "GitHub Actions environment of the job, if the job uses one"
        ),
        examples=["production"],
    )

    workflow_ref: str | None = Field(
        None,
        title="Workflow reference",
        description=(
            "Path and ref of the top-level workflow file that was triggered"
        ),
    )

    event_name: str | None = Field(
        None,
        title="Event name",
        description="Name of the event that triggered the workflow run",
        examples=["push"],
    )

    actor: str | None = Field(
        None,
        title="Actor",
        description="GitHub login of the user who triggered the workflow run",
    )

    run_id: str | None = Field(
        None,
        title="Run ID",
        description="ID of the workflow run",
    )

    run_attempt: str | None = Field(
        None,
        title="Run attempt",
        description="Attempt number of the workflow run",
    )

    workflow_sha: str | None = Field(
        None,
        title="Workflow commit",
        description="Commit SHA of the workflow file that is running",
    )


class GitHubActionsOIDCMetadata(BaseModel):
    """OpenID Connect provider metadata for GitHub Actions.

    Only the metadata used by the token exchange is modeled. Any other
    metadata is ignored.
    """

    model_config = ConfigDict(extra="ignore")

    jwks_uri: Annotated[
        AnyUrl, UrlConstraints(allowed_schemes=["https"], host_required=True)
    ] = Field(
        ...,
        title="JWKS URI",
        description=(
            "URL of GitHub's JSON Web Key Set, from which the signing keys"
            " for GitHub Actions ID tokens are retrieved. Must be an HTTPS"
            " URL, since the keys retrieved from it decide which tokens are"
            " trusted."
        ),
        examples=[
            "https://token.actions.githubusercontent.com/.well-known/jwks"
        ],
    )


class GitHubActionsJWKS(BaseModel):
    """JSON Web Key Set published by GitHub for GitHub Actions ID tokens.

    The keys are not modeled further. The verifier parses each one with PyJWT
    and skips any that it cannot use, so that one unusable key in the set
    does not prevent verifying tokens signed with the others.
    """

    model_config = ConfigDict(extra="ignore")

    keys: list[dict[str, Any]] = Field(
        ...,
        title="Signing keys",
        description="Keys in JWK format",
    )


class GitHubTokenExchangeReply(BaseModel):
    """A reply to a successful GitHub Actions token exchange.

    The fields are those of a successful token response in RFC 6749 and RFC
    8693. The reply deliberately carries nothing Gafaelfawr-specific, such as
    the bot username or the matched project: a workflow does not need them,
    and the audit trail records both.
    """

    access_token: str = Field(
        ...,
        title="Gafaelfawr token",
        description="The minted Gafaelfawr token, of type ``github``",
        examples=["gt-vHj2M0OdtGVmwq3vz0u4iw.vk_fmBhUSsFndqRgvSi9ow"],
    )

    issued_token_type: str = Field(
        OAUTH_ACCESS_TOKEN_TYPE,
        title="Issued token type",
        description=f"Will always be ``{OAUTH_ACCESS_TOKEN_TYPE}``",
        examples=[OAUTH_ACCESS_TOKEN_TYPE],
    )

    token_type: str = Field(
        "Bearer",
        title="Type of token",
        description="Will always be ``Bearer``",
        examples=["Bearer"],
    )

    expires_in: int = Field(
        ...,
        title="Expiration in seconds",
        description="Remaining lifetime of the token in seconds",
        examples=[3600],
    )

    scope: str = Field(
        ...,
        title="Scopes of token",
        description="Space-separated scopes of the minted token",
        examples=["exec:linkcheck write:docverse"],
    )


class GitHubTokenExchangeResult(BaseModel):
    """Outcome of a successful GitHub Actions token exchange.

    This is what the exchange service returns to the route handler, which
    builds the reply to the client from it and records the exchange in the
    metrics events. It carries the identity the exchange resolved and the
    claims it resolved it from, so that an exchange can be traced to the
    exact workflow run that performed it.
    """

    token: Token = Field(..., title="Minted token")

    username: str = Field(
        ...,
        title="Bot username",
        description="Bot username of the matching GitHub project",
        examples=["bot-gh-lsst-sqre-ook"],
    )

    github_project_id: int = Field(
        ...,
        title="GitHub project ID",
        description="ID of the GitHub project that authorized the token",
        examples=[42],
    )

    scopes: Scopes = Field(..., title="Scopes of the minted token")

    expires: UtcDatetime = Field(..., title="Expiration of the minted token")

    claims: GitHubActionsClaims = Field(
        ...,
        title="ID token claims",
        description="Claims of the verified GitHub Actions ID token",
    )

    def to_reply(self) -> GitHubTokenExchangeReply:
        """Build the reply to send to the client.

        Returns
        -------
        GitHubTokenExchangeReply
            Reply following RFC 6749 and RFC 8693, with the remaining
            lifetime of the token calculated as of now.
        """
        remaining = self.expires - datetime.now(tz=UTC)
        return GitHubTokenExchangeReply(
            access_token=str(self.token),
            expires_in=max(int(remaining.total_seconds()), 0),
            scope=" ".join(sorted(self.scopes)),
        )
