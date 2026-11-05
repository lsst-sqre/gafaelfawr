"""Models for GitHub Actions ID tokens.

These models describe the claims carried by the OpenID Connect ID tokens that
GitHub issues to GitHub Actions jobs, which the GitHub Actions token exchange
verifies and matches against the project registry.
"""

from typing import Annotated, Any

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, UrlConstraints

__all__ = [
    "GitHubActionsClaims",
    "GitHubActionsJWKS",
    "GitHubActionsOIDCMetadata",
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
