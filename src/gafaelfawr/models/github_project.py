"""Models for the registry of GitHub projects.

A GitHub project binds a set of constraints on the claims of a GitHub Actions
ID token to a bot username and a token policy. The registry of projects is
the trust configuration of the GitHub Actions token exchange.
"""

import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Self

from pydantic import BaseModel, Field, field_validator, model_validator
from safir.pydantic import UtcDatetime

from ..constants import (
    GITHUB_BOT_USERNAME_REGEX,
    GITHUB_PROJECT_DEFAULT_LIFETIME,
    GITHUB_REPOSITORY_REGEX,
)
from ..types import IpAddress, Scopes
from .enums import GitHubProjectChange
from .userinfo import Group

__all__ = [
    "GitHubProject",
    "GitHubProjectCreate",
    "GitHubProjectHistoryEntry",
    "GitHubProjectUpdate",
]

# Field definitions shared between the create, update, and full models, so
# that the API documentation is consistent between them. The models differ
# in which fields are required and which may be null, so they cannot share
# the fields through inheritance.

_DESCRIPTION = Field(
    title="Description",
    description="Free text about this project for administrators",
    examples=["Documentation builds for SQR-062"],
)

_REQUESTED_BY = Field(
    title="Requested by",
    description=(
        "Opaque identifier of the person on whose behalf the project was"
        " created, as ``<source>:<identifier>``. Recorded and filterable but"
        " never interpreted."
    ),
    examples=["slack:U024BE7LH", "gafaelfawr:someuser"],
    min_length=1,
    max_length=256,
)

_USERNAME = Field(
    title="Bot username",
    description=(
        "Username for which tokens are minted. Must start with ``bot-gh-``"
        " and otherwise be a valid username. Several projects may share one."
    ),
    examples=["bot-gh-lsst-sqre-sqr-062"],
    min_length=1,
    max_length=64,
    pattern=GITHUB_BOT_USERNAME_REGEX,
)

_REPOSITORY = Field(
    title="Repository",
    description=(
        "GitHub repository as ``owner/name``, matched case-insensitively"
        " against the ``repository`` claim. Must be a public repository."
    ),
    examples=["lsst-sqre/sqr-062"],
    min_length=3,
    max_length=140,
    pattern=GITHUB_REPOSITORY_REGEX,
)

_REPOSITORY_ID = Field(
    title="Repository ID",
    description=(
        "Numeric GitHub ID of the repository, looked up when the project is"
        " created or its repository is changed and compared against the"
        " ``repository_id`` claim"
    ),
    examples=[123456],
)

_REPOSITORY_OWNER_ID = Field(
    title="Repository owner ID",
    description=(
        "Numeric GitHub ID of the repository owner, looked up when the"
        " project is created or its repository is changed and compared"
        " against the ``repository_owner_id`` claim"
    ),
    examples=[654321],
)

_WORKFLOW = Field(
    title="Workflow",
    description=(
        "Workflow file, compared against the path part of the"
        " ``job_workflow_ref`` claim. Either ``.github/workflows/<file>``"
        " for a workflow in the project repository or"
        " ``<owner>/<repo>/.github/workflows/<file>`` for a reusable"
        " workflow in another repository. No other forms are accepted, and"
        " a ref suffix such as ``@refs/heads/main`` is not allowed. Matches"
        " any workflow if unset."
    ),
    examples=[
        ".github/workflows/docs.yaml",
        "lsst-sqre/shared/.github/workflows/docs.yaml",
    ],
    min_length=1,
)

_ENVIRONMENT = Field(
    title="Environment",
    description=(
        "GitHub Actions environment name, compared against the"
        " ``environment`` claim. Tokens without that claim never match if"
        " this is set. Matches any environment if unset."
    ),
    examples=["production"],
    min_length=1,
)

_REF = Field(
    title="Git ref",
    description=(
        "Git ref, compared against the ``ref`` claim. Either an exact value"
        " such as ``refs/heads/main`` or a prefix ending in ``/`` such as"
        " ``refs/tags/``. Matches any ref if unset."
    ),
    examples=["refs/heads/main", "refs/tags/"],
    min_length=6,
    pattern="^refs/",
)

_SCOPES = Field(
    title="Scopes",
    description=(
        "Maximum scopes a minted token may carry. Each must be a known"
        " scope and may not be an ``admin:`` scope."
    ),
    examples=[["write:docverse", "exec:linkcheck"]],
)

_MAX_LIFETIME = Field(
    title="Maximum lifetime",
    description=(
        "Maximum lifetime of a minted token, as a number of seconds or an"
        " ISO 8601 duration. Capped by the Gafaelfawr configuration."
    ),
    examples=["PT1H", 3600],
)

_UID = Field(
    title="UID number",
    description="UID to store with minted tokens, if any",
    examples=[100000],
    ge=1,
)

_GID = Field(
    title="Primary GID",
    description="Primary GID to store with minted tokens, if any",
    examples=[100000],
    ge=1,
)

_GROUPS = Field(
    title="Groups",
    description="Groups to store with minted tokens, if any",
)

_ENABLED = Field(
    title="Enabled",
    description=(
        "Disabled projects are kept but never match. Disabling a project"
        " revokes its outstanding tokens."
    ),
)


_WORKFLOWS_DIR = ".github/workflows/"
"""Directory, relative to the repository root, that holds workflows."""


def _validate_workflow(v: str | None) -> str | None:
    """Require a workflow constraint to be one of the two accepted forms.

    The path part of the ``job_workflow_ref`` claim is always
    ``<owner>/<repo>/.github/workflows/<file>``, so a constraint must be
    either ``.github/workflows/<file>``, which is taken relative to the
    project repository, or that full path for a reusable workflow in
    another repository. Anything else could never match a token, and some
    other forms would be mistaken for a reusable workflow in a different
    repository and so escape the overlap check.
    """
    if v is None:
        return v
    if "@" in v:
        msg = "workflow must be a file path without a ref"
        raise ValueError(msg)
    repository, path = _split_workflow(v)
    if repository is not None and not re.fullmatch(
        GITHUB_REPOSITORY_REGEX, repository
    ):
        msg = _invalid_workflow_message(v)
        raise ValueError(msg)
    file = path.removeprefix(_WORKFLOWS_DIR)
    if file == path or not file or "/" in file:
        msg = _invalid_workflow_message(v)
        raise ValueError(msg)
    return v


def _invalid_workflow_message(workflow: str) -> str:
    """Build the error message for a workflow not in an accepted form."""
    return (
        f"workflow must be {_WORKFLOWS_DIR}<file> or"
        f" <owner>/<repo>/{_WORKFLOWS_DIR}<file>, not {workflow!r}"
    )


def _split_workflow(workflow: str) -> tuple[str | None, str]:
    """Split a workflow constraint into its repository and path parts.

    Parameters
    ----------
    workflow
        Workflow constraint. Need not be valid.

    Returns
    -------
    tuple
        The ``owner/repo`` part of the workflow, or `None` if the workflow
        is relative to the project repository, and the path within that
        repository.
    """
    if workflow.startswith(".github/"):
        return None, workflow
    owner, _, rest = workflow.partition("/")
    repo, _, path = rest.partition("/")
    return f"{owner}/{repo}", path


class GitHubProjectCreate(BaseModel):
    """Fields needed to create a new GitHub project."""

    description: Annotated[str | None, _DESCRIPTION] = None

    requested_by: Annotated[str | None, _REQUESTED_BY] = None

    username: Annotated[
        str | None,
        _USERNAME,
        Field(
            description=(
                "Username for which tokens are minted. Must start with"
                " ``bot-gh-`` and otherwise be a valid username. Derived"
                " from the repository as ``bot-gh-<owner>-<repo>`` if"
                " omitted."
            )
        ),
    ] = None

    repository: Annotated[str, _REPOSITORY]

    workflow: Annotated[str | None, _WORKFLOW] = None

    environment: Annotated[str | None, _ENVIRONMENT] = None

    ref: Annotated[str | None, _REF] = None

    scopes: Annotated[Scopes, _SCOPES]

    max_lifetime: Annotated[timedelta, _MAX_LIFETIME] = (
        GITHUB_PROJECT_DEFAULT_LIFETIME
    )

    uid: Annotated[int | None, _UID] = None

    gid: Annotated[int | None, _GID] = None

    groups: Annotated[list[Group] | None, _GROUPS] = None

    enabled: Annotated[bool, _ENABLED] = True

    _validate_workflow = field_validator("workflow")(_validate_workflow)


class GitHubProjectUpdate(BaseModel):
    """Changes to a GitHub project.

    Fields that are not set are left unchanged. Setting an optional field to
    null clears it. Setting ``username`` to null derives it from the
    repository again, and changing ``repository`` looks up its IDs again.
    """

    description: Annotated[str | None, _DESCRIPTION] = None

    requested_by: Annotated[str | None, _REQUESTED_BY] = None

    username: Annotated[
        str | None,
        _USERNAME,
        Field(
            description=(
                "Username for which tokens are minted. Must start with"
                " ``bot-gh-`` and otherwise be a valid username. Derived"
                " from the repository as ``bot-gh-<owner>-<repo>`` if set"
                " to null."
            )
        ),
    ] = None

    repository: Annotated[str | None, _REPOSITORY] = None

    workflow: Annotated[str | None, _WORKFLOW] = None

    environment: Annotated[str | None, _ENVIRONMENT] = None

    ref: Annotated[str | None, _REF] = None

    scopes: Annotated[Scopes | None, _SCOPES] = None

    max_lifetime: Annotated[timedelta | None, _MAX_LIFETIME] = None

    uid: Annotated[int | None, _UID] = None

    gid: Annotated[int | None, _GID] = None

    groups: Annotated[list[Group] | None, _GROUPS] = None

    enabled: Annotated[bool | None, _ENABLED] = None

    _validate_workflow = field_validator("workflow")(_validate_workflow)

    @model_validator(mode="after")
    def _reject_null_required_fields(self) -> Self:
        for name in ("repository", "scopes", "max_lifetime", "enabled"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} may not be null")
        return self


class GitHubProject(BaseModel):
    """A registered GitHub project."""

    id: int = Field(
        ...,
        title="Project ID",
        description="Unique identifier of the project",
        examples=[42],
    )

    template: str | None = Field(
        None,
        title="Template",
        description=(
            "Name of the project template this project was provisioned from,"
            " or null if it was created directly"
        ),
        examples=["technote"],
    )

    description: Annotated[str | None, _DESCRIPTION] = None

    requested_by: Annotated[str | None, _REQUESTED_BY] = None

    username: Annotated[str, _USERNAME]

    repository: Annotated[str, _REPOSITORY]

    repository_id: Annotated[int, _REPOSITORY_ID]

    repository_owner_id: Annotated[int, _REPOSITORY_OWNER_ID]

    workflow: Annotated[str | None, _WORKFLOW] = None

    environment: Annotated[str | None, _ENVIRONMENT] = None

    ref: Annotated[str | None, _REF] = None

    scopes: Annotated[Scopes, _SCOPES]

    max_lifetime: Annotated[timedelta, _MAX_LIFETIME]

    uid: Annotated[int | None, _UID] = None

    gid: Annotated[int | None, _GID] = None

    groups: Annotated[list[Group] | None, _GROUPS] = None

    enabled: Annotated[bool, _ENABLED]

    created: UtcDatetime = Field(
        ...,
        title="Created",
        description="When the project was created",
    )

    created_by: str = Field(
        ...,
        title="Created by",
        description="Username of the person who created the project",
        examples=["someadmin"],
    )

    modified: UtcDatetime = Field(
        ...,
        title="Modified",
        description="When the project was last modified",
    )

    modified_by: str = Field(
        ...,
        title="Modified by",
        description="Username of the person who last modified the project",
        examples=["someadmin"],
    )

    _validate_workflow = field_validator("workflow")(_validate_workflow)

    def overlaps(self, other: GitHubProjectCreate | Self) -> bool:
        """Whether a GitHub Actions ID token could match both projects.

        Two projects overlap when they are for the same repository and, for
        each of ``workflow``, ``environment``, and ``ref``, the constraint is
        unset in at least one of them, the values are equal, or one ref is a
        prefix of the other.

        Parameters
        ----------
        other
            Project to compare against, with its repository in the form
            GitHub reports it.

        Returns
        -------
        bool
            `True` if some token could satisfy the constraints of both.
        """
        if self.repository.lower() != other.repository.lower():
            return False
        if self.workflow and other.workflow:
            other_path = _workflow_path(other.repository, other.workflow)
            if self.workflow_path != other_path:
                return False
        if self.environment and other.environment:
            if self.environment != other.environment:
                return False
        if self.ref and other.ref:
            if not _refs_overlap(self.ref, other.ref):
                return False
        return True

    @property
    def workflow_path(self) -> str | None:
        """Workflow as a full path, as in the ``job_workflow_ref`` claim.

        A workflow given as ``.github/workflows/<file>`` is prefixed with
        the project repository, and one given as a full
        ``<owner>/<repo>/.github/workflows/<file>`` path is used as is. The
        repository part is lowercased, since repository names are matched
        case-insensitively, but the path part is not.
        """
        return _workflow_path(self.repository, self.workflow)


def _refs_overlap(a: str, b: str) -> bool:
    """Whether two ref constraints could match the same ref."""
    if a == b:
        return True
    if a.endswith("/") and b.startswith(a):
        return True
    return b.endswith("/") and a.startswith(b)


def _workflow_path(repository: str, workflow: str | None) -> str | None:
    """Convert a workflow constraint to a full path.

    Parameters
    ----------
    repository
        Repository of the project.
    workflow
        Workflow constraint in one of the forms accepted by
        `_validate_workflow`: either ``.github/workflows/<file>``, relative
        to the project repository, or a full
        ``<owner>/<repo>/.github/workflows/<file>`` path.

    Returns
    -------
    str or None
        Full path in the form of the path part of the ``job_workflow_ref``
        claim, with the repository lowercased, or `None` if the workflow is
        not constrained.
    """
    if workflow is None:
        return None
    workflow_repository, path = _split_workflow(workflow)
    if workflow_repository is None:
        workflow_repository = repository
    return f"{workflow_repository.lower()}/{path}"


class GitHubProjectHistoryEntry(BaseModel):
    """A record of a change to a GitHub project or project template."""

    project_id: int | None = Field(
        None,
        title="Project ID",
        description=(
            "ID of the project that was changed, or null for a change to a"
            " project template"
        ),
        examples=[42],
    )

    template: str | None = Field(
        None,
        title="Template",
        description=(
            "Name of the project template that was changed, or that the"
            " changed project was provisioned from"
        ),
        examples=["technote"],
    )

    action: GitHubProjectChange = Field(
        ..., title="Type of change", examples=["modify"]
    )

    actor: str = Field(
        ...,
        title="Actor",
        description="Username of the person making the change",
        examples=["someadmin"],
        min_length=1,
        max_length=64,
    )

    ip_address: IpAddress | None = Field(
        None,
        title="IP address",
        description=(
            "IP address from which the change was made. Will be missing if"
            " the change was made internally by Gafaelfawr."
        ),
        examples=["198.51.100.50"],
    )

    event_time: UtcDatetime = Field(
        default_factory=lambda: datetime.now(tz=UTC).replace(microsecond=0),
        title="Timestamp",
        description="When the change was made",
    )

    old_values: dict[str, Any] | None = Field(
        None,
        title="Old values",
        description=(
            "The project or template before the change, or null for a creation"
        ),
    )

    new_values: dict[str, Any] | None = Field(
        None,
        title="New values",
        description=(
            "The project or template after the change, or null for a deletion"
        ),
    )
