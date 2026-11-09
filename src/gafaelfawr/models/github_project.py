"""Models for the registry of GitHub projects.

A GitHub project binds a set of constraints on the claims of a GitHub Actions
ID token to a bot username and a token policy. The registry of projects is
the trust configuration of the GitHub Actions token exchange. A project
template fixes every field of a project except the repository, so that a
provisioner holding a narrower scope than a token administrator can create
projects of an administrator-defined shape.
"""

import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Self

from pydantic import (
    BaseModel,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)
from safir.pydantic import UtcDatetime

from ..constants import (
    GITHUB_BOT_USERNAME_REGEX,
    GITHUB_OWNER_REGEX,
    GITHUB_PROJECT_TEMPLATE_NAME_REGEX,
    GITHUB_REPOSITORY_REGEX,
)
from ..types import IpAddress, Scopes
from .enums import GitHubProjectChange
from .github import GitHubRepository
from .github_actions import GitHubActionsClaims
from .userinfo import Group

__all__ = [
    "GitHubBotUsername",
    "GitHubOwner",
    "GitHubOwnerName",
    "GitHubProject",
    "GitHubProjectCreate",
    "GitHubProjectHistoryEntry",
    "GitHubProjectProvision",
    "GitHubProjectRequester",
    "GitHubProjectTemplate",
    "GitHubProjectTemplateCreate",
    "GitHubProjectTemplateName",
    "GitHubProjectTemplateUpdate",
    "GitHubProjectUpdate",
    "GitHubRepositoryName",
]

# Validation constraints on the string fields that the list API also
# accepts as filters. The constraints are attached to the types rather
# than the field definitions below so that the filters in the API
# handler can share them and cannot drift from the models. These are
# plain aliases rather than PEP 695 type aliases because the latter
# become separate component schemas in the OpenAPI document, which
# hides the constraints from the query parameter documentation.

GitHubBotUsername = Annotated[
    str,
    StringConstraints(
        min_length=1, max_length=64, pattern=GITHUB_BOT_USERNAME_REGEX
    ),
]
"""Bot username for which a GitHub project mints tokens."""

GitHubOwnerName = Annotated[
    str,
    StringConstraints(min_length=1, max_length=39, pattern=GITHUB_OWNER_REGEX),
]
"""Login of a GitHub owner (organization or user)."""

GitHubProjectRequester = Annotated[
    str, StringConstraints(min_length=1, max_length=256)
]
"""Opaque identifier of the person who requested a GitHub project."""

GitHubProjectTemplateName = Annotated[
    str,
    StringConstraints(
        min_length=1, max_length=64, pattern=GITHUB_PROJECT_TEMPLATE_NAME_REGEX
    ),
]
"""Name of a GitHub project template."""

GitHubRepositoryName = Annotated[
    str,
    StringConstraints(
        min_length=3, max_length=140, pattern=GITHUB_REPOSITORY_REGEX
    ),
]
"""GitHub repository as ``owner/name``."""

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
)

_USERNAME = Field(
    title="Bot username",
    description=(
        "Username for which tokens are minted. Must start with ``bot-gh-``"
        " and otherwise be a valid username. Several projects may share one."
    ),
    examples=["bot-gh-lsst-sqre-sqr-062"],
)

_REPOSITORY = Field(
    title="Repository",
    description=(
        "GitHub repository as ``owner/name``, matched case-insensitively"
        " against the ``repository`` claim. Must be a public repository."
    ),
    examples=["lsst-sqre/sqr-062"],
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
        "Disabled projects are kept but never match and do not take part in"
        " overlap checks, so a disabled project may overlap other projects."
        " Disabling a project revokes its outstanding tokens. Re-enabling"
        " one is refused if it would overlap an enabled project."
    ),
)

_TEMPLATE_NAME = Field(
    title="Name",
    description=(
        "Identifier of the template, used in URLs and by provisioners."
        " Cannot be changed once the template is created."
    ),
    examples=["technote"],
)

_TEMPLATE_DESCRIPTION = Field(
    title="Description",
    description="Free text about this template for administrators",
    examples=["Documentation builds for technotes created by Templatebot"],
)

_OWNERS = Field(
    title="Owners",
    description=(
        "GitHub owners (organizations or users) whose repositories may be"
        " provisioned from this template. Each is looked up on GitHub when"
        " the template is created or the list is changed, and its numeric"
        " ID is pinned alongside its name."
    ),
    examples=[["lsst-sqre", "lsst-dm"]],
    min_length=1,
)

_REPOSITORY_PATTERN = Field(
    title="Repository pattern",
    description=(
        "Regular expression that the name of a repository, without its"
        " owner, must match in full (case-insensitively) to be provisioned"
        " from this template. Any name is allowed if unset."
    ),
    examples=["^[a-z]+-[0-9]{3,}$"],
    min_length=1,
)

_TEMPLATE_WORKFLOW = Field(
    title="Workflow",
    description=(
        "Workflow constraint copied into every project provisioned from"
        " this template, in the same forms as for a project. The"
        " ``.github/workflows/<file>`` form is relative to the provisioned"
        " repository."
    ),
    examples=[
        "lsst-sqre/rubin-sphinx-technote-workflows/.github/workflows/ci.yaml"
    ],
    min_length=1,
)

_TEMPLATE_ENVIRONMENT = Field(
    title="Environment",
    description=(
        "Environment constraint copied into every project provisioned from"
        " this template"
    ),
    examples=["production"],
    min_length=1,
)

_TEMPLATE_REF = Field(
    title="Git ref",
    description=(
        "Ref constraint copied into every project provisioned from this"
        " template, either an exact ref or a prefix ending in ``/``"
    ),
    examples=["refs/heads/main", "refs/tags/"],
    min_length=6,
    pattern="^refs/",
)

_TEMPLATE_SCOPES = Field(
    title="Scopes",
    description=(
        "Maximum scopes of tokens minted for projects provisioned from this"
        " template. Each must be a known scope and may not be an ``admin:``"
        " scope."
    ),
    examples=[["write:docverse", "exec:linkcheck"]],
)

_TEMPLATE_MAX_LIFETIME = Field(
    title="Maximum lifetime",
    description=(
        "Maximum lifetime of tokens minted for projects provisioned from"
        " this template, as a number of seconds or an ISO 8601 duration."
        " Capped by the Gafaelfawr configuration."
    ),
    examples=["PT1H", 3600],
)

_TEMPLATE_ENABLED = Field(
    title="Enabled",
    description=(
        "Disabled templates cannot be used to provision projects. Projects"
        " already provisioned from a disabled template are unaffected."
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


def _validate_repository_pattern(v: str | None) -> str | None:
    """Require a repository pattern to be a valid regular expression."""
    if v is None:
        return v
    try:
        re.compile(v)
    except re.error as e:
        msg = f"repository_pattern is not a valid regular expression: {e}"
        raise ValueError(msg) from e
    return v


def _validate_owners(v: list[str]) -> list[str]:
    """Require the owners of a template to be distinct.

    GitHub logins are case-insensitive, so two spellings of the same login
    are duplicates.
    """
    seen = set()
    for owner in v:
        if owner.lower() in seen:
            msg = f"Duplicate owner {owner}"
            raise ValueError(msg)
        seen.add(owner.lower())
    return v


class GitHubProjectCreate(BaseModel):
    """Fields needed to create a new GitHub project."""

    description: Annotated[str | None, _DESCRIPTION] = None

    requested_by: Annotated[GitHubProjectRequester | None, _REQUESTED_BY] = (
        None
    )

    username: Annotated[
        GitHubBotUsername | None,
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

    repository: Annotated[GitHubRepositoryName, _REPOSITORY]

    workflow: Annotated[str | None, _WORKFLOW] = None

    environment: Annotated[str | None, _ENVIRONMENT] = None

    ref: Annotated[str | None, _REF] = None

    scopes: Annotated[Scopes, _SCOPES]

    max_lifetime: Annotated[
        timedelta | None,
        _MAX_LIFETIME,
        Field(
            description=(
                "Maximum lifetime of a minted token, as a number of seconds"
                " or an ISO 8601 duration. Capped by the Gafaelfawr"
                " configuration. If omitted, defaults to one hour or the"
                " configured maximum, whichever is shorter."
            )
        ),
    ] = None

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

    requested_by: Annotated[GitHubProjectRequester | None, _REQUESTED_BY] = (
        None
    )

    username: Annotated[
        GitHubBotUsername | None,
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

    repository: Annotated[GitHubRepositoryName | None, _REPOSITORY] = None

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

    template: Annotated[
        GitHubProjectTemplateName | None,
        Field(
            title="Template",
            description=(
                "Name of the project template this project was provisioned"
                " from, or null if it was created directly"
            ),
            examples=["technote"],
        ),
    ] = None

    description: Annotated[str | None, _DESCRIPTION] = None

    requested_by: Annotated[GitHubProjectRequester | None, _REQUESTED_BY] = (
        None
    )

    username: Annotated[GitHubBotUsername, _USERNAME]

    repository: Annotated[GitHubRepositoryName, _REPOSITORY]

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

    def matches(self, claims: GitHubActionsClaims) -> bool:
        """Whether a GitHub Actions ID token satisfies this project.

        A token matches when the project is enabled and every constraint
        the project sets is satisfied: the ``repository`` claim equals the
        project repository (case-insensitively) and the ``repository_id``
        and ``repository_owner_id`` claims equal the pinned IDs; if a
        workflow is set, the path part of ``job_workflow_ref`` equals it;
        if an environment is set, the ``environment`` claim equals it; and
        if a ref is set, the ``ref`` claim equals it or, when the ref ends
        in ``/``, starts with it. Unset constraints match anything.

        Parameters
        ----------
        claims
            Claims of the verified token.

        Returns
        -------
        bool
            `True` if the token satisfies every constraint of the project.
        """
        if not self.enabled or not self._matches_repository(claims):
            return False
        if self.workflow and self.workflow_path != _job_workflow_path(claims):
            return False
        if self.environment and self.environment != claims.environment:
            return False
        return not self.ref or _ref_matches(self.ref, claims.ref)

    def _matches_repository(self, claims: GitHubActionsClaims) -> bool:
        """Whether a token comes from the pinned repository.

        The repository name is compared case-insensitively, and the numeric
        IDs of the repository and its owner must equal the pinned values, so
        that a renamed or re-created repository does not inherit trust.
        """
        return (
            self.repository.lower() == claims.repository.lower()
            and self.repository_id == claims.repository_id
            and self.repository_owner_id == claims.repository_owner_id
        )

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


def _job_workflow_path(claims: GitHubActionsClaims) -> str:
    """Extract the workflow path from the ``job_workflow_ref`` claim.

    The claim is always ``<owner>/<repo>/.github/workflows/<file>@<ref>``,
    naming the repository that holds the workflow even when it is the one
    running the job, so unlike a workflow constraint it is never relative
    to the ``repository`` claim. The ref is dropped and the owner and
    repository parts are lowercased, producing the same form as
    `GitHubProject.workflow_path` so that the two can be compared.

    Parameters
    ----------
    claims
        Claims of the verified token.

    Returns
    -------
    str
        Workflow path with the repository lowercased.
    """
    path, _, _ = claims.job_workflow_ref.partition("@")
    owner, _, rest = path.partition("/")
    repo, _, file_path = rest.partition("/")
    return f"{owner.lower()}/{repo.lower()}/{file_path}"


def _ref_matches(constraint: str, ref: str) -> bool:
    """Whether a ref satisfies a ref constraint.

    A constraint ending in ``/`` is a prefix and matches any ref that starts
    with it; any other constraint must equal the ref.
    """
    if constraint.endswith("/"):
        return ref.startswith(constraint)
    return ref == constraint


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


class GitHubOwner(BaseModel):
    """A GitHub owner (organization or user) with its pinned numeric ID.

    Owners are stored on project templates by name and ID so that the
    template keeps trusting the original owner if the name is later
    reused, as the pinned repository IDs do for projects.
    """

    name: str = Field(
        ...,
        title="Owner name",
        description="Login of the owner, as GitHub reports it",
        examples=["lsst-sqre"],
    )

    id: int = Field(
        ...,
        title="Owner ID",
        description="Numeric GitHub ID of the owner",
        examples=[654321],
    )


class GitHubProjectTemplateCreate(BaseModel):
    """Fields needed to create a new GitHub project template."""

    name: Annotated[GitHubProjectTemplateName, _TEMPLATE_NAME]

    description: Annotated[str | None, _TEMPLATE_DESCRIPTION] = None

    owners: Annotated[list[GitHubOwnerName], _OWNERS]

    repository_pattern: Annotated[str | None, _REPOSITORY_PATTERN] = None

    workflow: Annotated[str | None, _TEMPLATE_WORKFLOW] = None

    environment: Annotated[str | None, _TEMPLATE_ENVIRONMENT] = None

    ref: Annotated[str | None, _TEMPLATE_REF] = None

    scopes: Annotated[Scopes, _TEMPLATE_SCOPES]

    max_lifetime: Annotated[
        timedelta | None,
        _TEMPLATE_MAX_LIFETIME,
        Field(
            description=(
                "Maximum lifetime of tokens minted for projects provisioned"
                " from this template, as a number of seconds or an ISO 8601"
                " duration. Capped by the Gafaelfawr configuration. If"
                " omitted, defaults to one hour or the configured maximum,"
                " whichever is shorter."
            )
        ),
    ] = None

    uid: Annotated[int | None, _UID] = None

    gid: Annotated[int | None, _GID] = None

    groups: Annotated[list[Group] | None, _GROUPS] = None

    enabled: Annotated[bool, _TEMPLATE_ENABLED] = True

    _validate_owners = field_validator("owners")(_validate_owners)
    _validate_repository_pattern = field_validator("repository_pattern")(
        _validate_repository_pattern
    )
    _validate_workflow = field_validator("workflow")(_validate_workflow)


class GitHubProjectTemplateUpdate(BaseModel):
    """Changes to a GitHub project template.

    Fields that are not set are left unchanged. Setting an optional field to
    null clears it. The name of a template cannot be changed. Changing the
    owners looks up the IDs of owners that were not already in the list.
    Changes to a template affect only projects provisioned afterwards.
    """

    description: Annotated[str | None, _TEMPLATE_DESCRIPTION] = None

    owners: Annotated[list[GitHubOwnerName] | None, _OWNERS] = None

    repository_pattern: Annotated[str | None, _REPOSITORY_PATTERN] = None

    workflow: Annotated[str | None, _TEMPLATE_WORKFLOW] = None

    environment: Annotated[str | None, _TEMPLATE_ENVIRONMENT] = None

    ref: Annotated[str | None, _TEMPLATE_REF] = None

    scopes: Annotated[Scopes | None, _TEMPLATE_SCOPES] = None

    max_lifetime: Annotated[timedelta | None, _TEMPLATE_MAX_LIFETIME] = None

    uid: Annotated[int | None, _UID] = None

    gid: Annotated[int | None, _GID] = None

    groups: Annotated[list[Group] | None, _GROUPS] = None

    enabled: Annotated[bool | None, _TEMPLATE_ENABLED] = None

    _validate_repository_pattern = field_validator("repository_pattern")(
        _validate_repository_pattern
    )
    _validate_workflow = field_validator("workflow")(_validate_workflow)

    @field_validator("owners")
    @classmethod
    def _validate_optional_owners(
        cls, v: list[str] | None
    ) -> list[str] | None:
        return None if v is None else _validate_owners(v)

    @model_validator(mode="after")
    def _reject_null_required_fields(self) -> Self:
        for name in ("owners", "scopes", "max_lifetime", "enabled"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} may not be null")
        return self


class GitHubProjectProvision(BaseModel):
    """Request to provision a GitHub project from a template.

    Only the repository and the descriptive fields can be chosen. Every
    other field of the project comes from the template, and the username is
    always derived from the repository.
    """

    repository: Annotated[GitHubRepositoryName, _REPOSITORY]

    description: Annotated[str | None, _DESCRIPTION] = None

    requested_by: Annotated[GitHubProjectRequester | None, _REQUESTED_BY] = (
        None
    )


class GitHubProjectTemplate(BaseModel):
    """A template from which GitHub projects can be provisioned.

    A template fixes every field of a project except the repository, its
    description, and its requester, and restricts the repositories that may
    be provisioned from it to a set of GitHub owners and an optional pattern
    on the repository name. The fields of the template are copied into each
    provisioned project, so later changes to the template do not affect
    projects already provisioned from it.
    """

    name: Annotated[GitHubProjectTemplateName, _TEMPLATE_NAME]

    description: Annotated[str | None, _TEMPLATE_DESCRIPTION] = None

    owners: Annotated[
        list[GitHubOwner],
        _OWNERS,
        Field(
            description=(
                "GitHub owners (organizations or users) whose repositories"
                " may be provisioned from this template, with the numeric"
                " ID of each pinned alongside its name"
            ),
            examples=[[{"name": "lsst-sqre", "id": 654321}]],
        ),
    ]

    repository_pattern: Annotated[str | None, _REPOSITORY_PATTERN] = None

    workflow: Annotated[str | None, _TEMPLATE_WORKFLOW] = None

    environment: Annotated[str | None, _TEMPLATE_ENVIRONMENT] = None

    ref: Annotated[str | None, _TEMPLATE_REF] = None

    scopes: Annotated[Scopes, _TEMPLATE_SCOPES]

    max_lifetime: Annotated[timedelta, _TEMPLATE_MAX_LIFETIME]

    uid: Annotated[int | None, _UID] = None

    gid: Annotated[int | None, _GID] = None

    groups: Annotated[list[Group] | None, _GROUPS] = None

    enabled: Annotated[bool, _TEMPLATE_ENABLED]

    created: UtcDatetime = Field(
        ...,
        title="Created",
        description="When the template was created",
    )

    created_by: str = Field(
        ...,
        title="Created by",
        description="Username of the person who created the template",
        examples=["someadmin"],
    )

    modified: UtcDatetime = Field(
        ...,
        title="Modified",
        description="When the template was last modified",
    )

    modified_by: str = Field(
        ...,
        title="Modified by",
        description="Username of the person who last modified the template",
        examples=["someadmin"],
    )

    _validate_repository_pattern = field_validator("repository_pattern")(
        _validate_repository_pattern
    )
    _validate_workflow = field_validator("workflow")(_validate_workflow)

    def allows_owner(self, repository: GitHubRepository) -> bool:
        """Whether a repository belongs to one of the allowed owners.

        The owner part of the repository name must equal the name of an
        allowed owner case-insensitively, and the numeric ID of the
        repository owner must equal the ID pinned for that owner, so that
        an owner name re-registered after deletion is not trusted.

        Parameters
        ----------
        repository
            Repository metadata from GitHub.

        Returns
        -------
        bool
            `True` if the repository may be provisioned from this template
            as far as its owner is concerned.
        """
        owner_name, _, _ = repository.full_name.partition("/")
        return any(
            o.name.lower() == owner_name.lower()
            and o.id == repository.owner_id
            for o in self.owners
        )

    def matches_name(self, repository: GitHubRepository) -> bool:
        """Whether a repository name satisfies the repository pattern.

        The name of the repository, without its owner, must match the
        whole pattern, compared case-insensitively since GitHub repository
        names are case-insensitive. Any name matches if the template has
        no pattern.

        Parameters
        ----------
        repository
            Repository metadata from GitHub.

        Returns
        -------
        bool
            `True` if the repository name is allowed by this template.
        """
        if self.repository_pattern is None:
            return True
        _, _, name = repository.full_name.partition("/")
        return bool(
            re.fullmatch(self.repository_pattern, name, flags=re.IGNORECASE)
        )

    def to_project_create(
        self, provision: GitHubProjectProvision
    ) -> GitHubProjectCreate:
        """Build the request to create a project from this template.

        The constraints and token policy come from the template and the
        repository, description, and requester from the provisioning
        request. The username is left unset so that it is derived from the
        repository, and the project is enabled.

        Parameters
        ----------
        provision
            Provisioning request.

        Returns
        -------
        GitHubProjectCreate
            Equivalent request to the project creation API.
        """
        return GitHubProjectCreate(
            description=provision.description,
            requested_by=provision.requested_by,
            repository=provision.repository,
            workflow=self.workflow,
            environment=self.environment,
            ref=self.ref,
            scopes=self.scopes,
            max_lifetime=self.max_lifetime,
            uid=self.uid,
            gid=self.gid,
            groups=self.groups,
            enabled=True,
        )


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
