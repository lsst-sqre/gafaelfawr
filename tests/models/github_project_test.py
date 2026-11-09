"""Tests for the GitHub project models."""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from gafaelfawr.main import create_openapi
from gafaelfawr.models.github_actions import GitHubActionsClaims
from gafaelfawr.models.github_project import (
    GitHubProject,
    GitHubProjectCreate,
    GitHubProjectUpdate,
)


def make_project(
    repository: str = "lsst-sqre/sqr-062",
    *,
    workflow: str | None = None,
    environment: str | None = None,
    ref: str | None = None,
) -> GitHubProject:
    now = datetime.now(tz=UTC).replace(microsecond=0)
    return GitHubProject(
        id=1,
        username="bot-gh-lsst-sqre-sqr-062",
        repository=repository,
        repository_id=123456,
        repository_owner_id=654321,
        workflow=workflow,
        environment=environment,
        ref=ref,
        scopes={"read:all"},
        max_lifetime=timedelta(hours=1),
        enabled=True,
        created=now,
        created_by="admin",
        modified=now,
        modified_by="admin",
    )


def test_create_validation() -> None:
    create = GitHubProjectCreate(
        repository="lsst-sqre/sqr-062", scopes={"read:all"}
    )
    assert create.username is None
    assert create.max_lifetime is None
    assert create.enabled

    # Durations can be given as seconds or ISO 8601 and serialize to ISO
    # 8601.
    create = GitHubProjectCreate.model_validate(
        {"repository": "lsst-sqre/sqr-062", "scopes": [], "max_lifetime": 900}
    )
    assert create.max_lifetime == timedelta(minutes=15)
    assert create.model_dump(mode="json")["max_lifetime"] == "PT15M"
    create = GitHubProjectCreate.model_validate(
        {
            "repository": "lsst-sqre/sqr-062",
            "scopes": ["read:all"],
            "max_lifetime": "PT2H",
        }
    )
    assert create.max_lifetime == timedelta(hours=2)

    for username in ("bot-sqr-062", "bot-gh-", "bot-gh-Foo", "someuser"):
        with pytest.raises(ValidationError):
            GitHubProjectCreate(
                repository="lsst-sqre/sqr-062", scopes=set(), username=username
            )
    for repository in ("sqr-062", "-lsst/sqr-062", "lsst/sqr/062", "a/b c"):
        with pytest.raises(ValidationError):
            GitHubProjectCreate(repository=repository, scopes=set())
    with pytest.raises(ValidationError):
        GitHubProjectCreate(
            repository="lsst-sqre/sqr-062", scopes=set(), ref="main"
        )
    with pytest.raises(ValidationError):
        GitHubProjectCreate(
            repository="lsst-sqre/sqr-062",
            scopes=set(),
            workflow=".github/workflows/ci.yaml@refs/heads/main",
        )


def test_workflow_validation() -> None:
    # Only a path relative to the repository root or a full path including
    # the repository of a reusable workflow are accepted.
    for workflow in (
        ".github/workflows/docs.yaml",
        "lsst-sqre/shared/.github/workflows/docs.yaml",
        "LSST-SQRE/Shared.Repo/.github/workflows/docs.yml",
    ):
        create = GitHubProjectCreate(
            repository="lsst-sqre/sqr-062", scopes=set(), workflow=workflow
        )
        assert create.workflow == workflow
        update = GitHubProjectUpdate(workflow=workflow)
        assert update.workflow == workflow
        assert make_project(workflow=workflow).workflow == workflow

    # Anything else could never match the path part of a job_workflow_ref
    # claim, or would be mistaken for a reusable workflow elsewhere.
    for workflow in (
        "docs.yaml",
        "workflows/docs.yaml",
        "docs/ci/build.yaml",
        ".github/workflows/",
        ".github/workflows",
        ".github/workflows/nested/docs.yaml",
        ".github/docs.yaml",
        "lsst-sqre/shared/docs.yaml",
        "lsst-sqre/shared/.github/workflows/",
        "-lsst/shared/.github/workflows/docs.yaml",
        "lsst-sqre/shared/extra/.github/workflows/docs.yaml",
        ".github/workflows/ci.yaml@refs/heads/main",
        "lsst-sqre/shared/.github/workflows/docs.yaml@v1",
    ):
        with pytest.raises(ValidationError):
            GitHubProjectCreate(
                repository="lsst-sqre/sqr-062",
                scopes=set(),
                workflow=workflow,
            )
        with pytest.raises(ValidationError):
            GitHubProjectUpdate(workflow=workflow)
        with pytest.raises(ValidationError):
            make_project(workflow=workflow)

    # The accepted forms produce the full path of the job_workflow_ref
    # claim, with only the repository part lowercased.
    assert make_project().workflow_path is None
    project = make_project(
        "LSST-SQRE/SQR-062", workflow=".github/workflows/Docs.yaml"
    )
    assert (
        project.workflow_path
        == "lsst-sqre/sqr-062/.github/workflows/Docs.yaml"
    )
    project = make_project(
        workflow="LSST-SQRE/Shared/.github/workflows/Docs.yaml"
    )
    assert (
        project.workflow_path == "lsst-sqre/shared/.github/workflows/Docs.yaml"
    )


def test_update_validation() -> None:
    update = GitHubProjectUpdate(username=None, description="Some text")
    assert update.model_fields_set == {"username", "description"}
    assert update.model_dump(exclude_unset=True) == {
        "username": None,
        "description": "Some text",
    }

    for field in ("repository", "scopes", "max_lifetime", "enabled"):
        with pytest.raises(ValidationError):
            GitHubProjectUpdate(**{field: None})


def make_claims(
    repository: str = "lsst-sqre/sqr-062",
    *,
    repository_id: int = 123456,
    repository_owner_id: int = 654321,
    job_workflow_ref: str | None = None,
    ref: str = "refs/heads/main",
    environment: str | None = None,
) -> GitHubActionsClaims:
    if job_workflow_ref is None:
        job_workflow_ref = f"{repository}/.github/workflows/docs.yaml@{ref}"
    return GitHubActionsClaims(
        sub=f"repo:{repository}:ref:{ref}",
        jti="some-jti",
        repository=repository,
        repository_id=repository_id,
        repository_owner="lsst-sqre",
        repository_owner_id=repository_owner_id,
        job_workflow_ref=job_workflow_ref,
        ref=ref,
        environment=environment,
    )


def test_matches() -> None:
    base = make_project()
    assert base.matches(make_claims())
    assert base.matches(make_claims("LSST-SQRE/SQR-062"))
    assert not base.matches(make_claims("lsst-sqre/other"))
    assert not base.matches(make_claims(repository_id=999999))
    assert not base.matches(make_claims(repository_owner_id=999999))
    assert not base.model_copy(update={"enabled": False}).matches(
        make_claims()
    )

    # An unconstrained project matches any workflow, ref, and environment.
    assert base.matches(
        make_claims(
            job_workflow_ref="lsst-sqre/sqr-062/.github/workflows/ci.yaml@x",
            ref="refs/pull/42/merge",
            environment="production",
        )
    )

    # Workflows are compared as full paths without the ref, with the
    # repository part case-insensitive and the file part case-sensitive.
    relative = make_project(workflow=".github/workflows/docs.yaml")
    assert relative.matches(make_claims())
    assert relative.matches(
        make_claims(
            "LSST-SQRE/SQR-062",
            job_workflow_ref=(
                "LSST-SQRE/SQR-062/.github/workflows/docs.yaml@refs/tags/v1"
            ),
        )
    )
    assert not relative.matches(
        make_claims(
            job_workflow_ref=(
                "lsst-sqre/sqr-062/.github/workflows/Docs.yaml@refs/heads/main"
            )
        )
    )
    assert not relative.matches(
        make_claims(
            job_workflow_ref=(
                "lsst-sqre/sqr-062/.github/workflows/ci.yaml@refs/heads/main"
            )
        )
    )
    reusable = make_project(
        workflow="lsst-sqre/shared/.github/workflows/docs.yaml"
    )
    assert not reusable.matches(make_claims())
    assert reusable.matches(
        make_claims(
            job_workflow_ref=(
                "lsst-sqre/shared/.github/workflows/docs.yaml@refs/heads/main"
            )
        )
    )
    assert reusable.matches(
        make_claims(
            job_workflow_ref=(
                "LSST-SQRE/Shared/.github/workflows/docs.yaml@refs/heads/main"
            )
        )
    )
    assert not reusable.matches(
        make_claims(
            job_workflow_ref=(
                "lsst-sqre/shared/.github/workflows/Docs.yaml@refs/heads/main"
            )
        )
    )

    # Environments must match exactly and must be present if constrained.
    production = make_project(environment="production")
    assert production.matches(make_claims(environment="production"))
    assert not production.matches(make_claims(environment="staging"))
    assert not production.matches(make_claims())

    # Refs must match exactly unless the constraint is a prefix.
    main = make_project(ref="refs/heads/main")
    assert main.matches(make_claims())
    assert not main.matches(make_claims(ref="refs/heads/main-branch"))
    assert not main.matches(make_claims(ref="refs/heads/develop"))
    tags = make_project(ref="refs/tags/")
    assert tags.matches(make_claims(ref="refs/tags/v1.0"))
    assert not tags.matches(make_claims(ref="refs/tags"))
    assert not tags.matches(make_claims(ref="refs/heads/main"))

    # Every constraint must be satisfied at once.
    narrow = make_project(
        workflow=".github/workflows/docs.yaml",
        environment="production",
        ref="refs/heads/main",
    )
    assert narrow.matches(make_claims(environment="production"))
    assert not narrow.matches(make_claims())
    assert not narrow.matches(
        make_claims(environment="production", ref="refs/heads/develop")
    )


def test_overlaps() -> None:
    base = make_project()
    assert base.overlaps(make_project("LSST-SQRE/SQR-062"))
    assert not base.overlaps(make_project("lsst-sqre/other"))

    # Any unset constraint matches anything.
    narrow = make_project(
        workflow=".github/workflows/docs.yaml",
        environment="production",
        ref="refs/heads/main",
    )
    assert base.overlaps(narrow)
    assert narrow.overlaps(base)

    # Workflows are compared as full paths, with the repository part
    # case-insensitive.
    full = make_project(
        "LSST-SQRE/SQR-062",
        workflow="lsst-sqre/sqr-062/.github/workflows/docs.yaml",
    )
    assert narrow.overlaps(full)
    other = make_project(workflow=".github/workflows/ci.yaml")
    assert not narrow.overlaps(other)
    reusable = make_project(
        workflow="lsst-sqre/shared/.github/workflows/docs.yaml"
    )
    assert not narrow.overlaps(reusable)

    # Environments must match exactly.
    assert not narrow.overlaps(make_project(environment="staging"))

    # Refs may be prefixes.
    assert not narrow.overlaps(make_project(ref="refs/heads/develop"))
    assert narrow.overlaps(make_project(ref="refs/heads/"))
    assert make_project(ref="refs/heads/").overlaps(narrow)
    assert not narrow.overlaps(make_project(ref="refs/tags/"))
    assert make_project(ref="refs/tags/").overlaps(
        make_project(ref="refs/tags/v1.0")
    )
    assert not make_project(ref="refs/heads/main").overlaps(
        make_project(ref="refs/heads/main-branch")
    )

    # Create models can be compared too.
    create = GitHubProjectCreate(
        repository="lsst-sqre/sqr-062",
        scopes=set(),
        workflow=".github/workflows/docs.yaml",
        ref="refs/tags/",
    )
    assert not narrow.overlaps(create)
    assert base.overlaps(create)


def test_field_lengths() -> None:
    # Length limits are enforced as well as patterns.
    long_name = "a" * 138
    create = GitHubProjectCreate(repository=f"o/{long_name}", scopes=set())
    assert create.repository == f"o/{long_name}"
    with pytest.raises(ValidationError):
        GitHubProjectCreate(repository=f"o/{long_name}a", scopes=set())
    username = "bot-gh-" + "a" * 57
    create = GitHubProjectCreate(
        repository="lsst-sqre/sqr-062", scopes=set(), username=username
    )
    assert create.username == username
    with pytest.raises(ValidationError):
        GitHubProjectCreate(
            repository="lsst-sqre/sqr-062",
            scopes=set(),
            username=username + "a",
        )
    with pytest.raises(ValidationError):
        GitHubProjectUpdate(requested_by="a" * 257)
    with pytest.raises(ValidationError):
        GitHubProjectUpdate(requested_by="")


def test_filter_constraints() -> None:
    """The list filters must enforce the same constraints as the models.

    The filters are declared separately from the model fields in the API
    handler, so check the generated OpenAPI schema to catch any drift
    between them.
    """
    schema = json.loads(create_openapi())
    route = schema["paths"]["/auth/api/v1/github/projects"]["get"]
    filters = {p["name"]: p["schema"] for p in route["parameters"]}
    fields = schema["components"]["schemas"]["GitHubProject"]["properties"]

    def string_schema(schema: dict[str, Any]) -> dict[str, Any]:
        """Extract the string branch of a possibly nullable schema."""
        for option in schema.get("anyOf", [schema]):
            if option.get("type") == "string":
                return option
        raise AssertionError(f"No string schema in {schema}")

    for name in ("repository", "username", "template", "requested_by"):
        expected = string_schema(fields[name])
        actual = string_schema(filters[name])
        for constraint in ("minLength", "maxLength", "pattern"):
            assert actual.get(constraint) == expected.get(constraint), (
                f"{name} filter {constraint} differs from the model"
            )

    # The template field of a project must in turn match the name of a
    # template, since it is a reference to one.
    templates = schema["components"]["schemas"]["GitHubProjectTemplate"]
    expected = string_schema(templates["properties"]["name"])
    actual = string_schema(fields["template"])
    for constraint in ("minLength", "maxLength", "pattern"):
        assert actual.get(constraint) == expected.get(constraint)
