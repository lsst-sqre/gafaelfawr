"""Tests for GitHub project templates and provisioning."""

from datetime import timedelta
from unittest.mock import ANY

import pytest
import respx
from pydantic import ValidationError

from gafaelfawr.config import Config
from gafaelfawr.exceptions import (
    DuplicateGitHubProjectTemplateError,
    GitHubProjectOverlapError,
    GitHubProjectTemplateDisabledError,
    GitHubProjectTemplateInUseError,
    GitHubRepositoryNotAllowedError,
    InvalidMaxLifetimeError,
    InvalidScopesError,
    NotFoundError,
    PermissionDeniedError,
    UnknownGitHubOwnerError,
    UnknownGitHubRepositoryError,
)
from gafaelfawr.factory import Factory
from gafaelfawr.models.enums import GitHubProjectChange
from gafaelfawr.models.github import GitHubRepository
from gafaelfawr.models.github_project import (
    GitHubOwner,
    GitHubProjectCreate,
    GitHubProjectProvision,
    GitHubProjectTemplateCreate,
    GitHubProjectTemplateUpdate,
)
from gafaelfawr.models.token import TokenData
from gafaelfawr.models.userinfo import Group
from gafaelfawr.storage.github_project import GitHubProjectHistoryStore

from ..support.github import mock_github_owners, mock_github_repositories
from ..support.tokens import create_session_token
from ..support.util import assert_is_now

LSST_SQRE = GitHubOwner(name="lsst-sqre", id=654321)
LSST_DM = GitHubOwner(name="lsst-dm", id=765432)
LSST = GitHubOwner(name="lsst", id=876543)

SQR_120 = GitHubRepository(
    full_name="lsst-sqre/sqr-120", id=123456, owner_id=LSST_SQRE.id
)
SQR_062 = GitHubRepository(
    full_name="lsst-sqre/sqr-062", id=123457, owner_id=LSST_SQRE.id
)
DMTN_300 = GitHubRepository(
    full_name="lsst-dm/DMTN-300", id=234567, owner_id=LSST_DM.id
)
OOK = GitHubRepository(
    full_name="lsst-sqre/ook", id=345678, owner_id=LSST_SQRE.id
)
LDM_151 = GitHubRepository(
    full_name="lsst/ldm-151", id=456789, owner_id=LSST.id
)
IMPOSTOR_SQR = GitHubRepository(
    full_name="lsst-sqre/sqr-999", id=567890, owner_id=999999
)

TECHNOTE_WORKFLOW = (
    "lsst-sqre/rubin-sphinx-technote-workflows/.github/workflows/ci.yaml"
)


async def create_admin(factory: Factory) -> TokenData:
    return await create_session_token(
        factory, username="some-admin", scopes={"admin:token"}
    )


async def create_provisioner(factory: Factory) -> TokenData:
    return await create_session_token(
        factory,
        username="bot-templatebot",
        scopes={"admin:github-oidc-provision"},
    )


def technote_template(**kwargs: object) -> GitHubProjectTemplateCreate:
    fields: dict[str, object] = {
        "name": "technote",
        "description": "Documentation builds for technotes",
        "owners": ["lsst-sqre", "lsst-dm"],
        "repository_pattern": "^[a-z]+-[0-9]{3,}$",
        "workflow": TECHNOTE_WORKFLOW,
        "scopes": {"read:all", "exec:test"},
        "max_lifetime": timedelta(minutes=30),
    }
    fields.update(kwargs)
    return GitHubProjectTemplateCreate.model_validate(fields)


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_create_template(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    mock = mock_github_owners(respx_mock, [LSST_SQRE, LSST_DM])
    admin = await create_admin(factory)

    # Owners are given in any case and stored as GitHub reports them, with
    # their IDs pinned.
    create = technote_template(owners=["LSST-SQRE", "lsst-dm"])
    template = await service.create_template(
        create, admin, ip_address="127.0.0.1"
    )
    assert template.name == "technote"
    assert template.description == "Documentation builds for technotes"
    assert template.owners == [LSST_SQRE, LSST_DM]
    assert template.repository_pattern == "^[a-z]+-[0-9]{3,}$"
    assert template.workflow == TECHNOTE_WORKFLOW
    assert template.environment is None
    assert template.ref is None
    assert template.scopes == {"exec:test", "read:all"}
    assert template.max_lifetime == timedelta(minutes=30)
    assert template.uid is None
    assert template.gid is None
    assert template.groups is None
    assert template.enabled
    assert_is_now(template.created)
    assert template.created_by == "some-admin"
    assert template.modified == template.created
    assert template.modified_by == "some-admin"
    assert mock.requests == 2

    # The stored template matches what was returned.
    assert await service.get_template("technote", admin) == template
    assert await service.list_templates(admin) == [template]

    # The creation was recorded in the history as a template change.
    history_store = GitHubProjectHistoryStore(factory.session)
    async with factory.session.begin():
        history = await history_store.list(template="technote")
    assert len(history) == 1
    assert history[0].model_dump() == {
        "project_id": None,
        "template": "technote",
        "action": GitHubProjectChange.create,
        "actor": "some-admin",
        "ip_address": "127.0.0.1",
        "event_time": ANY,
        "old_values": None,
        "new_values": template.model_dump(mode="json"),
    }
    assert history[0].new_values
    assert history[0].new_values["owners"] == [
        {"name": "lsst-sqre", "id": LSST_SQRE.id},
        {"name": "lsst-dm", "id": LSST_DM.id},
    ]
    assert history[0].new_values["max_lifetime"] == "PT30M"

    # A minimal template defaults the lifetime, and may carry identity
    # attributes and be disabled. Templates are listed by name.
    create = GitHubProjectTemplateCreate(
        name="minimal",
        owners=["lsst-dm"],
        scopes=set(),
        uid=100000,
        gid=100000,
        groups=[Group(name="bots", id=100000)],
        enabled=False,
    )
    minimal = await service.create_template(create, admin, ip_address=None)
    assert minimal.owners == [LSST_DM]
    assert minimal.repository_pattern is None
    assert minimal.max_lifetime == timedelta(hours=1)
    assert minimal.groups == [Group(name="bots", id=100000)]
    assert not minimal.enabled
    assert await service.list_templates(admin) == [minimal, template]
    async with factory.session.begin():
        history = await history_store.list(template="minimal")
    assert len(history) == 1
    assert history[0].ip_address is None


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_create_template_errors(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    mock = mock_github_owners(respx_mock, [LSST_SQRE, LSST_DM])
    admin = await create_admin(factory)
    user = await create_session_token(factory, scopes={"user:token"})
    provisioner = await create_provisioner(factory)

    # Neither a regular user nor a provisioner may manage templates.
    for data in (user, provisioner):
        with pytest.raises(PermissionDeniedError):
            await service.create_template(
                technote_template(), data, ip_address=None
            )
        with pytest.raises(PermissionDeniedError):
            await service.list_templates(data)
    assert mock.requests == 0

    # Unknown owners are refused.
    with pytest.raises(UnknownGitHubOwnerError) as excinfo:
        await service.create_template(
            technote_template(owners=["lsst-sqre", "lsst-nope"]),
            admin,
            ip_address=None,
        )
    assert str(excinfo.value) == "GitHub owner lsst-nope not found"
    assert await service.list_templates(admin) == []

    # Unknown and reserved scopes are refused, including the provisioning
    # scope itself, so that no workflow can obtain a token that provisions
    # projects.
    with pytest.raises(InvalidScopesError) as scopes_exc:
        await service.create_template(
            technote_template(scopes={"read:all", "read:nope"}),
            admin,
            ip_address=None,
        )
    assert str(scopes_exc.value) == "Unknown scopes: read:nope"
    with pytest.raises(InvalidScopesError) as scopes_exc:
        await service.create_template(
            technote_template(scopes={"admin:github-oidc-provision"}),
            admin,
            ip_address=None,
        )
    assert str(scopes_exc.value) == (
        "Reserved scopes not allowed: admin:github-oidc-provision"
    )

    # The maximum lifetime is bounded.
    with pytest.raises(InvalidMaxLifetimeError):
        await service.create_template(
            technote_template(max_lifetime=timedelta(days=1)),
            admin,
            ip_address=None,
        )
    with pytest.raises(InvalidMaxLifetimeError):
        await service.create_template(
            technote_template(max_lifetime=timedelta(seconds=10)),
            admin,
            ip_address=None,
        )

    # Validation of the request itself: duplicate owners, invalid names,
    # and an invalid regular expression.
    with pytest.raises(ValidationError, match="Duplicate owner"):
        technote_template(owners=["lsst-sqre", "LSST-SQRE"])
    with pytest.raises(ValidationError):
        technote_template(owners=[])
    with pytest.raises(ValidationError):
        technote_template(owners=["-bad"])
    with pytest.raises(ValidationError):
        technote_template(name="Technote")
    with pytest.raises(ValidationError, match="regular expression"):
        technote_template(repository_pattern="^[a-z")
    with pytest.raises(ValidationError):
        technote_template(workflow="docs.yaml")

    # Duplicate names are refused, and nothing above created a template.
    await service.create_template(technote_template(), admin, ip_address=None)
    with pytest.raises(DuplicateGitHubProjectTemplateError) as dup_exc:
        await service.create_template(
            technote_template(owners=["lsst-dm"]), admin, ip_address=None
        )
    assert str(dup_exc.value) == (
        "GitHub project template technote already exists"
    )
    assert len(await service.list_templates(admin)) == 1

    # Getting an unknown template fails.
    with pytest.raises(NotFoundError):
        await service.get_template("nope", admin)


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_update_template(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    mock = mock_github_owners(respx_mock, [LSST_SQRE, LSST_DM, LSST])
    admin = await create_admin(factory)
    history_store = GitHubProjectHistoryStore(factory.session)
    template = await service.create_template(
        technote_template(), admin, ip_address=None
    )
    assert mock.requests == 2

    # Change several fields, clear an optional one, and keep the rest.
    update = GitHubProjectTemplateUpdate(
        description="Updated",
        repository_pattern=None,
        ref="refs/heads/main",
        scopes={"read:all"},
        max_lifetime=timedelta(minutes=15),
        enabled=False,
    )
    new = await service.update_template(
        "technote", update, admin, ip_address="127.0.0.1"
    )
    assert new.description == "Updated"
    assert new.owners == template.owners
    assert new.repository_pattern is None
    assert new.workflow == TECHNOTE_WORKFLOW
    assert new.ref == "refs/heads/main"
    assert new.scopes == {"read:all"}
    assert new.max_lifetime == timedelta(minutes=15)
    assert not new.enabled
    assert new.created == template.created
    assert new.modified >= template.modified
    assert_is_now(new.modified)
    assert new.modified_by == "some-admin"
    assert await service.get_template("technote", admin) == new
    assert mock.requests == 2
    async with factory.session.begin():
        history = await history_store.list(template="technote")
    assert len(history) == 2
    assert history[1].model_dump() == {
        "project_id": None,
        "template": "technote",
        "action": GitHubProjectChange.modify,
        "actor": "some-admin",
        "ip_address": "127.0.0.1",
        "event_time": ANY,
        "old_values": template.model_dump(mode="json"),
        "new_values": new.model_dump(mode="json"),
    }

    # Changing the owners looks up only the new owner. An owner that stays
    # in the list keeps its pinned ID even if GitHub now reports a
    # different one for that name, and may be re-sent in any case.
    mock.owners["lsst-sqre"] = GitHubOwner(name="lsst-sqre", id=1)
    update = GitHubProjectTemplateUpdate(owners=["lsst", "LSST-SQRE"])
    newer = await service.update_template(
        "technote", update, admin, ip_address=None
    )
    assert newer.owners == [LSST, LSST_SQRE]
    assert mock.requests == 3
    async with factory.session.begin():
        history = await history_store.list(template="technote")
    assert len(history) == 3
    assert history[2].old_values == new.model_dump(mode="json")
    assert history[2].new_values == newer.model_dump(mode="json")

    # Updates that change nothing are not recorded and do not touch the
    # modification metadata, including re-sending the owners in another
    # order of case.
    for update in (
        GitHubProjectTemplateUpdate(),
        GitHubProjectTemplateUpdate(description="Updated", enabled=False),
        GitHubProjectTemplateUpdate(owners=["LSST", "lsst-sqre"]),
        GitHubProjectTemplateUpdate(repository_pattern=None),
    ):
        assert (
            await service.update_template(
                "technote", update, admin, ip_address=None
            )
            == newer
        )
    assert mock.requests == 3
    async with factory.session.begin():
        history = await history_store.list(template="technote")
    assert len(history) == 3


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_update_template_errors(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    mock_github_owners(respx_mock, [LSST_SQRE, LSST_DM])
    admin = await create_admin(factory)
    user = await create_session_token(factory, scopes={"user:token"})
    provisioner = await create_provisioner(factory)
    await service.create_template(technote_template(), admin, ip_address=None)
    update = GitHubProjectTemplateUpdate(description="Changed")

    for data in (user, provisioner):
        with pytest.raises(PermissionDeniedError):
            await service.update_template(
                "technote", update, data, ip_address=None
            )
    with pytest.raises(NotFoundError):
        await service.update_template("nope", update, admin, ip_address=None)
    with pytest.raises(UnknownGitHubOwnerError):
        await service.update_template(
            "technote",
            GitHubProjectTemplateUpdate(owners=["lsst-sqre", "lsst-nope"]),
            admin,
            ip_address=None,
        )
    with pytest.raises(InvalidScopesError):
        await service.update_template(
            "technote",
            GitHubProjectTemplateUpdate(scopes={"admin:token"}),
            admin,
            ip_address=None,
        )
    with pytest.raises(InvalidMaxLifetimeError):
        await service.update_template(
            "technote",
            GitHubProjectTemplateUpdate(max_lifetime=timedelta(days=2)),
            admin,
            ip_address=None,
        )

    # Required fields cannot be set to null.
    for field in ("owners", "scopes", "max_lifetime", "enabled"):
        with pytest.raises(ValidationError, match=f"{field} may not be null"):
            GitHubProjectTemplateUpdate.model_validate({field: None})

    # Nothing above changed the template.
    template = await service.get_template("technote", admin)
    assert template.description == "Documentation builds for technotes"
    history_store = GitHubProjectHistoryStore(factory.session)
    async with factory.session.begin():
        history = await history_store.list(template="technote")
    assert len(history) == 1


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_delete_template(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    mock_github_owners(respx_mock, [LSST_SQRE, LSST_DM])
    mock_github_repositories(respx_mock, [SQR_120, DMTN_300])
    admin = await create_admin(factory)
    user = await create_session_token(factory, scopes={"user:token"})
    provisioner = await create_provisioner(factory)
    history_store = GitHubProjectHistoryStore(factory.session)
    template = await service.create_template(
        technote_template(), admin, ip_address=None
    )

    with pytest.raises(PermissionDeniedError):
        await service.delete_template("technote", user, ip_address=None)
    with pytest.raises(PermissionDeniedError):
        await service.delete_template("technote", provisioner, ip_address=None)
    with pytest.raises(NotFoundError):
        await service.delete_template("nope", admin, ip_address=None)

    # A template with provisioned projects cannot be deleted, even after it
    # is disabled, and the error gives the number of projects.
    for repository in ("lsst-sqre/sqr-120", "lsst-dm/dmtn-300"):
        await service.provision_project(
            "technote",
            GitHubProjectProvision(repository=repository),
            provisioner,
            ip_address=None,
        )
    with pytest.raises(GitHubProjectTemplateInUseError) as excinfo:
        await service.delete_template("technote", admin, ip_address=None)
    assert excinfo.value.count == 2
    assert str(excinfo.value) == (
        "GitHub project template technote is used by 2 projects and cannot"
        " be deleted, disable it instead"
    )
    await service.update_template(
        "technote",
        GitHubProjectTemplateUpdate(enabled=False),
        admin,
        ip_address=None,
    )
    with pytest.raises(GitHubProjectTemplateInUseError):
        await service.delete_template("technote", admin, ip_address=None)

    # Once the projects are gone, the template can be deleted, and its
    # deletion is recorded in the history. The project history entries
    # that name the template remain.
    projects = await service.list_projects(admin, template="technote")
    for project in projects:
        await service.delete_project(project.id, admin, ip_address=None)

    # Re-provision one project to check the singular message.
    await service.update_template(
        "technote",
        GitHubProjectTemplateUpdate(enabled=True),
        admin,
        ip_address=None,
    )
    await service.provision_project(
        "technote",
        GitHubProjectProvision(repository="lsst-sqre/sqr-120"),
        admin,
        ip_address=None,
    )
    with pytest.raises(GitHubProjectTemplateInUseError) as single_exc:
        await service.delete_template("technote", admin, ip_address=None)
    assert single_exc.value.count == 1
    assert "used by 1 project and" in str(single_exc.value)
    projects = await service.list_projects(admin, template="technote")
    for project in projects:
        await service.delete_project(project.id, admin, ip_address=None)

    disabled = await service.update_template(
        "technote",
        GitHubProjectTemplateUpdate(enabled=False),
        admin,
        ip_address=None,
    )
    await service.delete_template("technote", admin, ip_address="127.0.0.1")
    with pytest.raises(NotFoundError):
        await service.get_template("technote", admin)
    assert await service.list_templates(admin) == []
    async with factory.session.begin():
        history = await history_store.list(template="technote")
    assert history[-1].model_dump() == {
        "project_id": None,
        "template": "technote",
        "action": GitHubProjectChange.delete,
        "actor": "some-admin",
        "ip_address": "127.0.0.1",
        "event_time": ANY,
        "old_values": disabled.model_dump(mode="json"),
        "new_values": None,
    }
    template_entries = [e for e in history if e.project_id is None]
    project_entries = [e for e in history if e.project_id is not None]
    assert [e.action for e in template_entries] == [
        GitHubProjectChange.create,
        GitHubProjectChange.modify,
        GitHubProjectChange.modify,
        GitHubProjectChange.modify,
        GitHubProjectChange.delete,
    ]
    assert len(project_entries) == 6
    assert template.name == "technote"


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_provision_project(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    mock_github_owners(respx_mock, [LSST_SQRE, LSST_DM])
    mock = mock_github_repositories(respx_mock, [SQR_120, DMTN_300])
    admin = await create_admin(factory)
    provisioner = await create_provisioner(factory)
    history_store = GitHubProjectHistoryStore(factory.session)
    template = await service.create_template(
        technote_template(
            uid=100000, groups=[Group(name="technotes", id=100000)]
        ),
        admin,
        ip_address=None,
    )

    # The project copies the template's fields, derives its username, pins
    # the repository IDs, records the template, and names the provisioner
    # rather than the requester as its creator.
    provision = GitHubProjectProvision(
        repository="LSST-SQRE/SQR-120",
        description="Created by Templatebot for Someone",
        requested_by="slack:U024BE7LH",
    )
    project, created = await service.provision_project(
        "technote", provision, provisioner, ip_address="198.51.100.5"
    )
    assert created
    assert project.id
    assert project.template == "technote"
    assert project.description == "Created by Templatebot for Someone"
    assert project.requested_by == "slack:U024BE7LH"
    assert project.username == "bot-gh-lsst-sqre-sqr-120"
    assert project.repository == "lsst-sqre/sqr-120"
    assert project.repository_id == SQR_120.id
    assert project.repository_owner_id == SQR_120.owner_id
    assert project.workflow == TECHNOTE_WORKFLOW
    assert project.environment is None
    assert project.ref is None
    assert project.scopes == template.scopes
    assert project.max_lifetime == template.max_lifetime
    assert project.uid == 100000
    assert project.gid is None
    assert project.groups == [Group(name="technotes", id=100000)]
    assert project.enabled
    assert_is_now(project.created)
    assert project.created_by == "bot-templatebot"
    assert project.modified_by == "bot-templatebot"
    assert mock.requests == 1
    assert await service.get_project(project.id, admin) == project
    assert await service.list_projects(admin, template="technote") == [project]
    async with factory.session.begin():
        history = await history_store.list(project_id=project.id)
    assert len(history) == 1
    assert history[0].model_dump() == {
        "project_id": project.id,
        "template": "technote",
        "action": GitHubProjectChange.create,
        "actor": "bot-templatebot",
        "ip_address": "198.51.100.5",
        "event_time": ANY,
        "old_values": None,
        "new_values": project.model_dump(mode="json"),
    }

    # The template's history lists its own changes and its projects.
    async with factory.session.begin():
        history = await history_store.list(template="technote")
    assert [(e.project_id, e.action) for e in history] == [
        (None, GitHubProjectChange.create),
        (project.id, GitHubProjectChange.create),
    ]

    # Provisioning again for the same repository returns the existing
    # project unchanged, regardless of case or descriptive fields, and
    # records nothing.
    again = GitHubProjectProvision(
        repository="lsst-sqre/sqr-120", requested_by="slack:UOTHER"
    )
    assert await service.provision_project(
        "technote", again, provisioner, ip_address=None
    ) == (project, False)
    assert mock.requests == 2
    async with factory.session.begin():
        history = await history_store.list(template="technote")
    assert len(history) == 2

    # Token administrators may provision too, and a template with an
    # uppercase repository pattern match works case-insensitively.
    other, created = await service.provision_project(
        "technote",
        GitHubProjectProvision(repository="lsst-dm/dmtn-300"),
        admin,
        ip_address=None,
    )
    assert created
    assert other.repository == "lsst-dm/DMTN-300"
    assert other.username == "bot-gh-lsst-dm-dmtn-300"
    assert other.created_by == "some-admin"
    assert other.template == "technote"
    assert await service.list_projects(admin, template="technote") == [
        project,
        other,
    ]

    # A later change to the template does not touch provisioned projects.
    await service.update_template(
        "technote",
        GitHubProjectTemplateUpdate(scopes=set()),
        admin,
        ip_address=None,
    )
    assert await service.get_project(project.id, admin) == project


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_provision_project_errors(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    mock_github_owners(respx_mock, [LSST_SQRE, LSST_DM, LSST])
    mock = mock_github_repositories(
        respx_mock, [SQR_120, SQR_062, OOK, LDM_151, IMPOSTOR_SQR]
    )
    admin = await create_admin(factory)
    provisioner = await create_provisioner(factory)
    user = await create_session_token(factory, scopes={"user:token"})
    await service.create_template(technote_template(), admin, ip_address=None)
    provision = GitHubProjectProvision(repository="lsst-sqre/sqr-120")

    # Only admin:token or the provisioning scope may provision.
    with pytest.raises(PermissionDeniedError):
        await service.provision_project(
            "technote", provision, user, ip_address=None
        )
    assert mock.requests == 0

    # Unknown templates fail before talking to GitHub.
    with pytest.raises(NotFoundError):
        await service.provision_project(
            "nope", provision, provisioner, ip_address=None
        )
    assert mock.requests == 0

    # The owner must be in the template's list by name...
    with pytest.raises(GitHubRepositoryNotAllowedError) as excinfo:
        await service.provision_project(
            "technote",
            GitHubProjectProvision(repository="lsst/ldm-151"),
            provisioner,
            ip_address=None,
        )
    assert str(excinfo.value) == (
        "Owner lsst of repository lsst/ldm-151 is not allowed by GitHub"
        " project template technote"
    )

    # ...and by pinned ID, so a re-registered owner name is not trusted.
    with pytest.raises(GitHubRepositoryNotAllowedError) as excinfo:
        await service.provision_project(
            "technote",
            GitHubProjectProvision(repository="lsst-sqre/sqr-999"),
            provisioner,
            ip_address=None,
        )
    assert str(excinfo.value) == (
        "Owner lsst-sqre of repository lsst-sqre/sqr-999 is not allowed by"
        " GitHub project template technote"
    )

    # The repository name must match the pattern.
    with pytest.raises(GitHubRepositoryNotAllowedError) as excinfo:
        await service.provision_project(
            "technote",
            GitHubProjectProvision(repository="lsst-sqre/ook"),
            provisioner,
            ip_address=None,
        )
    assert str(excinfo.value) == (
        "Name ook of repository lsst-sqre/ook does not match the repository"
        " pattern of GitHub project template technote"
    )

    # Unknown repositories are refused as for the admin API.
    with pytest.raises(UnknownGitHubRepositoryError):
        await service.provision_project(
            "technote",
            GitHubProjectProvision(repository="lsst-sqre/sqr-000"),
            provisioner,
            ip_address=None,
        )
    assert await service.list_projects(admin) == []

    # A project for the same repository created by hand, or from another
    # template, conflicts as usual rather than being returned.
    manual = await service.create_project(
        GitHubProjectCreate(repository="lsst-sqre/sqr-120", scopes=set()),
        admin,
        ip_address=None,
    )
    with pytest.raises(GitHubProjectOverlapError) as overlap_exc:
        await service.provision_project(
            "technote", provision, provisioner, ip_address=None
        )
    assert overlap_exc.value.project_id == manual.id
    await service.create_template(
        technote_template(name="other", owners=["lsst-sqre"]),
        admin,
        ip_address=None,
    )
    other, created = await service.provision_project(
        "other",
        GitHubProjectProvision(repository="lsst-sqre/sqr-062"),
        provisioner,
        ip_address=None,
    )
    assert created
    with pytest.raises(GitHubProjectOverlapError) as overlap_exc:
        await service.provision_project(
            "technote",
            GitHubProjectProvision(repository="lsst-sqre/sqr-062"),
            provisioner,
            ip_address=None,
        )
    assert overlap_exc.value.project_id == other.id

    # A disabled template cannot be used, even for a repository that
    # already has a project from it, and the check happens before talking
    # to GitHub.
    requests = mock.requests
    await service.update_template(
        "other",
        GitHubProjectTemplateUpdate(enabled=False),
        admin,
        ip_address=None,
    )
    with pytest.raises(GitHubProjectTemplateDisabledError) as disabled_exc:
        await service.provision_project(
            "other",
            GitHubProjectProvision(repository="lsst-sqre/sqr-062"),
            provisioner,
            ip_address=None,
        )
    assert str(disabled_exc.value) == (
        "GitHub project template other is disabled"
    )
    assert mock.requests == requests

    # A provisioner cannot otherwise touch projects or templates.
    with pytest.raises(PermissionDeniedError):
        await service.get_project(other.id, provisioner)
    with pytest.raises(PermissionDeniedError):
        await service.list_projects(provisioner)
    with pytest.raises(PermissionDeniedError):
        await service.get_template("technote", provisioner)
    with pytest.raises(PermissionDeniedError):
        await service.delete_project(other.id, provisioner, ip_address=None)
