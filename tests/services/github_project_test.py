"""Tests for the GitHub project registry service."""

from datetime import timedelta
from unittest.mock import ANY

import pytest
import respx

from gafaelfawr.config import Config
from gafaelfawr.exceptions import (
    DuplicateGitHubUsernameError,
    GitHubProjectOverlapError,
    InvalidGitHubUsernameError,
    InvalidMaxLifetimeError,
    InvalidScopesError,
    NotConfiguredError,
    NotFoundError,
    PermissionDeniedError,
    UnknownGitHubRepositoryError,
)
from gafaelfawr.factory import Factory
from gafaelfawr.models.enums import GitHubProjectChange, TokenChange
from gafaelfawr.models.github import GitHubRepository
from gafaelfawr.models.github_project import (
    GitHubProjectCreate,
    GitHubProjectUpdate,
)
from gafaelfawr.models.token import TokenData
from gafaelfawr.models.userinfo import Group
from gafaelfawr.storage.github_project import GitHubProjectHistoryStore

from ..support.github import mock_github_repositories
from ..support.tokens import add_github_token, create_session_token
from ..support.util import assert_is_now

SQR_062 = GitHubRepository(
    full_name="lsst-sqre/sqr-062", id=123456, owner_id=654321
)
OOK = GitHubRepository(full_name="lsst-sqre/ook", id=234567, owner_id=654321)
DOCS = GitHubRepository(full_name="lsst-sqre/docs", id=345678, owner_id=654321)
SQRE_DOCS = GitHubRepository(
    full_name="lsst/sqre-docs", id=456780, owner_id=765432
)
MIXED_CASE = GitHubRepository(
    full_name="LSST-SQRE/Mixed.Case_Repo", id=456789, owner_id=654321
)


async def create_admin(factory: Factory) -> TokenData:
    return await create_session_token(
        factory, username="some-admin", scopes={"admin:token"}
    )


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_create_project(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    mock = mock_github_repositories(respx_mock, [SQR_062, MIXED_CASE])
    admin = await create_admin(factory)

    create = GitHubProjectCreate(
        description="Documentation builds for SQR-062",
        requested_by="slack:U024BE7LH",
        repository="LSST-SQRE/SQR-062",
        workflow=".github/workflows/docs.yaml",
        ref="refs/heads/main",
        scopes={"read:all", "exec:test"},
        max_lifetime=timedelta(minutes=15),
    )
    project = await service.create_project(
        create, admin, ip_address="127.0.0.1"
    )
    assert project.id
    assert project.template is None
    assert project.description == "Documentation builds for SQR-062"
    assert project.requested_by == "slack:U024BE7LH"
    assert project.username == "bot-gh-lsst-sqre-sqr-062"
    assert project.repository == "lsst-sqre/sqr-062"
    assert project.repository_id == SQR_062.id
    assert project.repository_owner_id == SQR_062.owner_id
    assert project.workflow == ".github/workflows/docs.yaml"
    assert project.environment is None
    assert project.ref == "refs/heads/main"
    assert project.scopes == {"exec:test", "read:all"}
    assert project.max_lifetime == timedelta(minutes=15)
    assert project.uid is None
    assert project.gid is None
    assert project.groups is None
    assert project.enabled
    assert_is_now(project.created)
    assert project.created_by == "some-admin"
    assert project.modified == project.created
    assert project.modified_by == "some-admin"
    assert mock.requests == 1

    # The stored project matches what was returned.
    assert await service.get_project(project.id, admin) == project
    assert await service.list_projects(admin) == [project]

    # The creation was recorded in the history.
    history_store = GitHubProjectHistoryStore(factory.session)
    async with factory.session.begin():
        history = await history_store.list(project_id=project.id)
    assert len(history) == 1
    assert history[0].model_dump() == {
        "project_id": project.id,
        "template": None,
        "action": GitHubProjectChange.create,
        "actor": "some-admin",
        "ip_address": "127.0.0.1",
        "event_time": ANY,
        "old_values": None,
        "new_values": project.model_dump(mode="json"),
    }
    assert_is_now(history[0].event_time)
    assert history[0].new_values
    assert history[0].new_values["max_lifetime"] == "PT15M"
    assert history[0].new_values["scopes"] == ["exec:test", "read:all"]

    # An explicit username, identity attributes, and a disabled project.
    create = GitHubProjectCreate(
        username="bot-gh-mixed",
        repository="lsst-sqre/mixed.case_repo",
        environment="production",
        scopes=set(),
        uid=100000,
        gid=100000,
        groups=[Group(name="bot-gh-mixed", id=100000)],
        enabled=False,
    )
    project = await service.create_project(create, admin, ip_address=None)
    assert project.username == "bot-gh-mixed"
    assert project.repository == "LSST-SQRE/Mixed.Case_Repo"
    assert project.repository_id == MIXED_CASE.id
    assert project.scopes == set()
    assert project.max_lifetime == timedelta(hours=1)
    assert project.uid == 100000
    assert project.gid == 100000
    assert project.groups == [Group(name="bot-gh-mixed", id=100000)]
    assert not project.enabled
    assert await service.get_project(project.id, admin) == project
    async with factory.session.begin():
        history = await history_store.list(project_id=project.id)
    assert len(history) == 1
    assert history[0].ip_address is None

    # The username derived from a repository with characters that are not
    # valid in a username is sanitized.
    create = GitHubProjectCreate(
        repository="lsst-sqre/mixed.case_repo",
        scopes=set(),
        environment="staging",
    )
    project = await service.create_project(create, admin, ip_address=None)
    assert project.username == "bot-gh-lsst-sqre-mixed-case-repo"


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_create_project_errors(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    mock = mock_github_repositories(respx_mock, [SQR_062, DOCS, SQRE_DOCS])
    admin = await create_admin(factory)
    user = await create_session_token(factory, scopes={"user:token"})
    create = GitHubProjectCreate(
        repository="lsst-sqre/sqr-062", scopes={"read:all"}
    )

    # Permission denied before anything else is checked.
    with pytest.raises(PermissionDeniedError):
        await service.create_project(create, user, ip_address=None)

    # Scopes must be known and not reserved.
    bad = create.model_copy(update={"scopes": {"read:all", "bogus:scope"}})
    with pytest.raises(InvalidScopesError, match="bogus:scope"):
        await service.create_project(bad, admin, ip_address=None)
    bad = create.model_copy(update={"scopes": {"admin:token", "read:all"}})
    with pytest.raises(InvalidScopesError, match="admin:token"):
        await service.create_project(bad, admin, ip_address=None)
    bad = create.model_copy(update={"scopes": {"admin:userinfo"}})
    with pytest.raises(InvalidScopesError, match="admin:userinfo"):
        await service.create_project(bad, admin, ip_address=None)

    # Lifetime must be within the configured bounds (default 6h cap).
    bad = create.model_copy(update={"max_lifetime": timedelta(minutes=4)})
    with pytest.raises(InvalidMaxLifetimeError, match="at least 300s"):
        await service.create_project(bad, admin, ip_address=None)
    bad = create.model_copy(update={"max_lifetime": timedelta(hours=7)})
    with pytest.raises(InvalidMaxLifetimeError, match="at most 21600s"):
        await service.create_project(bad, admin, ip_address=None)
    assert mock.requests == 0

    # Unknown (or private) repositories are rejected.
    bad = create.model_copy(update={"repository": "lsst-sqre/private"})
    with pytest.raises(UnknownGitHubRepositoryError):
        await service.create_project(bad, admin, ip_address=None)
    assert await service.list_projects(admin) == []

    # Overlapping constraints are refused, naming the conflicting project.
    first = await service.create_project(
        create.model_copy(update={"ref": "refs/heads/main"}),
        admin,
        ip_address=None,
    )
    overlapping = create.model_copy(update={"ref": "refs/heads/"})
    with pytest.raises(GitHubProjectOverlapError) as excinfo:
        await service.create_project(overlapping, admin, ip_address=None)
    assert excinfo.value.project_id == first.id
    assert str(excinfo.value) == (
        f"Constraints overlap GitHub project {first.id} for lsst-sqre/sqr-062"
    )
    with pytest.raises(GitHubProjectOverlapError):
        await service.create_project(create, admin, ip_address=None)

    # Disjoint constraints for the same repository are fine and share the
    # derived username.
    second = await service.create_project(
        create.model_copy(update={"ref": "refs/pull/"}),
        admin,
        ip_address=None,
    )
    assert second.username == first.username

    # A derived username already used for a different repository is
    # refused, since lsst-sqre/docs and lsst/sqre-docs both derive the same
    # username, but an explicit one may be shared deliberately.
    docs = await service.create_project(
        GitHubProjectCreate(repository="lsst-sqre/docs", scopes=set()),
        admin,
        ip_address=None,
    )
    assert docs.username == "bot-gh-lsst-sqre-docs"
    bad = GitHubProjectCreate(repository="lsst/sqre-docs", scopes=set())
    with pytest.raises(DuplicateGitHubUsernameError) as dup_excinfo:
        await service.create_project(bad, admin, ip_address=None)
    assert str(dup_excinfo.value) == (
        "Username bot-gh-lsst-sqre-docs derived from lsst/sqre-docs is"
        f" already used by GitHub project {docs.id} for lsst-sqre/docs,"
        " provide an explicit username"
    )
    shared = await service.create_project(
        bad.model_copy(update={"username": docs.username}),
        admin,
        ip_address=None,
    )
    assert shared.username == docs.username

    # A derived username that is too long is refused.
    long_name = "lsst-sqre/" + "a" * 100
    mock.repositories[long_name] = GitHubRepository(
        full_name=long_name, id=1, owner_id=654321
    )
    bad = GitHubProjectCreate(repository=long_name, scopes=set())
    with pytest.raises(InvalidGitHubUsernameError):
        await service.create_project(bad, admin, ip_address=None)


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_list_projects(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    mock_github_repositories(respx_mock, [SQR_062, OOK])
    admin = await create_admin(factory)

    docs = await service.create_project(
        GitHubProjectCreate(
            repository="lsst-sqre/sqr-062",
            requested_by="slack:U024BE7LH",
            scopes=set(),
            ref="refs/heads/main",
        ),
        admin,
        ip_address=None,
    )
    pulls = await service.create_project(
        GitHubProjectCreate(
            repository="lsst-sqre/sqr-062", scopes=set(), ref="refs/pull/"
        ),
        admin,
        ip_address=None,
    )
    ook = await service.create_project(
        GitHubProjectCreate(
            repository="lsst-sqre/ook",
            requested_by="slack:U024BE7LH",
            scopes=set(),
        ),
        admin,
        ip_address=None,
    )

    assert await service.list_projects(admin) == [docs, pulls, ook]
    result = await service.list_projects(admin, repository="LSST-SQRE/SQR-062")
    assert result == [docs, pulls]
    result = await service.list_projects(admin, username=ook.username)
    assert result == [ook]
    result = await service.list_projects(admin, requested_by="slack:U024BE7LH")
    assert result == [docs, ook]
    result = await service.list_projects(admin, template="technote")
    assert result == []
    result = await service.list_projects(
        admin, repository="lsst-sqre/ook", username=docs.username
    )
    assert result == []

    user = await create_session_token(factory, scopes={"user:token"})
    with pytest.raises(PermissionDeniedError):
        await service.list_projects(user)
    with pytest.raises(PermissionDeniedError):
        await service.get_project(docs.id, user)
    with pytest.raises(NotFoundError):
        await service.get_project(docs.id + 1000, admin)


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_update_project(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    token_service = factory.create_token_service()
    mock = mock_github_repositories(respx_mock, [SQR_062, OOK])
    admin = await create_admin(factory)
    other_admin = await create_session_token(
        factory, username="other-admin", scopes={"admin:token"}
    )
    history_store = GitHubProjectHistoryStore(factory.session)

    project = await service.create_project(
        GitHubProjectCreate(
            description="Original",
            repository="lsst-sqre/sqr-062",
            workflow=".github/workflows/docs.yaml",
            scopes={"read:all"},
        ),
        admin,
        ip_address=None,
    )
    assert mock.requests == 1

    # Change some fields, clear one, and leave the rest alone.
    update = GitHubProjectUpdate(
        description=None,
        requested_by="gafaelfawr:someuser",
        ref="refs/heads/main",
        scopes={"read:all", "exec:test"},
        max_lifetime=timedelta(hours=2),
        uid=100001,
        groups=[Group(name="some-group", id=100001)],
    )
    updated = await service.update_project(
        project.id, update, other_admin, ip_address="127.0.0.1"
    )
    assert updated.id == project.id
    assert updated.description is None
    assert updated.requested_by == "gafaelfawr:someuser"
    assert updated.username == project.username
    assert updated.repository == project.repository
    assert updated.repository_id == project.repository_id
    assert updated.workflow == ".github/workflows/docs.yaml"
    assert updated.ref == "refs/heads/main"
    assert updated.scopes == {"exec:test", "read:all"}
    assert updated.max_lifetime == timedelta(hours=2)
    assert updated.uid == 100001
    assert updated.gid is None
    assert updated.groups == [Group(name="some-group", id=100001)]
    assert updated.enabled
    assert updated.created == project.created
    assert updated.created_by == "some-admin"
    assert updated.modified >= project.modified
    assert_is_now(updated.modified)
    assert updated.modified_by == "other-admin"
    assert await service.get_project(project.id, admin) == updated
    assert mock.requests == 1
    async with factory.session.begin():
        history = await history_store.list(project_id=project.id)
    assert len(history) == 2
    assert history[1].model_dump() == {
        "project_id": project.id,
        "template": None,
        "action": GitHubProjectChange.modify,
        "actor": "other-admin",
        "ip_address": "127.0.0.1",
        "event_time": ANY,
        "old_values": project.model_dump(mode="json"),
        "new_values": updated.model_dump(mode="json"),
    }

    # Changing the repository looks up the IDs again but keeps the username.
    update = GitHubProjectUpdate(repository="lsst-sqre/ook")
    moved = await service.update_project(
        project.id, update, admin, ip_address=None
    )
    assert moved.repository == "lsst-sqre/ook"
    assert moved.repository_id == OOK.id
    assert moved.repository_owner_id == OOK.owner_id
    assert moved.username == "bot-gh-lsst-sqre-sqr-062"
    assert mock.requests == 2

    # Setting the username to null derives it from the new repository, and
    # setting it explicitly uses that value. Sending the same repository
    # again doesn't look it up again.
    update = GitHubProjectUpdate(username=None, repository="lsst-sqre/ook")
    renamed = await service.update_project(
        project.id, update, admin, ip_address=None
    )
    assert renamed.username == "bot-gh-lsst-sqre-ook"
    assert mock.requests == 2
    update = GitHubProjectUpdate(username="bot-gh-ook-docs")
    renamed = await service.update_project(
        project.id, update, admin, ip_address=None
    )
    assert renamed.username == "bot-gh-ook-docs"

    # Disabling the project revokes its tokens, recorded with the acting
    # administrator, and other changes do not.
    token = await add_github_token(
        factory, username=renamed.username, github_project_id=project.id
    )
    child = await add_github_token(
        factory,
        username=renamed.username,
        github_project_id=project.id,
        parent=token.token.key,
    )
    update = GitHubProjectUpdate(scopes={"read:all"})
    await service.update_project(project.id, update, admin, ip_address=None)
    assert await token_service.get_data(token.token) == token
    update = GitHubProjectUpdate(enabled=False)
    disabled = await service.update_project(
        project.id, update, other_admin, ip_address="127.0.0.1"
    )
    assert not disabled.enabled
    assert await token_service.get_data(token.token) is None
    assert await token_service.get_data(child.token) is None
    assert (
        await token_service.get_token_info_unchecked(token.token.key) is None
    )
    changes = await token_service.get_change_history(
        admin, key=token.token.key
    )
    revocation = [
        e
        for e in changes.entries
        if e.action == TokenChange.revoke and e.token == token.token.key
    ]
    assert len(revocation) == 1
    assert revocation[0].actor == "other-admin"
    assert revocation[0].ip_address == "127.0.0.1"
    assert revocation[0].github_project_id == project.id

    # Disabling an already-disabled project or re-enabling it doesn't try
    # to revoke anything.
    update = GitHubProjectUpdate(enabled=False)
    await service.update_project(project.id, update, admin, ip_address=None)
    update = GitHubProjectUpdate(enabled=True)
    enabled = await service.update_project(
        project.id, update, admin, ip_address=None
    )
    assert enabled.enabled

    # Empty updates are allowed and still bump the modification metadata.
    empty = await service.update_project(
        project.id, GitHubProjectUpdate(), other_admin, ip_address=None
    )
    assert empty.modified_by == "other-admin"
    async with factory.session.begin():
        history = await history_store.list(project_id=project.id)
    assert len(history) == 10


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_update_project_errors(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    mock = mock_github_repositories(respx_mock, [SQR_062, OOK, SQRE_DOCS])
    admin = await create_admin(factory)
    user = await create_session_token(factory, scopes={"user:token"})

    main = await service.create_project(
        GitHubProjectCreate(
            repository="lsst-sqre/sqr-062",
            scopes={"read:all"},
            ref="refs/heads/main",
        ),
        admin,
        ip_address=None,
    )
    tags = await service.create_project(
        GitHubProjectCreate(
            repository="lsst-sqre/sqr-062",
            scopes={"read:all"},
            ref="refs/tags/",
        ),
        admin,
        ip_address=None,
    )
    ook = await service.create_project(
        GitHubProjectCreate(repository="lsst-sqre/ook", scopes=set()),
        admin,
        ip_address=None,
    )
    requests = mock.requests

    update = GitHubProjectUpdate(description="Changed")
    with pytest.raises(PermissionDeniedError):
        await service.update_project(main.id, update, user, ip_address=None)
    with pytest.raises(NotFoundError):
        await service.update_project(
            main.id + 1000, update, admin, ip_address=None
        )

    update = GitHubProjectUpdate(scopes={"admin:token"})
    with pytest.raises(InvalidScopesError):
        await service.update_project(main.id, update, admin, ip_address=None)
    update = GitHubProjectUpdate(max_lifetime=timedelta(days=1))
    with pytest.raises(InvalidMaxLifetimeError):
        await service.update_project(main.id, update, admin, ip_address=None)
    update = GitHubProjectUpdate(repository="lsst-sqre/private")
    with pytest.raises(UnknownGitHubRepositoryError):
        await service.update_project(main.id, update, admin, ip_address=None)

    # Changing a constraint so that it overlaps another project for the
    # same repository is refused, but a project never overlaps itself.
    update = GitHubProjectUpdate(ref="refs/tags/v1.0")
    with pytest.raises(GitHubProjectOverlapError) as excinfo:
        await service.update_project(main.id, update, admin, ip_address=None)
    assert excinfo.value.project_id == tags.id
    update = GitHubProjectUpdate(ref="refs/heads/main")
    same = await service.update_project(
        main.id, update, admin, ip_address=None
    )
    assert same.ref == "refs/heads/main"

    # Moving a project to a repository with an existing unconstrained
    # project is refused.
    update = GitHubProjectUpdate(repository="lsst-sqre/ook")
    with pytest.raises(GitHubProjectOverlapError) as excinfo:
        await service.update_project(main.id, update, admin, ip_address=None)
    assert excinfo.value.project_id == ook.id

    # Deriving a username that collides with another repository's project
    # is refused.
    update = GitHubProjectUpdate(
        username="bot-gh-lsst-sqre-ook", repository="lsst/sqre-docs"
    )
    await service.update_project(tags.id, update, admin, ip_address=None)
    update = GitHubProjectUpdate(username=None)
    with pytest.raises(DuplicateGitHubUsernameError):
        await service.update_project(ook.id, update, admin, ip_address=None)

    # None of the failed updates changed anything.
    assert await service.get_project(main.id, admin) == same
    assert await service.get_project(ook.id, admin) == ook
    assert mock.requests == requests + 3


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_delete_project(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    service = factory.create_github_project_service()
    token_service = factory.create_token_service()
    mock_github_repositories(respx_mock, [SQR_062])
    admin = await create_admin(factory)
    user = await create_session_token(factory, scopes={"user:token"})
    history_store = GitHubProjectHistoryStore(factory.session)

    project = await service.create_project(
        GitHubProjectCreate(repository="lsst-sqre/sqr-062", scopes=set()),
        admin,
        ip_address=None,
    )
    tokens = [
        await add_github_token(
            factory, username=project.username, github_project_id=project.id
        )
        for _ in range(3)
    ]
    other = await add_github_token(
        factory, username=project.username, github_project_id=project.id + 1
    )

    with pytest.raises(PermissionDeniedError):
        await service.delete_project(project.id, user, ip_address=None)
    with pytest.raises(NotFoundError):
        await service.delete_project(project.id + 1000, admin, ip_address=None)

    await service.delete_project(project.id, admin, ip_address="127.0.0.1")
    with pytest.raises(NotFoundError):
        await service.get_project(project.id, admin)
    assert await service.list_projects(admin) == []
    for token in tokens:
        assert await token_service.get_data(token.token) is None
    assert await token_service.get_data(other.token) == other

    async with factory.session.begin():
        history = await history_store.list(project_id=project.id)
    assert history[-1].model_dump() == {
        "project_id": project.id,
        "template": None,
        "action": GitHubProjectChange.delete,
        "actor": "some-admin",
        "ip_address": "127.0.0.1",
        "event_time": ANY,
        "old_values": project.model_dump(mode="json"),
        "new_values": None,
    }
    changes = await token_service.get_change_history(
        admin, username=project.username
    )
    revoked = [e for e in changes.entries if e.action == TokenChange.revoke]
    assert {e.token for e in revoked} == {t.token.key for t in tokens}
    assert all(e.github_project_id == project.id for e in revoked)
    assert all(e.actor == "some-admin" for e in revoked)


@pytest.mark.parametrize(
    "config", ["github-token-exchange-disabled"], indirect=True
)
@pytest.mark.asyncio
async def test_not_configured(config: Config, factory: Factory) -> None:
    with pytest.raises(NotConfiguredError):
        factory.create_github_project_service()
