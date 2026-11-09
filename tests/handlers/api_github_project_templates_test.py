"""Tests for GitHub project templates and provisioning via the admin API."""

from datetime import UTC, datetime
from unittest.mock import ANY

import pytest
import respx
from httpx import AsyncClient, Response
from safir.testing.slack import MockSlackWebhook

from gafaelfawr.config import Config
from gafaelfawr.constants import COOKIE_NAME, GITHUB_API_URL
from gafaelfawr.factory import Factory
from gafaelfawr.models.enums import GitHubProjectChange
from gafaelfawr.models.github import GitHubRepository
from gafaelfawr.models.github_project import GitHubOwner
from gafaelfawr.models.state import State
from gafaelfawr.storage.github_project import GitHubProjectHistoryStore

from ..support.constants import TEST_HOSTNAME
from ..support.cookies import clear_session_cookie, set_session_cookie
from ..support.github import mock_github_owners, mock_github_repositories
from ..support.tokens import create_session_token

LSST_SQRE = GitHubOwner(name="lsst-sqre", id=654321)
LSST_DM = GitHubOwner(name="lsst-dm", id=765432)
SQR_120 = GitHubRepository(
    full_name="lsst-sqre/sqr-120", id=123456, owner_id=LSST_SQRE.id
)
DMTN_300 = GitHubRepository(
    full_name="lsst-dm/DMTN-300", id=234567, owner_id=LSST_DM.id
)
OOK = GitHubRepository(
    full_name="lsst-sqre/ook", id=345678, owner_id=LSST_SQRE.id
)

TECHNOTE_WORKFLOW = (
    "lsst-sqre/rubin-sphinx-technote-workflows/.github/workflows/ci.yaml"
)
TECHNOTE = {
    "name": "technote",
    "description": "Documentation builds for technotes",
    "owners": ["lsst-sqre", "lsst-dm"],
    "repository_pattern": "^[a-z]+-[0-9]{3,}$",
    "workflow": TECHNOTE_WORKFLOW,
    "scopes": ["read:all", "exec:test"],
    "max_lifetime": "PT30M",
}

URL = "/auth/api/v1/github/project-templates"
URL_PREFIX = f"https://{TEST_HOSTNAME}{URL}"
PROJECTS_URL = "/auth/api/v1/github/projects"
PROJECTS_URL_PREFIX = f"https://{TEST_HOSTNAME}{PROJECTS_URL}"


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_lifecycle(
    client: AsyncClient,
    factory: Factory,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    owners = mock_github_owners(respx_mock, [LSST_SQRE, LSST_DM])
    repositories = mock_github_repositories(respx_mock, [SQR_120, DMTN_300])
    admin_data = await create_session_token(
        factory, username="some-admin", scopes={"admin:token"}
    )
    provisioner_data = await create_session_token(
        factory,
        username="bot-templatebot",
        scopes={"admin:github-oidc-provision"},
    )
    headers = {"Authorization": f"Bearer {admin_data.token}"}
    provisioner_headers = {"Authorization": f"Bearer {provisioner_data.token}"}

    # Create a template. Owners are pinned with their IDs.
    start = datetime.now(tz=UTC).replace(microsecond=0)
    r = await client.post(URL, json=TECHNOTE, headers=headers)
    now = datetime.now(tz=UTC)
    assert r.status_code == 201
    template = r.json()
    assert r.headers["Location"] == f"{URL_PREFIX}/technote"
    assert template == {
        "name": "technote",
        "description": "Documentation builds for technotes",
        "owners": [
            {"name": "lsst-sqre", "id": LSST_SQRE.id},
            {"name": "lsst-dm", "id": LSST_DM.id},
        ],
        "repository_pattern": "^[a-z]+-[0-9]{3,}$",
        "workflow": TECHNOTE_WORKFLOW,
        "environment": None,
        "ref": None,
        "scopes": ["exec:test", "read:all"],
        "max_lifetime": "PT30M",
        "uid": None,
        "gid": None,
        "groups": None,
        "enabled": True,
        "created": ANY,
        "created_by": "some-admin",
        "modified": ANY,
        "modified_by": "some-admin",
    }
    created = datetime.fromisoformat(template["created"])
    assert start <= created <= now
    assert template["modified"] == template["created"]
    assert owners.requests == 2

    r = await client.get(f"{URL}/technote", headers=headers)
    assert r.status_code == 200
    assert r.json() == template
    r = await client.get(URL, headers=headers)
    assert r.status_code == 200
    assert r.json() == [template]

    # Modify the template.
    r = await client.patch(
        f"{URL}/technote",
        json={"description": "Updated", "repository_pattern": None},
        headers=headers,
    )
    assert r.status_code == 200
    template = r.json()
    assert template["description"] == "Updated"
    assert template["repository_pattern"] is None
    assert template["modified_by"] == "some-admin"
    assert owners.requests == 2
    r = await client.get(f"{URL}/technote", headers=headers)
    assert r.json() == template

    # Provision a project from the template as the provisioner.
    r = await client.post(
        f"{URL}/technote/projects",
        json={
            "repository": "LSST-SQRE/SQR-120",
            "description": "Created by Templatebot",
            "requested_by": "slack:U024BE7LH",
        },
        headers=provisioner_headers,
    )
    assert r.status_code == 201
    project = r.json()
    project_id = project["id"]
    assert r.headers["Location"] == f"{PROJECTS_URL_PREFIX}/{project_id}"
    assert project == {
        "id": project_id,
        "template": "technote",
        "description": "Created by Templatebot",
        "requested_by": "slack:U024BE7LH",
        "username": "bot-gh-lsst-sqre-sqr-120",
        "repository": "lsst-sqre/sqr-120",
        "repository_id": SQR_120.id,
        "repository_owner_id": SQR_120.owner_id,
        "workflow": TECHNOTE_WORKFLOW,
        "environment": None,
        "ref": None,
        "scopes": ["exec:test", "read:all"],
        "max_lifetime": "PT30M",
        "uid": None,
        "gid": None,
        "groups": None,
        "enabled": True,
        "created": ANY,
        "created_by": "bot-templatebot",
        "modified": ANY,
        "modified_by": "bot-templatebot",
    }
    assert repositories.requests == 1

    # Provisioning again returns the existing project with 200 and no
    # Location header.
    r = await client.post(
        f"{URL}/technote/projects",
        json={"repository": "lsst-sqre/sqr-120"},
        headers=provisioner_headers,
    )
    assert r.status_code == 200
    assert r.json() == project
    assert "Location" not in r.headers

    # The project appears in the admin API, filtered by template.
    r = await client.get(
        PROJECTS_URL, params={"template": "technote"}, headers=headers
    )
    assert r.status_code == 200
    assert r.json() == [project]
    r = await client.get(f"{PROJECTS_URL}/{project_id}", headers=headers)
    assert r.status_code == 200
    assert r.json() == project

    # The history records the template changes and the provisioning.
    history_store = GitHubProjectHistoryStore(factory.session)
    async with factory.session.begin():
        history = await history_store.list(template="technote")
    assert [(e.project_id, e.action, e.actor) for e in history] == [
        (None, GitHubProjectChange.create, "some-admin"),
        (None, GitHubProjectChange.modify, "some-admin"),
        (project_id, GitHubProjectChange.create, "bot-templatebot"),
    ]

    # The template cannot be deleted while the project exists.
    r = await client.delete(f"{URL}/technote", headers=headers)
    assert r.status_code == 409
    assert r.json() == {
        "detail": [
            {
                "loc": ["path", "name"],
                "msg": (
                    "GitHub project template technote is used by 1 project"
                    " and cannot be deleted, disable it instead"
                ),
                "type": "template_in_use",
            }
        ]
    }

    # Deleting the project and then the template works.
    r = await client.delete(f"{PROJECTS_URL}/{project_id}", headers=headers)
    assert r.status_code == 204
    r = await client.delete(f"{URL}/technote", headers=headers)
    assert r.status_code == 204
    r = await client.get(f"{URL}/technote", headers=headers)
    assert r.status_code == 404
    r = await client.get(URL, headers=headers)
    assert r.status_code == 200
    assert r.json() == []
    async with factory.session.begin():
        history = await history_store.list(template="technote")
    assert [e.action for e in history][-2:] == [
        GitHubProjectChange.delete,
        GitHubProjectChange.delete,
    ]

    # None of this should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_errors(
    client: AsyncClient,
    factory: Factory,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    mock_github_owners(respx_mock, [LSST_SQRE, LSST_DM])
    mock_github_repositories(respx_mock, [SQR_120, OOK])
    admin_data = await create_session_token(factory, scopes={"admin:token"})
    headers = {"Authorization": f"Bearer {admin_data.token}"}

    r = await client.post(URL, json=TECHNOTE, headers=headers)
    assert r.status_code == 201

    # Duplicate name.
    r = await client.post(URL, json=TECHNOTE, headers=headers)
    assert r.status_code == 409
    assert r.json() == {
        "detail": [
            {
                "loc": ["body", "name"],
                "msg": "GitHub project template technote already exists",
                "type": "duplicate_template",
            }
        ]
    }

    # Unknown owner, reserved scope, invalid regular expression, and
    # invalid name.
    r = await client.post(
        URL,
        json={**TECHNOTE, "name": "other", "owners": ["lsst-nope"]},
        headers=headers,
    )
    assert r.status_code == 422
    assert r.json() == {
        "detail": [
            {
                "loc": ["body", "owners"],
                "msg": "GitHub owner lsst-nope not found",
                "type": "unknown_owner",
            }
        ]
    }
    r = await client.post(
        URL,
        json={
            **TECHNOTE,
            "name": "other",
            "scopes": ["admin:github-oidc-provision"],
        },
        headers=headers,
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "invalid_scopes"
    r = await client.post(
        URL,
        json={**TECHNOTE, "name": "other", "repository_pattern": "^[a-z"},
        headers=headers,
    )
    assert r.status_code == 422
    assert "regular expression" in r.json()["detail"][0]["msg"]
    r = await client.post(
        URL, json={**TECHNOTE, "name": "Not Valid"}, headers=headers
    )
    assert r.status_code == 422
    r = await client.get(f"{URL}/Not%20Valid", headers=headers)
    assert r.status_code == 422

    # Required fields cannot be nulled on update, and unknown templates
    # cannot be modified or deleted.
    r = await client.patch(
        f"{URL}/technote", json={"owners": None}, headers=headers
    )
    assert r.status_code == 422
    r = await client.patch(
        f"{URL}/other", json={"description": "x"}, headers=headers
    )
    assert r.status_code == 404
    r = await client.delete(f"{URL}/other", headers=headers)
    assert r.status_code == 404

    # Provisioning errors.
    r = await client.post(
        f"{URL}/other/projects",
        json={"repository": "lsst-sqre/sqr-120"},
        headers=headers,
    )
    assert r.status_code == 404
    r = await client.post(
        f"{URL}/technote/projects",
        json={"repository": "lsst-sqre/ook"},
        headers=headers,
    )
    assert r.status_code == 422
    assert r.json() == {
        "detail": [
            {
                "loc": ["body", "repository"],
                "msg": (
                    "Name ook of repository lsst-sqre/ook does not match the"
                    " repository pattern of GitHub project template technote"
                ),
                "type": "repository_not_allowed",
            }
        ]
    }
    r = await client.post(
        f"{URL}/technote/projects",
        json={"repository": "lsst-sqre/sqr-000"},
        headers=headers,
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "unknown_repository"
    r = await client.post(
        f"{URL}/technote/projects",
        json={"repository": "lsst-sqre/sqr-120", "username": "bot-gh-x"},
        headers=headers,
    )
    assert r.status_code == 201
    assert r.json()["username"] == "bot-gh-lsst-sqre-sqr-120"
    project_url = r.headers["Location"]

    # A manually created project for a repository conflicts with
    # provisioning for it.
    r = await client.delete(project_url, headers=headers)
    assert r.status_code == 204
    r = await client.post(
        PROJECTS_URL,
        json={"repository": "lsst-sqre/sqr-120", "scopes": []},
        headers=headers,
    )
    assert r.status_code == 201
    manual_id = r.json()["id"]
    r = await client.post(
        f"{URL}/technote/projects",
        json={"repository": "lsst-sqre/sqr-120"},
        headers=headers,
    )
    assert r.status_code == 409
    assert r.json()["detail"][0]["type"] == "github_project_overlap"
    assert str(manual_id) in r.json()["detail"][0]["msg"]

    # A disabled template cannot be used.
    r = await client.patch(
        f"{URL}/technote", json={"enabled": False}, headers=headers
    )
    assert r.status_code == 200
    r = await client.post(
        f"{URL}/technote/projects",
        json={"repository": "lsst-sqre/sqr-120"},
        headers=headers,
    )
    assert r.status_code == 409
    assert r.json() == {
        "detail": [
            {
                "loc": ["path", "name"],
                "msg": "GitHub project template technote is disabled",
                "type": "template_disabled",
            }
        ]
    }

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_github_failure(
    client: AsyncClient,
    factory: Factory,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    owners = mock_github_owners(respx_mock, [LSST_SQRE, LSST_DM])
    repositories = mock_github_repositories(respx_mock, [SQR_120])
    admin_data = await create_session_token(factory, scopes={"admin:token"})
    headers = {"Authorization": f"Bearer {admin_data.token}"}
    expected_error = {
        "detail": [
            {
                "msg": "GitHub lookup failed, retry later",
                "type": "github_unavailable",
            }
        ]
    }

    # A failed owner lookup during template creation is a 502, creates
    # nothing, and is reported to Slack.
    owners.failure = Response(503, text="Service Unavailable")
    r = await client.post(URL, json=TECHNOTE, headers=headers)
    assert r.status_code == 502
    assert r.json() == expected_error
    assert owners.requests == 1
    r = await client.get(URL, headers=headers)
    assert r.json() == []
    assert len(mock_slack.messages) == 1
    alert = mock_slack.messages[0]["blocks"][0]["text"]["text"]
    assert alert == (
        "Error in Gafaelfawr: Status 503 from GET"
        f" {GITHUB_API_URL}/users/lsst-sqre"
    )
    mock_slack.messages.clear()

    # Once GitHub recovers, creation works. Updates that keep the existing
    # owners do not call GitHub, but adding one does and fails the same
    # way, leaving the template untouched.
    owners.failure = None
    r = await client.post(URL, json=TECHNOTE, headers=headers)
    assert r.status_code == 201
    assert owners.requests == 3
    owners.failure = Response(503, text="Service Unavailable")
    r = await client.patch(
        f"{URL}/technote",
        json={"owners": ["lsst-dm", "lsst-sqre"]},
        headers=headers,
    )
    assert r.status_code == 200
    assert [o["name"] for o in r.json()["owners"]] == ["lsst-dm", "lsst-sqre"]
    assert owners.requests == 3
    r = await client.patch(
        f"{URL}/technote",
        json={"owners": ["lsst-sqre", "lsst"]},
        headers=headers,
    )
    assert r.status_code == 502
    assert r.json() == expected_error
    assert owners.requests == 4
    assert len(mock_slack.messages) == 1
    mock_slack.messages.clear()
    r = await client.get(f"{URL}/technote", headers=headers)
    assert [o["name"] for o in r.json()["owners"]] == ["lsst-dm", "lsst-sqre"]

    # A failed repository lookup during provisioning is handled the same
    # way.
    repositories.failure = Response(503, text="Service Unavailable")
    r = await client.post(
        f"{URL}/technote/projects",
        json={"repository": "lsst-sqre/sqr-120"},
        headers=headers,
    )
    assert r.status_code == 502
    assert r.json() == expected_error
    assert len(mock_slack.messages) == 1
    r = await client.get(PROJECTS_URL, headers=headers)
    assert r.json() == []


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_provisioner_scope(
    client: AsyncClient,
    config: Config,
    factory: Factory,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    """The provisioning scope allows exactly one route."""
    mock_github_owners(respx_mock, [LSST_SQRE])
    mock_github_repositories(respx_mock, [SQR_120, DMTN_300])
    admin_data = await create_session_token(factory, scopes={"admin:token"})
    admin_headers = {"Authorization": f"Bearer {admin_data.token}"}
    provisioner_data = await create_session_token(
        factory,
        username="bot-templatebot",
        scopes={"admin:github-oidc-provision"},
    )
    headers = {"Authorization": f"Bearer {provisioner_data.token}"}
    r = await client.post(
        URL, json={**TECHNOTE, "owners": ["lsst-sqre"]}, headers=admin_headers
    )
    assert r.status_code == 201

    # The provisioner can provision but cannot read or change templates or
    # projects, including the project it just created.
    r = await client.post(
        f"{URL}/technote/projects",
        json={"repository": "lsst-sqre/sqr-120"},
        headers=headers,
    )
    assert r.status_code == 201
    project_url = r.headers["Location"]
    r = await client.get(URL, headers=headers)
    assert r.status_code == 403
    r = await client.get(f"{URL}/technote", headers=headers)
    assert r.status_code == 403
    r = await client.post(
        URL, json={**TECHNOTE, "name": "other"}, headers=headers
    )
    assert r.status_code == 403
    r = await client.patch(
        f"{URL}/technote", json={"enabled": False}, headers=headers
    )
    assert r.status_code == 403
    r = await client.delete(f"{URL}/technote", headers=headers)
    assert r.status_code == 403
    r = await client.get(PROJECTS_URL, headers=headers)
    assert r.status_code == 403
    r = await client.get(project_url, headers=headers)
    assert r.status_code == 403
    r = await client.post(
        PROJECTS_URL,
        json={"repository": "lsst-dm/dmtn-300", "scopes": []},
        headers=headers,
    )
    assert r.status_code == 403
    r = await client.patch(
        project_url, json={"enabled": False}, headers=headers
    )
    assert r.status_code == 403
    r = await client.delete(project_url, headers=headers)
    assert r.status_code == 403

    # A repository outside the template's owners is refused even though the
    # repository exists.
    r = await client.post(
        f"{URL}/technote/projects",
        json={"repository": "lsst-dm/dmtn-300"},
        headers=headers,
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "repository_not_allowed"

    # Tokens with neither scope, including other admin scopes, cannot
    # provision. The bootstrap token can, since it has admin:token.
    for scopes in (set(), {"admin:oidc", "admin:userinfo"}, {"user:token"}):
        other_data = await create_session_token(
            factory, username="other", scopes=scopes
        )
        r = await client.post(
            f"{URL}/technote/projects",
            json={"repository": "lsst-sqre/sqr-120"},
            headers={"Authorization": f"Bearer {other_data.token}"},
        )
        assert r.status_code == 403
    bootstrap_token = config.bootstrap_token.get_secret_value()
    r = await client.post(
        f"{URL}/technote/projects",
        json={"repository": "lsst-sqre/sqr-120"},
        headers={"Authorization": f"Bearer {bootstrap_token}"},
    )
    assert r.status_code == 200
    assert r.json()["created_by"] == "bot-templatebot"

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_auth_required(
    client: AsyncClient,
    factory: Factory,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    mock_github_owners(respx_mock, [LSST_SQRE, LSST_DM])
    admin_data = await create_session_token(factory, scopes={"admin:token"})
    csrf = await set_session_cookie(client, admin_data.token)

    # Create one valid template with cookie authentication, which requires
    # the CSRF token.
    r = await client.post(URL, json=TECHNOTE)
    assert r.status_code == 403
    r = await client.post(URL, headers={"X-CSRF-Token": csrf}, json=TECHNOTE)
    assert r.status_code == 201
    provision = {"repository": "lsst-sqre/sqr-120"}
    r = await client.post(f"{URL}/technote/projects", json=provision)
    assert r.status_code == 403

    # Replace the cookie with one containing the CSRF token but not the
    # authentication token.
    clear_session_cookie(client)
    client.cookies[COOKIE_NAME] = State(csrf=csrf).to_cookie()
    csrf_headers = {"X-CSRF-Token": csrf}
    r = await client.get(URL)
    assert r.status_code == 401
    r = await client.post(URL, headers=csrf_headers, json=TECHNOTE)
    assert r.status_code == 401
    r = await client.get(f"{URL}/technote")
    assert r.status_code == 401
    r = await client.patch(
        f"{URL}/technote", headers=csrf_headers, json={"enabled": False}
    )
    assert r.status_code == 401
    r = await client.delete(f"{URL}/technote", headers=csrf_headers)
    assert r.status_code == 401
    r = await client.post(
        f"{URL}/technote/projects", headers=csrf_headers, json=provision
    )
    assert r.status_code == 401

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.parametrize(
    "config", ["github-token-exchange-disabled"], indirect=True
)
@pytest.mark.asyncio
async def test_not_configured(
    client: AsyncClient, factory: Factory, mock_slack: MockSlackWebhook
) -> None:
    admin_data = await create_session_token(factory, scopes={"admin:token"})
    headers = {"Authorization": f"Bearer {admin_data.token}"}

    r = await client.get(URL, headers=headers)
    assert r.status_code == 404
    assert r.json()["detail"][0]["type"] == "not_supported"
    r = await client.post(URL, headers=headers, json=TECHNOTE)
    assert r.status_code == 404
    r = await client.get(f"{URL}/technote", headers=headers)
    assert r.status_code == 404
    r = await client.patch(
        f"{URL}/technote", headers=headers, json={"enabled": False}
    )
    assert r.status_code == 404
    r = await client.delete(f"{URL}/technote", headers=headers)
    assert r.status_code == 404
    r = await client.post(
        f"{URL}/technote/projects",
        headers=headers,
        json={"repository": "lsst-sqre/sqr-120"},
    )
    assert r.status_code == 404

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []
