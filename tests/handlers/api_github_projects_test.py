"""Tests for managing GitHub projects through the admin API."""

from datetime import UTC, datetime
from typing import Any
from unittest.mock import ANY

import pytest
import respx
from httpx import AsyncClient, ConnectError, Response
from safir.testing.slack import MockSlackWebhook

from gafaelfawr.config import Config
from gafaelfawr.constants import COOKIE_NAME, GITHUB_API_URL
from gafaelfawr.factory import Factory
from gafaelfawr.models.enums import GitHubProjectChange, TokenChange
from gafaelfawr.models.github import GitHubRepository
from gafaelfawr.models.state import State
from gafaelfawr.storage.github_project import GitHubProjectHistoryStore

from ..support.constants import TEST_HOSTNAME
from ..support.cookies import clear_session_cookie, set_session_cookie
from ..support.github import mock_github_repositories
from ..support.tokens import add_github_token, create_session_token

SQR_062 = GitHubRepository(
    full_name="lsst-sqre/sqr-062", id=123456, owner_id=654321
)
OOK = GitHubRepository(full_name="lsst-sqre/ook", id=234567, owner_id=654321)
DOCS = GitHubRepository(full_name="lsst-sqre/docs", id=345678, owner_id=654321)
SQRE_DOCS = GitHubRepository(
    full_name="lsst/sqre-docs", id=456780, owner_id=765432
)

URL = "/auth/api/v1/github/projects"
URL_PREFIX = f"https://{TEST_HOSTNAME}{URL}"


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_lifecycle(
    client: AsyncClient,
    factory: Factory,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    mock = mock_github_repositories(respx_mock, [SQR_062, OOK])
    admin_data = await create_session_token(
        factory, username="some-admin", scopes={"admin:token"}
    )
    other_data = await create_session_token(
        factory, username="other-admin", scopes={"admin:token"}
    )
    headers = {"Authorization": f"Bearer {admin_data.token}"}
    other_headers = {"Authorization": f"Bearer {other_data.token}"}

    # Create a project with the username derived from the repository and
    # the maximum lifetime defaulted. The repository name is normalized to
    # the form GitHub reports.
    start = datetime.now(tz=UTC).replace(microsecond=0)
    r = await client.post(
        URL,
        json={
            "description": "Documentation builds for SQR-062",
            "requested_by": "slack:U024BE7LH",
            "repository": "LSST-SQRE/SQR-062",
            "workflow": ".github/workflows/docs.yaml",
            "ref": "refs/heads/main",
            "scopes": ["read:all", "exec:test"],
            "max_lifetime": "PT15M",
        },
        headers=headers,
    )
    now = datetime.now(tz=UTC)
    assert r.status_code == 201
    project = r.json()
    project_id = project["id"]
    assert project_id
    expected_url = f"{URL_PREFIX}/{project_id}"
    assert r.headers["Location"] == expected_url
    expected = {
        "id": project_id,
        "template": None,
        "description": "Documentation builds for SQR-062",
        "requested_by": "slack:U024BE7LH",
        "username": "bot-gh-lsst-sqre-sqr-062",
        "repository": "lsst-sqre/sqr-062",
        "repository_id": SQR_062.id,
        "repository_owner_id": SQR_062.owner_id,
        "workflow": ".github/workflows/docs.yaml",
        "environment": None,
        "ref": "refs/heads/main",
        "scopes": ["exec:test", "read:all"],
        "max_lifetime": "PT15M",
        "uid": None,
        "gid": None,
        "groups": None,
        "enabled": True,
        "created": ANY,
        "created_by": "some-admin",
        "modified": project["created"],
        "modified_by": "some-admin",
    }
    assert project == expected
    created = datetime.fromisoformat(project["created"])
    assert start <= created <= now
    assert mock.requests == 1

    r = await client.get(expected_url, headers=headers)
    assert r.status_code == 200
    assert r.json() == expected
    r = await client.get(URL, headers=headers)
    assert r.status_code == 200
    assert r.json() == [expected]

    # Modify the project as a different administrator. Durations may be
    # given as seconds and are returned as ISO 8601. Setting an optional
    # field to null clears it.
    start = datetime.now(tz=UTC).replace(microsecond=0)
    r = await client.patch(
        expected_url,
        json={
            "description": "Updated description",
            "requested_by": None,
            "environment": "production",
            "ref": "refs/tags/",
            "scopes": ["read:all"],
            "max_lifetime": 3600,
            "uid": 100000,
            "gid": 100000,
            "groups": [{"name": "bot-gh-lsst-sqre-sqr-062", "id": 100000}],
        },
        headers=other_headers,
    )
    now = datetime.now(tz=UTC)
    assert r.status_code == 200
    project = r.json()
    new_expected = {
        **expected,
        "description": "Updated description",
        "requested_by": None,
        "environment": "production",
        "ref": "refs/tags/",
        "scopes": ["read:all"],
        "max_lifetime": "PT1H",
        "uid": 100000,
        "gid": 100000,
        "groups": [{"name": "bot-gh-lsst-sqre-sqr-062", "id": 100000}],
        "modified": ANY,
        "modified_by": "other-admin",
    }
    assert project == new_expected
    modified = datetime.fromisoformat(project["modified"])
    assert start <= modified <= now
    assert modified >= created
    assert mock.requests == 1

    r = await client.get(expected_url, headers=headers)
    assert r.status_code == 200
    assert r.json() == new_expected

    # Changing the repository looks its IDs up again but keeps the username.
    # Setting the username to null then derives it from the new repository.
    r = await client.patch(
        expected_url, json={"repository": "lsst-sqre/ook"}, headers=headers
    )
    assert r.status_code == 200
    assert r.json()["repository"] == "lsst-sqre/ook"
    assert r.json()["repository_id"] == OOK.id
    assert r.json()["repository_owner_id"] == OOK.owner_id
    assert r.json()["username"] == "bot-gh-lsst-sqre-sqr-062"
    assert mock.requests == 2
    r = await client.patch(
        expected_url, json={"username": None}, headers=headers
    )
    assert r.status_code == 200
    assert r.json()["username"] == "bot-gh-lsst-sqre-ook"
    assert r.json()["modified_by"] == "some-admin"
    assert mock.requests == 2

    # Disabling the project revokes its outstanding tokens.
    token_data = await add_github_token(
        factory,
        username="bot-gh-lsst-sqre-ook",
        github_project_id=project_id,
        scopes={"read:all"},
    )
    token_service = factory.create_token_service()
    assert await token_service.get_data(token_data.token) == token_data
    r = await client.patch(
        expected_url, json={"enabled": False}, headers=other_headers
    )
    assert r.status_code == 200
    assert not r.json()["enabled"]
    assert await token_service.get_data(token_data.token) is None
    history = await token_service.get_change_history(
        admin_data, key=token_data.token.key
    )
    revocations = [
        e for e in history.entries if e.action == TokenChange.revoke
    ]
    assert len(revocations) == 1
    assert revocations[0].actor == "other-admin"
    assert revocations[0].ip_address == "127.0.0.1"
    assert revocations[0].github_project_id == project_id

    # Delete the project.
    r = await client.delete(expected_url, headers=headers)
    assert r.status_code == 204
    r = await client.get(expected_url, headers=headers)
    assert r.status_code == 404
    r = await client.delete(expected_url, headers=headers)
    assert r.status_code == 404
    r = await client.get(URL, headers=headers)
    assert r.status_code == 200
    assert r.json() == []

    # Every change was recorded in the project history with the actor and
    # the IP address of the client.
    history_store = GitHubProjectHistoryStore(factory.session)
    async with factory.session.begin():
        entries = await history_store.list(project_id=project_id)
    assert [e.action for e in entries] == [
        GitHubProjectChange.create,
        GitHubProjectChange.modify,
        GitHubProjectChange.modify,
        GitHubProjectChange.modify,
        GitHubProjectChange.modify,
        GitHubProjectChange.delete,
    ]
    assert [e.actor for e in entries] == [
        "some-admin",
        "other-admin",
        "some-admin",
        "some-admin",
        "other-admin",
        "some-admin",
    ]
    assert all(e.ip_address == "127.0.0.1" for e in entries)
    assert entries[0].old_values is None
    assert entries[0].new_values == expected
    assert entries[1].old_values == expected
    assert entries[1].new_values == new_expected
    assert entries[-1].new_values is None
    assert entries[-1].old_values == {
        **new_expected,
        "username": "bot-gh-lsst-sqre-ook",
        "repository": "lsst-sqre/ook",
        "repository_id": OOK.id,
        "repository_owner_id": OOK.owner_id,
        "enabled": False,
        "modified": ANY,
    }

    # No Slack messages logged.
    assert mock_slack.messages == []


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_list_filters(
    client: AsyncClient, factory: Factory, respx_mock: respx.Router
) -> None:
    mock_github_repositories(respx_mock, [SQR_062, OOK, DOCS])
    admin_data = await create_session_token(factory, scopes={"admin:token"})
    headers = {"Authorization": f"Bearer {admin_data.token}"}

    projects = []
    for create in (
        {
            "repository": "lsst-sqre/sqr-062",
            "ref": "refs/heads/main",
            "scopes": ["read:all"],
            "requested_by": "slack:U024BE7LH",
        },
        {
            "repository": "lsst-sqre/sqr-062",
            "ref": "refs/pull/",
            "scopes": [],
            "requested_by": "slack:U024BE7LH",
        },
        {
            "username": "bot-gh-lsst-sqre-sqr-062",
            "repository": "lsst-sqre/ook",
            "scopes": ["read:all"],
            "requested_by": "gafaelfawr:someuser",
        },
        {"repository": "lsst-sqre/docs", "scopes": []},
    ):
        r = await client.post(URL, json=create, headers=headers)
        assert r.status_code == 201
        projects.append(r.json())

    r = await client.get(URL, headers=headers)
    assert r.status_code == 200
    assert r.json() == projects

    # The repository filter is case-insensitive.
    r = await client.get(
        URL, params={"repository": "LSST-SQRE/sqr-062"}, headers=headers
    )
    assert r.status_code == 200
    assert r.json() == projects[:2]

    r = await client.get(
        URL, params={"username": "bot-gh-lsst-sqre-sqr-062"}, headers=headers
    )
    assert r.status_code == 200
    assert r.json() == projects[:3]

    r = await client.get(
        URL, params={"requested_by": "gafaelfawr:someuser"}, headers=headers
    )
    assert r.status_code == 200
    assert r.json() == [projects[2]]

    # Filters combine, and a template filter matches nothing until project
    # templates exist.
    r = await client.get(
        URL,
        params={
            "repository": "lsst-sqre/sqr-062",
            "username": "bot-gh-lsst-sqre-sqr-062",
            "requested_by": "gafaelfawr:someuser",
        },
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json() == []
    r = await client.get(URL, params={"template": "technote"}, headers=headers)
    assert r.status_code == 200
    assert r.json() == []

    # Malformed filter values are rejected rather than matching nothing.
    r = await client.get(
        URL, params={"repository": "sqr-062"}, headers=headers
    )
    assert r.status_code == 422
    r = await client.get(
        URL, params={"username": "bot-other"}, headers=headers
    )
    assert r.status_code == 422
    r = await client.get(URL, params={"requested_by": ""}, headers=headers)
    assert r.status_code == 422


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_errors(
    client: AsyncClient,
    factory: Factory,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    mock_github_repositories(respx_mock, [SQR_062, DOCS, SQRE_DOCS])
    admin_data = await create_session_token(factory, scopes={"admin:token"})
    headers = {"Authorization": f"Bearer {admin_data.token}"}

    r = await client.post(
        URL,
        json={
            "repository": "lsst-sqre/sqr-062",
            "workflow": ".github/workflows/docs.yaml",
            "ref": "refs/heads/main",
            "scopes": ["read:all"],
        },
        headers=headers,
    )
    assert r.status_code == 201
    project_id = r.json()["id"]
    project_url = f"{URL}/{project_id}"

    # Overlapping constraints are refused with an error naming the
    # conflicting project.
    r = await client.post(
        URL,
        json={"repository": "lsst-sqre/sqr-062", "scopes": []},
        headers=headers,
    )
    assert r.status_code == 409
    assert r.json() == {
        "detail": [
            {
                "loc": ["body", "repository"],
                "msg": (
                    f"Constraints overlap GitHub project {project_id} for"
                    " lsst-sqre/sqr-062"
                ),
                "type": "github_project_overlap",
            }
        ]
    }

    # A disjoint project for the same repository is fine, but then cannot
    # be modified to overlap the first.
    r = await client.post(
        URL,
        json={
            "repository": "lsst-sqre/sqr-062",
            "ref": "refs/pull/",
            "scopes": [],
        },
        headers=headers,
    )
    assert r.status_code == 201
    other_url = f"{URL}/{r.json()['id']}"
    r = await client.patch(
        other_url, json={"ref": "refs/heads/"}, headers=headers
    )
    assert r.status_code == 409
    assert r.json()["detail"][0]["type"] == "github_project_overlap"
    assert str(project_id) in r.json()["detail"][0]["msg"]

    # A derived username already used for a different repository is refused
    # with an error naming the conflicting project.
    r = await client.post(
        URL,
        json={"repository": "lsst-sqre/docs", "scopes": []},
        headers=headers,
    )
    assert r.status_code == 201
    docs_id = r.json()["id"]
    r = await client.post(
        URL,
        json={"repository": "lsst/sqre-docs", "scopes": []},
        headers=headers,
    )
    assert r.status_code == 409
    assert r.json() == {
        "detail": [
            {
                "loc": ["body", "username"],
                "msg": (
                    "Username bot-gh-lsst-sqre-docs derived from"
                    f" lsst/sqre-docs is already used by GitHub project"
                    f" {docs_id} for lsst-sqre/docs, provide an explicit"
                    " username"
                ),
                "type": "duplicate_username",
            }
        ]
    }

    # Unknown or private repositories.
    r = await client.post(
        URL,
        json={"repository": "lsst-sqre/nonexistent", "scopes": []},
        headers=headers,
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "unknown_repository"
    assert r.json()["detail"][0]["loc"] == ["body", "repository"]
    r = await client.patch(
        project_url,
        json={"repository": "lsst-sqre/nonexistent"},
        headers=headers,
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "unknown_repository"

    # Scopes must be known and may not be admin scopes.
    r = await client.post(
        URL,
        json={"repository": "lsst-sqre/sqre-docs", "scopes": ["read:bogus"]},
        headers=headers,
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "invalid_scopes"
    assert r.json()["detail"][0]["loc"] == ["body", "scopes"]
    r = await client.patch(
        project_url, json={"scopes": ["admin:token"]}, headers=headers
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "invalid_scopes"

    # The maximum lifetime is capped by the configuration.
    r = await client.patch(
        project_url, json={"max_lifetime": "P1D"}, headers=headers
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "invalid_max_lifetime"
    assert r.json()["detail"][0]["loc"] == ["body", "max_lifetime"]

    # Malformed requests are rejected by model validation.
    bad_creates: list[dict[str, Any]] = [
        {"scopes": []},
        {"repository": "sqr-062", "scopes": []},
        {"repository": "lsst-sqre/sqr-062"},
        {
            "repository": "lsst-sqre/sqr-062",
            "username": "bot-sqr-062",
            "scopes": [],
        },
        {
            "repository": "lsst-sqre/sqr-062",
            "workflow": "docs.yaml",
            "scopes": [],
        },
        {
            "repository": "lsst-sqre/sqr-062",
            "workflow": ".github/workflows/docs.yaml@refs/heads/main",
            "scopes": [],
        },
        {"repository": "lsst-sqre/sqr-062", "ref": "main", "scopes": []},
        {"repository": "lsst-sqre/sqr-062", "scopes": [], "uid": 0},
    ]
    for body in bad_creates:
        r = await client.post(URL, json=body, headers=headers)
        assert r.status_code == 422, body
    for update in (
        {"repository": None},
        {"scopes": None},
        {"max_lifetime": None},
        {"enabled": None},
        {"username": "someuser"},
    ):
        r = await client.patch(project_url, json=update, headers=headers)
        assert r.status_code == 422, update

    # Unknown and malformed project IDs.
    r = await client.get(f"{URL}/999999", headers=headers)
    assert r.status_code == 404
    assert r.json()["detail"][0]["type"] == "not_found"
    r = await client.patch(
        f"{URL}/999999", json={"description": "x"}, headers=headers
    )
    assert r.status_code == 404
    r = await client.delete(f"{URL}/999999", headers=headers)
    assert r.status_code == 404
    r = await client.get(f"{URL}/0", headers=headers)
    assert r.status_code == 422
    r = await client.get(f"{URL}/foo", headers=headers)
    assert r.status_code == 422

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
    mock = mock_github_repositories(respx_mock, [SQR_062, OOK])
    admin_data = await create_session_token(factory, scopes={"admin:token"})
    headers = {"Authorization": f"Bearer {admin_data.token}"}
    create = {"repository": "lsst-sqre/sqr-062", "scopes": ["read:all"]}
    expected_error = {
        "detail": [
            {
                "msg": "GitHub lookup failed, retry later",
                "type": "github_unavailable",
            }
        ]
    }

    # Repository lookups are unauthenticated and therefore subject to the
    # anonymous rate limit, which GitHub reports as a 403. The failure is
    # reported to the client as a 502 with an ErrorModel body, nothing is
    # created, and the failure is reported to Slack with the response body.
    rate_limit = {
        "message": "API rate limit exceeded for 198.51.100.1.",
        "documentation_url": (
            "https://docs.github.com/rest/overview/rate-limits-for-the-rest-api"
        ),
    }
    mock.failure = Response(403, json=rate_limit)
    r = await client.post(URL, json=create, headers=headers)
    assert r.status_code == 502
    assert r.json() == expected_error
    assert mock.requests == 1
    r = await client.get(URL, headers=headers)
    assert r.status_code == 200
    assert r.json() == []
    assert mock_slack.messages == [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: Status 403 from GET"
                            f" {GITHUB_API_URL}/repos/lsst-sqre/sqr-062"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nGitHubWebError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "*URL*\nGET"
                            f" {GITHUB_API_URL}/repos/lsst-sqre/sqr-062"
                        ),
                        "verbatim": True,
                    },
                },
            ],
            "attachments": [
                {
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": ANY,
                                "verbatim": True,
                            },
                        },
                    ]
                }
            ],
        },
    ]
    attachment = mock_slack.messages[0]["attachments"][0]["blocks"][0]
    assert rate_limit["message"] in attachment["text"]["text"]
    mock_slack.messages.clear()

    # GitHub being down or unreachable is handled the same way.
    mock.failure = Response(503, text="Service Unavailable")
    r = await client.post(URL, json=create, headers=headers)
    assert r.status_code == 502
    assert r.json() == expected_error
    assert len(mock_slack.messages) == 1
    alert = mock_slack.messages[0]["blocks"][0]["text"]["text"]
    assert alert.startswith("Error in Gafaelfawr: Status 503 from GET")
    mock_slack.messages.clear()
    mock.failure = ConnectError
    r = await client.post(URL, json=create, headers=headers)
    assert r.status_code == 502
    assert r.json() == expected_error
    assert len(mock_slack.messages) == 1
    alert = mock_slack.messages[0]["blocks"][0]["text"]["text"]
    assert alert == "Error in Gafaelfawr: ConnectError: Mock Error"
    mock_slack.messages.clear()
    assert mock.requests == 3
    r = await client.get(URL, headers=headers)
    assert r.status_code == 200
    assert r.json() == []

    # Once GitHub recovers, the same request succeeds.
    mock.failure = None
    r = await client.post(URL, json=create, headers=headers)
    assert r.status_code == 201
    project = r.json()
    project_url = f"{URL}/{project['id']}"
    assert mock.requests == 4

    # Changing the repository of a project looks it up on GitHub and fails
    # the same way, leaving the project untouched.
    mock.failure = Response(403, json=rate_limit)
    r = await client.patch(
        project_url, json={"repository": "lsst-sqre/ook"}, headers=headers
    )
    assert r.status_code == 502
    assert r.json() == expected_error
    assert mock.requests == 5
    assert len(mock_slack.messages) == 1
    mock_slack.messages.clear()
    r = await client.get(project_url, headers=headers)
    assert r.status_code == 200
    assert r.json() == project

    # Changes that do not touch the repository, or that re-send the same
    # repository, do not call GitHub and therefore succeed while it is down.
    r = await client.patch(
        project_url, json={"description": "Still works"}, headers=headers
    )
    assert r.status_code == 200
    assert r.json()["description"] == "Still works"
    r = await client.patch(
        project_url,
        json={"repository": "lsst-sqre/sqr-062", "scopes": []},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["repository"] == "lsst-sqre/sqr-062"
    assert r.json()["scopes"] == []
    assert mock.requests == 5
    assert mock_slack.messages == []


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_bootstrap(
    client: AsyncClient,
    config: Config,
    factory: Factory,
    respx_mock: respx.Router,
) -> None:
    """The bootstrap token can manage projects, as it can service tokens."""
    mock_github_repositories(respx_mock, [SQR_062])
    bootstrap_token = config.bootstrap_token.get_secret_value()
    headers = {"Authorization": f"Bearer {bootstrap_token}"}

    r = await client.post(
        URL,
        json={"repository": "lsst-sqre/sqr-062", "scopes": ["read:all"]},
        headers=headers,
    )
    assert r.status_code == 201
    assert r.json()["created_by"] == "<bootstrap>"
    project_url = r.headers["Location"]

    r = await client.get(URL, headers=headers)
    assert r.status_code == 200
    assert len(r.json()) == 1
    r = await client.patch(
        project_url, json={"description": "Bootstrapped"}, headers=headers
    )
    assert r.status_code == 200
    assert r.json()["modified_by"] == "<bootstrap>"
    r = await client.delete(project_url, headers=headers)
    assert r.status_code == 204


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_auth_required(
    client: AsyncClient,
    factory: Factory,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    mock_github_repositories(respx_mock, [SQR_062])
    admin_data = await create_session_token(factory, scopes={"admin:token"})
    csrf = await set_session_cookie(client, admin_data.token)
    create = {"repository": "lsst-sqre/sqr-062", "scopes": []}

    # Create one valid project with cookie authentication.
    r = await client.post(URL, headers={"X-CSRF-Token": csrf}, json=create)
    assert r.status_code == 201
    project_url = r.headers["Location"]

    # Replace the cookie with one containing the CSRF token but not the
    # authentication token.
    clear_session_cookie(client)
    client.cookies[COOKIE_NAME] = State(csrf=csrf).to_cookie()

    r = await client.get(URL)
    assert r.status_code == 401
    r = await client.post(URL, headers={"X-CSRF-Token": csrf}, json=create)
    assert r.status_code == 401
    r = await client.get(project_url)
    assert r.status_code == 401
    r = await client.patch(
        project_url, headers={"X-CSRF-Token": csrf}, json={"enabled": False}
    )
    assert r.status_code == 401
    r = await client.delete(project_url, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 401

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_csrf_required(
    client: AsyncClient,
    factory: Factory,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    mock_github_repositories(respx_mock, [SQR_062])
    admin_data = await create_session_token(factory, scopes={"admin:token"})
    csrf = await set_session_cookie(client, admin_data.token)
    create = {"repository": "lsst-sqre/sqr-062", "scopes": []}

    r = await client.post(URL, json=create)
    assert r.status_code == 403
    r = await client.post(
        URL, headers={"X-CSRF-Token": f"XXX{csrf}"}, json=create
    )
    assert r.status_code == 403

    # Create a valid project for additional tests.
    r = await client.post(URL, headers={"X-CSRF-Token": csrf}, json=create)
    assert r.status_code == 201
    project_url = r.headers["Location"]

    r = await client.patch(project_url, json={"enabled": False})
    assert r.status_code == 403
    r = await client.delete(project_url)
    assert r.status_code == 403
    r = await client.get(project_url)
    assert r.status_code == 200
    assert r.json()["enabled"]

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_unauthorized(
    client: AsyncClient,
    factory: Factory,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    mock_github_repositories(respx_mock, [SQR_062])
    admin_data = await create_session_token(factory, scopes={"admin:token"})
    create = {"repository": "lsst-sqre/sqr-062", "scopes": []}

    # Create a valid project for testing.
    r = await client.post(
        URL,
        headers={"Authorization": f"Bearer {admin_data.token}"},
        json=create,
    )
    assert r.status_code == 201
    project_url = r.headers["Location"]

    # Neither a token without admin:token nor one with only other admin
    # scopes may use any of the routes.
    user_data = await create_session_token(factory)
    oidc_data = await create_session_token(
        factory, username="other", scopes={"admin:oidc", "admin:userinfo"}
    )
    for token_data in (user_data, oidc_data):
        headers = {"Authorization": f"Bearer {token_data.token}"}
        r = await client.get(URL, headers=headers)
        assert r.status_code == 403
        r = await client.post(URL, headers=headers, json=create)
        assert r.status_code == 403
        r = await client.get(project_url, headers=headers)
        assert r.status_code == 403
        r = await client.patch(
            project_url, headers=headers, json={"enabled": False}
        )
        assert r.status_code == 403
        r = await client.delete(project_url, headers=headers)
        assert r.status_code == 403

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
    create = {"repository": "lsst-sqre/sqr-062", "scopes": []}

    r = await client.get(URL, headers=headers)
    assert r.status_code == 404
    assert r.json()["detail"][0]["type"] == "not_supported"
    r = await client.post(URL, headers=headers, json=create)
    assert r.status_code == 404
    r = await client.get(f"{URL}/1", headers=headers)
    assert r.status_code == 404
    r = await client.patch(
        f"{URL}/1", headers=headers, json={"enabled": False}
    )
    assert r.status_code == 404
    r = await client.delete(f"{URL}/1", headers=headers)
    assert r.status_code == 404

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []
