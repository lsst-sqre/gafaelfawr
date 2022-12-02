"""Tests for the ``/login`` route with GitHub."""

from __future__ import annotations

from typing import Dict, Optional
from unittest.mock import ANY
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from _pytest.logging import LogCaptureFixture
from httpx import AsyncClient, Response

from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.factory import Factory
from gafaelfawr.models.github import GitHubTeam, GitHubUserInfo
from gafaelfawr.providers.github import GitHubProvider

from ..support.github import mock_github
from ..support.logging import parse_log
from ..support.slack import MockSlack


async def simulate_github_login(
    client: AsyncClient,
    respx_mock: respx.Router,
    user_info: GitHubUserInfo,
    headers: Optional[Dict[str, str]] = None,
    return_url: str = "https://example.com/",
    paginate_teams: bool = False,
    expect_revoke: bool = False,
) -> Response:
    """Simulate a GitHub login and return the final response.

    Given the user information that GitHub should return, simulate going to
    ``/login`` as an unauthenticated user, following the redirect to GitHub,
    and then returning to the ``/login`` handler.

    Parameters
    ----------
    client : `httpx.AsyncClient`
        Client to use to make calls to the application.
    respx_mock : `respx.Router`
        Mock for httpx calls.
    user_info : `gafaelfawr.providers.github.GitHubUserInfo`
        The user information that GitHub should return.
    headers : Dict[`str`, `str`], optional
        Optional headers to send on the initial login request.
    return_url : `str`, optional
        The return URL to pass to the login process.  If not provided, a
        simple one will be used.
    paginate_teams : `bool`, optional
        Whether to paginate the team list.  If this is set to true, there must
        be more then two teams.  Default is `False`.
    expect_revoke : `bool`, optional
        Whether to expect a call from Gafaelfawr to the token revocation URL
        immediately after retrieving user information.  Default is `False`.

    Returns
    -------
    response : ``httpx.Response``
        The response from the return to the ``/login`` handler.
    """
    config = await config_dependency()
    assert config.github
    if not headers:
        headers = {}
    await mock_github(
        respx_mock,
        "some-code",
        user_info,
        paginate_teams=paginate_teams,
        expect_revoke=expect_revoke,
    )

    # Simulate the redirect to GitHub.
    r = await client.get("/login", params={"rd": return_url}, headers=headers)
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    assert url.scheme == "https"
    assert "github.com" in url.netloc
    assert url.query
    query = parse_qs(url.query)
    assert query == {
        "client_id": [config.github.client_id],
        "scope": [" ".join(GitHubProvider._SCOPES)],
        "state": [ANY],
    }

    # Simulate the return from GitHub.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    if r.status_code == 307:
        assert r.headers["Location"] == return_url

    return r


@pytest.mark.asyncio
async def test_login(
    client: AsyncClient, respx_mock: respx.Router, caplog: LogCaptureFixture
) -> None:
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[
            GitHubTeam(slug="a-team", gid=1000, organization="org"),
            GitHubTeam(slug="other-team", gid=1001, organization="org"),
            GitHubTeam(
                slug="team-with-very-long-name",
                gid=1002,
                organization="other-org",
            ),
        ],
    )
    return_url = "https://example.com:4444/foo?a=bar&b=baz"

    # Simulate the GitHub login.
    caplog.clear()
    r = await simulate_github_login(
        client, respx_mock, user_info, return_url=return_url
    )
    assert r.status_code == 307
    assert parse_log(caplog) == [
        {
            "event": "Redirecting user to GitHub for authentication",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "info",
        },
        {
            "event": "Successfully authenticated user githubuser",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "info",
            "token_key": ANY,
            "token_username": "githubuser",
            "token_expires": ANY,
            "token_scopes": ["exec:test", "read:all", "user:token"],
            "token_userinfo": {
                "email": "githubuser@example.com",
                "gid": 123456,
                "groups": [
                    {"id": 123456, "name": "githubuser"},
                    {"id": 1000, "name": "org-a-team"},
                    {"id": 1001, "name": "org-other-team"},
                    {"id": 1002, "name": "other-org-team-with-very--F279yg"},
                ],
                "name": "GitHub User",
                "uid": 123456,
            },
        },
    ]

    # Examine the resulting cookie and ensure that it has the proper metadata
    # set.
    cookie = next((c for c in r.cookies.jar if c.name == "gafaelfawr"))
    assert cookie.secure
    assert cookie.discard
    assert cookie.has_nonstandard_attr("HttpOnly")
    assert cookie.get_nonstandard_attr("SameSite") == "lax"

    # Check that the /auth route works and finds our token, and that the user
    # information is correct.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "githubuser"
    assert r.headers["X-Auth-Request-Email"] == "githubuser@example.com"

    # Do the same verification with the user-info endpoint.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "githubuser",
        "name": "GitHub User",
        "email": "githubuser@example.com",
        "uid": 123456,
        "gid": 123456,
        "groups": [
            {"name": "githubuser", "id": 123456},
            {"name": "org-a-team", "id": 1000},
            {"name": "org-other-team", "id": 1001},
            {"name": "other-org-team-with-very--F279yg", "id": 1002},
        ],
    }


@pytest.mark.asyncio
async def test_redirect_header(
    client: AsyncClient, respx_mock: respx.Router
) -> None:
    """Test receiving the redirect header via X-Auth-Request-Redirect."""
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="ORG")],
    )
    return_url = "https://example.com/foo?a=bar&b=baz"
    await mock_github(respx_mock, "some-code", user_info)

    # Simulate the initial authentication request.
    r = await client.get(
        "/login", headers={"X-Auth-Request-Redirect": return_url}
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url


@pytest.mark.asyncio
async def test_no_destination(
    client: AsyncClient, mock_slack: MockSlack
) -> None:
    r = await client.get("/login")
    assert r.status_code == 422

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_cookie_and_token(
    client: AsyncClient, respx_mock: respx.Router
) -> None:
    """Test that cookie auth takes precedence over an Authorization header.

    JupyterHub sends an Authorization header in its internal requests with
    type token.  We want to ensure that we prefer our session cookie, rather
    than try to unsuccessfully parse that header.  Test this by completing a
    login to get a valid session and then make a request with a bogus
    Authorization header.
    """
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="org")],
    )

    # Simulate the GitHub login.
    r = await simulate_github_login(
        client,
        respx_mock,
        user_info,
        headers={"Authorization": "token some-jupyterhub-token"},
    )

    # Now make a request to the /auth endpoint with a bogus token.
    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers={"Authorization": "token some-jupyterhub-token"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "githubuser"


@pytest.mark.asyncio
async def test_bad_redirect(
    client: AsyncClient, respx_mock: respx.Router, mock_slack: MockSlack
) -> None:
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="org")],
    )

    r = await client.get("/login", params={"rd": "https://foo.example.com/"})
    assert r.status_code == 422

    r = await client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": "https://foo.example.com/"},
    )
    assert r.status_code == 422

    # But if we're deployed under foo.example.com as determined by the
    # X-Forwarded-Host header, this will be allowed.
    r = await simulate_github_login(
        client,
        respx_mock,
        user_info,
        headers={
            "X-Forwarded-For": "192.168.0.1",
            "X-Forwarded-Host": "foo.example.com",
        },
        return_url="https://foo.example.com/",
    )
    assert r.status_code == 307

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_github_uppercase(
    client: AsyncClient, respx_mock: respx.Router
) -> None:
    """Tests that usernames and organization names are forced to lowercase.

    We do not test that slugs are forced to lowercase (and do not change the
    case of slugs) because GitHub should already be coercing lowercase when
    creating the slug.
    """
    user_info = GitHubUserInfo(
        name="A User",
        username="SomeUser",
        uid=1000,
        email="user@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="ORG")],
    )

    r = await simulate_github_login(client, respx_mock, user_info)
    assert r.status_code == 307

    # The user returned by the /auth route should be forced to lowercase.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "someuser"

    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "someuser",
        "name": "A User",
        "email": "user@example.com",
        "uid": 1000,
        "gid": 1000,
        "groups": [
            {"name": "org-a-team", "id": 1000},
            {"name": "someuser", "id": 1000},
        ],
    }


@pytest.mark.asyncio
async def test_github_admin(
    client: AsyncClient, respx_mock: respx.Router, factory: Factory
) -> None:
    """Test that a token administrator gets the admin:token scope."""
    admin_service = factory.create_admin_service()
    async with factory.session.begin():
        await admin_service.add_admin(
            "someuser", actor="admin", ip_address="127.0.0.1"
        )
    user_info = GitHubUserInfo(
        name="A User",
        username="someuser",
        uid=1000,
        email="user@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="ORG")],
    )

    r = await simulate_github_login(client, respx_mock, user_info)
    assert r.status_code == 307

    # The user should have admin:token scope.
    r = await client.get("/auth", params={"scope": "admin:token"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_invalid_username(
    client: AsyncClient, respx_mock: respx.Router, mock_slack: MockSlack
) -> None:
    """Test that invalid usernames are rejected."""
    user_info = GitHubUserInfo(
        name="A User",
        username="invalid user",
        uid=1000,
        email="foo@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="ORG")],
    )

    r = await simulate_github_login(
        client, respx_mock, user_info, expect_revoke=True
    )
    assert r.status_code == 403
    assert "Invalid username: invalid user" in r.text

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_invalid_groups(
    client: AsyncClient, respx_mock: respx.Router
) -> None:
    user_info = GitHubUserInfo(
        name="A User",
        username="someuser",
        uid=1000,
        email="user@example.com",
        teams=[
            GitHubTeam(slug="a-team", gid=1000, organization="ORG"),
            GitHubTeam(slug="broken slug", gid=4000, organization="ORG"),
            GitHubTeam(slug="valid", gid=5000, organization="bad:org"),
        ],
    )

    r = await simulate_github_login(client, respx_mock, user_info)
    assert r.status_code == 307

    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "someuser",
        "name": "A User",
        "email": "user@example.com",
        "uid": 1000,
        "gid": 1000,
        "groups": [
            {"name": "org-a-team", "id": 1000},
            {"name": "someuser", "id": 1000},
        ],
    }


@pytest.mark.asyncio
async def test_paginated_teams(
    client: AsyncClient, respx_mock: respx.Router
) -> None:
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[
            GitHubTeam(slug="a-team", gid=1000, organization="org"),
            GitHubTeam(slug="other-team", gid=1001, organization="org"),
            GitHubTeam(slug="third-team", gid=1002, organization="foo"),
            GitHubTeam(
                slug="team-with-very-long-name",
                gid=1003,
                organization="other-org",
            ),
        ],
    )

    r = await simulate_github_login(
        client, respx_mock, user_info, paginate_teams=True
    )
    assert r.status_code == 307

    # Check the group list.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "githubuser",
        "name": "GitHub User",
        "email": "githubuser@example.com",
        "uid": 123456,
        "gid": 123456,
        "groups": [
            {"name": "foo-third-team", "id": 1002},
            {"name": "githubuser", "id": 123456},
            {"name": "org-a-team", "id": 1000},
            {"name": "org-other-team", "id": 1001},
            {"name": "other-org-team-with-very--F279yg", "id": 1003},
        ],
    }


@pytest.mark.asyncio
async def test_no_valid_groups(
    client: AsyncClient, respx_mock: respx.Router, mock_slack: MockSlack
) -> None:
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[],
    )

    r = await simulate_github_login(
        client, respx_mock, user_info, expect_revoke=True
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    assert "githubuser is not a member of any authorized groups" in r.text
    assert "Some <strong>error instructions</strong> with HTML." in r.text

    # The user should not be logged in.
    r = await client.get("/auth", params={"scope": "user:token"})
    assert r.status_code == 401

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_unicode_name(
    client: AsyncClient, respx_mock: respx.Router
) -> None:
    user_info = GitHubUserInfo(
        name="名字",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="org")],
    )

    r = await simulate_github_login(client, respx_mock, user_info)
    assert r.status_code == 307

    # Check that the name as returned from the user-info API is correct.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "githubuser",
        "name": "名字",
        "email": "githubuser@example.com",
        "uid": 123456,
        "gid": 123456,
        "groups": [
            {"name": "githubuser", "id": 123456},
            {"name": "org-a-team", "id": 1000},
        ],
    }
