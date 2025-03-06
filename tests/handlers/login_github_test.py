"""Tests for the ``/login`` route with GitHub."""

from __future__ import annotations

import base64
import os
from collections.abc import AsyncIterator
from unittest.mock import ANY
from urllib.parse import parse_qs, urlparse

import pytest
import pytest_asyncio
import respx
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient, Response
from safir.metrics import NOT_NONE, MockEventPublisher
from safir.testing.slack import MockSlackWebhook

from gafaelfawr.config import Config
from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.context import context_dependency
from gafaelfawr.factory import Factory
from gafaelfawr.main import create_app
from gafaelfawr.models.github import GitHubTeam, GitHubUserInfo
from gafaelfawr.models.state import State
from gafaelfawr.providers.github import GitHubProvider

from ..support.config import reconfigure
from ..support.constants import TEST_HOSTNAME
from ..support.github import mock_github
from ..support.logging import parse_log


async def simulate_github_login(
    client: AsyncClient,
    respx_mock: respx.Router,
    user_info: GitHubUserInfo,
    *,
    headers: dict[str, str] | None = None,
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
    client
        Client to use to make calls to the application.
    respx_mock
        Mock for httpx calls.
    user_info
        The user information that GitHub should return.
    headers
        Optional headers to send on the initial login request.
    return_url
        The return URL to pass to the login process.
    paginate_teams
        Whether to paginate the team list.  If this is set to true, there must
        be more then two teams.
    expect_revoke
        Whether to expect a call from Gafaelfawr to the token revocation URL
        immediately after retrieving user information.

    Returns
    -------
    httpx.Response
        The response from the return to the ``/login`` handler.
    """
    config = config_dependency.config()
    assert config.github
    if not headers:
        headers = {}
    mock_github(
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
    client: AsyncClient,
    respx_mock: respx.Router,
    caplog: pytest.LogCaptureFixture,
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

    # Ensure the resulting cookie has the proper metadata set.
    cookie = next(c for c in r.cookies.jar if c.name == "gafaelfawr")
    assert cookie.secure
    assert cookie.discard
    assert cookie.domain == TEST_HOSTNAME
    assert not cookie.domain_specified
    assert cookie.has_nonstandard_attr("HttpOnly")
    assert cookie.get_nonstandard_attr("SameSite") == "lax"

    # Check that the /auth route works and finds our token, and that the user
    # information is correct.
    r = await client.get("/ingress/auth", params={"scope": "read:all"})
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

    # Check that the correct metrics events were logged.
    events = context_dependency._events
    assert events
    assert isinstance(events.login_attempt, MockEventPublisher)
    events.login_attempt.published.assert_published_all([{}])
    assert isinstance(events.login_success, MockEventPublisher)
    events.login_success.published.assert_published_all(
        [{"username": "githubuser", "elapsed": NOT_NONE}]
    )
    assert isinstance(events.login_enrollment, MockEventPublisher)
    events.login_enrollment.published.assert_published_all([])
    assert isinstance(events.login_failure, MockEventPublisher)
    events.login_failure.published.assert_published_all([])


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
    mock_github(respx_mock, "some-code", user_info)

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
    client: AsyncClient, mock_slack: MockSlackWebhook
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
        "/ingress/auth",
        params={"scope": "read:all"},
        headers={"Authorization": "token some-jupyterhub-token"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "githubuser"


@pytest.mark.asyncio
async def test_bad_redirect(
    client: AsyncClient, respx_mock: respx.Router, mock_slack: MockSlackWebhook
) -> None:
    r = await client.get("/login", params={"rd": "https://foo.example.com/"})
    assert r.status_code == 422

    r = await client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": "https://foo.example.com/"},
    )
    assert r.status_code == 422

    # Even if we're deployed under foo.example.com as determined by the
    # X-Forwarded-Host header, this will not be allowed. Only the base URL is
    # checked.
    r = await client.get(
        "/login",
        params={"rd": "https://foo.example.com/"},
        headers={
            "X-Forwarded-For": "192.168.0.1",
            "X-Forwarded-Host": "foo.example.com",
        },
    )
    assert r.status_code == 422

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
    r = await client.get("/ingress/auth", params={"scope": "read:all"})
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
    r = await client.get("/ingress/auth", params={"scope": "admin:token"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_invalid_username(
    client: AsyncClient, respx_mock: respx.Router, mock_slack: MockSlackWebhook
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
    client: AsyncClient,
    config: Config,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
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
    assert r.headers["Cache-Control"] == "no-cache, no-store"
    assert r.headers["Content-Type"] == "text/html; charset=utf-8"
    assert "githubuser is not a member of any authorized groups" in r.text
    assert config.error_footer
    assert config.error_footer in r.text

    # The user should not be logged in.
    r = await client.get("/ingress/auth", params={"scope": "user:token"})
    assert r.status_code == 401

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []

    # Check that the correct metrics events were logged.
    events = context_dependency._events
    assert events
    assert isinstance(events.login_attempt, MockEventPublisher)
    events.login_attempt.published.assert_published_all([{}])
    assert isinstance(events.login_success, MockEventPublisher)
    events.login_success.published.assert_published_all([])
    assert isinstance(events.login_enrollment, MockEventPublisher)
    events.login_enrollment.published.assert_published_all([])
    assert isinstance(events.login_failure, MockEventPublisher)
    events.login_failure.published.assert_published_all([{}])


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


@pytest.mark.asyncio
async def test_invalid_state(
    client: AsyncClient, config: Config, respx_mock: respx.Router
) -> None:
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[],
    )
    return_url = "https://example.com/foo"

    mock_github(respx_mock, "some-code", user_info)
    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Change the state to something that won't match.
    state = await State.from_cookie(r.cookies[COOKIE_NAME])
    state.state = base64.urlsafe_b64encode(os.urandom(16)).decode()
    client.cookies.set(COOKIE_NAME, state.to_cookie(), domain=TEST_HOSTNAME)

    # We should now get an error from the login endpoint.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 403
    assert "Authentication state mismatch" in r.text

    # Change the state to None.
    state.state = None
    client.cookies.set(COOKIE_NAME, state.to_cookie(), domain=TEST_HOSTNAME)

    # Now we should get a simple redirect to the return URL even though the
    # authentication isn't complete, since the code should assume, given the
    # empty state, that the user may have logged in via another window.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url

    # Also drop the return URL, which is a more realistic case.
    state.return_url = None
    client.cookies.set(COOKIE_NAME, state.to_cookie(), domain=TEST_HOSTNAME)

    # Now we should get a redirect to the after logout URL.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 307
    assert r.headers["Location"] == str(config.after_logout_url)


@pytest_asyncio.fixture
async def subdomain_client(empty_database: None) -> AsyncIterator[AsyncClient]:
    """Create an application configured to support subdomains.

    Because middleware is configured when the application is created,
    testing a different cookie policy unfortunately requires ignoring the
    fixtures and making our own application.
    """
    await reconfigure("github-subdomain")
    app = create_app(validate_schema=False)
    async with LifespanManager(app):
        async with AsyncClient(
            base_url=f"https://{TEST_HOSTNAME}",
            headers={"X-Original-URL": "https://foo.example.com/bar"},
            transport=ASGITransport(app=app),
        ) as client:
            yield client


@pytest.mark.asyncio
async def test_subdomain(
    subdomain_client: AsyncClient, respx_mock: respx.Router
) -> None:
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="org")],
    )

    # Check both a subdomain and the parent domain, which was mishandled in
    # the original implementation of this feature.
    for return_url in (
        f"https://foo.{TEST_HOSTNAME}:4444/foo?a=bar&b=baz",
        f"https://{TEST_HOSTNAME}:4444/foo?a=bar&b=baz",
    ):
        r = await simulate_github_login(
            subdomain_client, respx_mock, user_info, return_url=return_url
        )
        assert r.status_code == 307

        # Check the cookie parameters.
        cookie = next(c for c in r.cookies.jar if c.name == "gafaelfawr")
        assert cookie.secure
        assert cookie.discard
        assert cookie.domain == f".{TEST_HOSTNAME}"
        assert cookie.domain_specified
        assert cookie.has_nonstandard_attr("HttpOnly")
        assert cookie.get_nonstandard_attr("SameSite") == "lax"
