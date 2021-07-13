"""Tests for the ``/login`` route with GitHub."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urlparse

import pytest

from gafaelfawr.providers.github import (
    GitHubProvider,
    GitHubTeam,
    GitHubUserInfo,
)
from tests.support.headers import query_from_url
from tests.support.logging import parse_log

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture

    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_login(setup: SetupTest, caplog: LogCaptureFixture) -> None:
    assert setup.config.github
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

    # Simulate the initial authentication request.
    setup.set_github_token_response("some-code", "some-github-token")
    caplog.clear()
    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    assert url.scheme == "https"
    assert "github.com" in url.netloc
    assert url.query
    query = parse_qs(url.query)
    assert query == {
        "client_id": [setup.config.github.client_id],
        "scope": [" ".join(GitHubProvider._SCOPES)],
        "state": [ANY],
    }
    assert parse_log(caplog) == [
        {
            "event": "Redirecting user to GitHub for authentication",
            "level": "info",
            "method": "GET",
            "path": "/login",
            "return_url": return_url,
            "remote": "127.0.0.1",
        }
    ]

    # Simulate the return from GitHub.
    setup.set_github_userinfo_response("some-github-token", user_info)
    caplog.clear()
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url
    assert parse_log(caplog) == [
        {
            "event": "Successfully authenticated user githubuser (123456)",
            "level": "info",
            "method": "GET",
            "path": "/login",
            "return_url": return_url,
            "remote": "127.0.0.1",
            "scope": "read:all user:token",
            "token": ANY,
            "user": "githubuser",
        },
    ]

    # Examine the resulting cookie and ensure that it has the proper metadata
    # set.
    cookie = next((c for c in r.cookies.jar if c.name == "gafaelfawr"))
    assert cookie.secure
    assert cookie.discard
    assert cookie.has_nonstandard_attr("HttpOnly")
    assert cookie.get_nonstandard_attr("SameSite") == "lax"

    # Check that the /auth route works and finds our token.
    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == "read:all user:token"
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == "read:all"
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-User"] == "githubuser"
    assert r.headers["X-Auth-Request-Name"] == "GitHub User"
    assert r.headers["X-Auth-Request-Email"] == "githubuser@example.com"
    assert r.headers["X-Auth-Request-Uid"] == "123456"
    expected = "org-a-team,org-other-team,other-org-team-with-very--F279yg"
    assert r.headers["X-Auth-Request-Groups"] == expected


@pytest.mark.asyncio
async def test_login_redirect_header(setup: SetupTest) -> None:
    """Test receiving the redirect header via X-Auth-Request-Redirect."""
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="ORG")],
    )
    return_url = "https://example.com/foo?a=bar&b=baz"

    # Simulate the initial authentication request.
    setup.set_github_token_response("some-code", "some-github-token")
    r = await setup.client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": return_url},
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    setup.set_github_userinfo_response("some-github-token", user_info)
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url


@pytest.mark.asyncio
async def test_login_no_destination(setup: SetupTest) -> None:
    r = await setup.client.get("/login", allow_redirects=False)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_cookie_auth_with_token(setup: SetupTest) -> None:
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

    setup.set_github_token_response("some-code", "some-github-token")
    r = await setup.client.get(
        "/login",
        params={"rd": "https://example.com/foo"},
        headers={"Authorization": "token some-jupyterhub-token"},
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    setup.set_github_userinfo_response("some-github-token", user_info)
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        headers={"Authorization": "token some-jupyterhub-token"},
        allow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["Location"] == "https://example.com/foo"

    # Now make a request to the /auth endpoint with a bogus token.
    r = await setup.client.get(
        "/auth",
        params={"scope": "read:all"},
        headers={"Authorization": "token some-jupyterhub-token"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "githubuser"


@pytest.mark.asyncio
async def test_claim_names(setup: SetupTest) -> None:
    """Uses an alternate settings environment with non-default claims."""
    setup.configure(username_claim="username", uid_claim="numeric-uid")
    assert setup.config.github
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="org")],
    )

    setup.set_github_token_response("some-code", "some-github-token")
    r = await setup.client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": "https://example.com"},
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    setup.set_github_userinfo_response("some-github-token", user_info)
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307

    # Check that the /auth route works and sets the headers correctly.
    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "githubuser"
    assert r.headers["X-Auth-Request-Uid"] == "123456"


@pytest.mark.asyncio
async def test_bad_redirect(setup: SetupTest) -> None:
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="ORG")],
    )

    setup.set_github_token_response("some-code", "some-github-token")
    r = await setup.client.get(
        "/login",
        params={"rd": "https://foo.example.com/"},
        allow_redirects=False,
    )
    assert r.status_code == 422

    r = await setup.client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": "https://foo.example.com/"},
        allow_redirects=False,
    )
    assert r.status_code == 422

    # But if we're deployed under foo.example.com as determined by the
    # X-Forwarded-Host header, this will be allowed.
    r = await setup.client.get(
        "/login",
        params={"rd": "https://foo.example.com/"},
        headers={
            "X-Forwarded-For": "192.168.0.1",
            "X-Forwarded-Host": "foo.example.com",
        },
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)
    setup.set_github_userinfo_response("some-github-token", user_info)
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["Location"] == "https://foo.example.com/"


@pytest.mark.asyncio
async def test_github_uppercase(setup: SetupTest) -> None:
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

    setup.set_github_token_response("some-code", "some-github-token")
    r = await setup.client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": "https://example.com"},
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    setup.set_github_userinfo_response("some-github-token", user_info)
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307

    # The user returned by the /auth route should be forced to lowercase.
    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "someuser"


@pytest.mark.asyncio
async def test_github_admin(setup: SetupTest) -> None:
    """Test that a token administrator gets the admin:token scope."""
    admin_service = setup.factory.create_admin_service()
    admin_service.add_admin("someuser", actor="admin", ip_address="127.0.0.1")
    user_info = GitHubUserInfo(
        name="A User",
        username="someuser",
        uid=1000,
        email="user@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="ORG")],
    )

    setup.set_github_token_response("some-code", "some-github-token")
    r = await setup.client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": "https://example.com"},
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    setup.set_github_userinfo_response("some-github-token", user_info)
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307

    # The user should have admin:token scope.
    r = await setup.client.get("/auth", params={"scope": "admin:token"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_invalid_username(setup: SetupTest) -> None:
    """Test that invalid usernames are rejected."""
    user_info = GitHubUserInfo(
        name="A User",
        username="invalid user",
        uid=1000,
        email="foo@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="ORG")],
    )

    setup.set_github_token_response("some-code", "some-github-token")
    r = await setup.client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": "https://example.com"},
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    setup.set_github_userinfo_response(
        "some-github-token", user_info, expect_revoke=True
    )
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 403
    assert "Invalid username: invalid user" in r.text


@pytest.mark.asyncio
async def test_invalid_groups(setup: SetupTest) -> None:
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

    setup.set_github_token_response("some-code", "some-github-token")
    r = await setup.client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": "https://example.com"},
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    setup.set_github_userinfo_response("some-github-token", user_info)
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307

    # The user returned by the /auth route should be forced to lowercase.
    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Groups"] == "org-a-team"


@pytest.mark.asyncio
async def test_paginated_teams(setup: SetupTest) -> None:
    assert setup.config.github
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

    setup.set_github_token_response("some-code", "some-github-token")
    r = await setup.client.get(
        "/login", params={"rd": "https://example.com"}, allow_redirects=False
    )
    assert r.status_code == 307
    query = query_from_url(r.headers["Location"])

    # Simulate the return from GitHub.
    setup.set_github_userinfo_response(
        "some-github-token", user_info, paginate_teams=True
    )
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307

    # Check the group list.
    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    expected = ",".join(
        [
            "org-a-team",
            "org-other-team",
            "foo-third-team",
            "other-org-team-with-very--F279yg",
        ]
    )
    assert r.headers["X-Auth-Request-Groups"] == expected


@pytest.mark.asyncio
async def test_no_valid_groups(setup: SetupTest) -> None:
    assert setup.config.github
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[],
    )

    setup.set_github_token_response("some-code", "some-github-token")
    r = await setup.client.get(
        "/login", params={"rd": "https://example.com"}, allow_redirects=False
    )
    assert r.status_code == 307
    query = query_from_url(r.headers["Location"])

    # Simulate the return from GitHub.
    setup.set_github_userinfo_response(
        "some-github-token", user_info, expect_revoke=True
    )
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    assert "githubuser is not a member of any authorized groups" in r.text
    assert "Some <bold>error instructions</bold> with HTML." in r.text

    # The user should not be logged in.
    r = await setup.client.get("/auth", params={"scope": "user:token"})
    assert r.status_code == 401
